using MemoryScanner.Models;
using System.Collections.Concurrent;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace MemoryScanner.Core;

public sealed partial class PointerScanService
{
    private const int InitialReadChunkSize = 64 * 1024;
    private const int MinReadChunkSize = 16 * 1024;
    private const int MaxReadChunkSize = 80 * 1024;
    private const ulong RegionSliceSize = 8UL * 1024 * 1024;
    private const int LocalParentFlushThreshold = 32768;
    private const int MergeShardCount = 64;
    private const int MergeProgressReportStep = 1024;
    private const string TempParentFilePattern = "MemoryScanner_ptrparents_*.bin";

    private readonly IMemoryAccessor _memory;
    private readonly MemoryRegionEnumerator _regionEnumerator;

    public PointerScanService(IMemoryAccessor memory, MemoryRegionEnumerator regionEnumerator)
    {
        _memory = memory;
        _regionEnumerator = regionEnumerator;
    }

    public IReadOnlyList<PointerPath> Scan(
        ulong targetAddress,
        PointerScanOptions options,
        IProgress<ScanProgressInfo>? progress,
        CancellationToken cancellationToken)
    {
        CleanupStaleTempParentFiles();
        var results = new List<PointerPath>();
        if (!_memory.IsAttached)
        {
            return results;
        }

        var regions = _regionEnumerator.Enumerate(_memory.Process, options.IncludePrivate, options.IncludeModuleImage, options.IncludeMapped);
        var slices = SliceRegions(regions, RegionSliceSize);
        var moduleLookup = ModuleLookup.Create(_memory.Modules);

        var hasAddressRange = options.TryGetNormalizedAddressRange(out var rangeMin, out var rangeMax);
        if (hasAddressRange)
        {
            if (options.RequireAllNodesInAddressRange && !IsAddressInRange(targetAddress, rangeMin, rangeMax))
            {
                ReportProgress(progress, 1, 1, "Pointer scan finished (target outside required range)");
                return results;
            }

            if (options.ClampSearchToAddressRange)
            {
                slices = FilterSlicesByRange(slices, rangeMin, rangeMax);
                if (slices.Count == 0)
                {
                    ReportProgress(progress, 1, 1, "Pointer scan finished (range has no readable regions)");
                    return results;
                }
            }
        }

        var frontier = new List<PointerChainNode>
        {
            new()
            {
                CurrentAddress = targetAddress,
                ChildNode = null,
                OffsetToChild = 0,
                Depth = 0
            }
        };

        var visited = options.AggressiveNodeDeduplication
            ? new ConcurrentDictionary<(ulong ParentAddress, int Depth), byte>()
            : null;
        int limitReached = 0;
        var resultLimit = options.UseResultLimit ? options.NormalizedResultLimit() : int.MaxValue;
        int pointerSizeBytes = ResolvePointerSizeBytes(options);

        long regionSteps = CalculateRegionSteps(slices, options.Alignment, pointerSizeBytes);
        long processedWork = 0;
        long totalWorkEstimate = Math.Max(1, SaturatingMultiply(regionSteps, Math.Max(1, options.MaxDepth)));

        var progressGate = new object();
        long lastReportTicks = 0;
        var tempStorageGuard = new TempStorageGuard(options);
        var stoppedByTempLimit = false;
        var tempStopReason = string.Empty;
        var canceledByException = false;

        ReportProgress(progress, 0, totalWorkEstimate, "Pointer scan");

        try
        {
            for (int depth = 0; depth < options.MaxDepth; depth++)
            {
                if (cancellationToken.IsCancellationRequested || Volatile.Read(ref limitReached) == 1)
                {
                    break;
                }

                if (frontier.Count == 0)
                {
                    break;
                }

                var groupedFrontier = GroupFrontierByAddress(frontier);
                var sortedTargets = groupedFrontier.Keys.ToArray();
                Array.Sort(sortedTargets);
                if (sortedTargets.Length == 0)
                {
                    break;
                }

                var scanStatus = $"Scanning d{depth + 1}/{options.MaxDepth} targets {sortedTargets.Length}";
                long mergeMapTotal = 1;
                var parentShards = FindParentsForTargets(
                    sortedTargets,
                    options,
                    slices,
                    pointerSizeBytes,
                    cancellationToken,
                    delta =>
                    {
                        var processedGlobal = Interlocked.Add(ref processedWork, delta);
                        TryReportProgressThrottled(
                            progress,
                            progressGate,
                            ref lastReportTicks,
                            processedGlobal,
                            totalWorkEstimate,
                            scanStatus,
                            ScanProgressPhase.Scanning);
                    },
                    (mergeProcessed, mergeTotal) =>
                    {
                        mergeTotal = Math.Max(1, mergeTotal);
                        mergeMapTotal = mergeTotal;

                        var processedGlobal = Volatile.Read(ref processedWork);
                        var mergeStatus = $"Merging map d{depth + 1}/{options.MaxDepth} {mergeProcessed}/{mergeTotal}";
                        var phaseTotal = mergeTotal + Math.Max(1, sortedTargets.Length);
                        var phaseProcessed = Math.Min(mergeProcessed, mergeTotal);

                        if (phaseProcessed >= mergeTotal)
                        {
                            phaseProcessed = Math.Max(0, mergeTotal - 1);
                        }

                        TryReportProgressThrottled(
                            progress,
                            progressGate,
                            ref lastReportTicks,
                            processedGlobal,
                            totalWorkEstimate,
                            mergeStatus,
                            ScanProgressPhase.Merging,
                            phaseProcessed,
                            phaseTotal);
                    });

                if (cancellationToken.IsCancellationRequested || Volatile.Read(ref limitReached) == 1)
                {
                    ClearParentShards(parentShards);
                    break;
                }

                using var parentLookup = BuildParentLookup(parentShards, options, tempStorageGuard, cancellationToken);

                var nextFrontier = new List<PointerChainNode>(Math.Max(128, frontier.Count * 2));
                var mergeExpansionWorkTotal = CalculateMergeExpansionWork(sortedTargets, groupedFrontier, parentLookup);
                var mergePhaseTotal = Math.Max(1, mergeMapTotal + mergeExpansionWorkTotal);
                long mergeExpansionWorkProcessed = 0;
                int resultSlots = results.Count;
                var nextFrontierMergeLock = new object();
                var resultMergeLock = new object();

                void ReportMergeExpansionProgress(long processedCount)
                {
                    processedCount = Math.Min(processedCount, mergeExpansionWorkTotal);
                    var processedGlobal = Volatile.Read(ref processedWork);
                    var mergePhaseProcessed = Math.Min(mergePhaseTotal, mergeMapTotal + processedCount);
                    var mergeStatus = $"Merging chains d{depth + 1}/{options.MaxDepth} {processedCount}/{mergeExpansionWorkTotal}";
                    TryReportProgressThrottled(
                        progress,
                        progressGate,
                        ref lastReportTicks,
                        processedGlobal,
                        totalWorkEstimate,
                        mergeStatus,
                        ScanProgressPhase.Merging,
                        mergePhaseProcessed,
                        mergePhaseTotal);
                }

                var expansionParallelOptions = new ParallelOptions
                {
                    MaxDegreeOfParallelism = options.NormalizedThreadCount()
                };

                Parallel.ForEach(
                    sortedTargets,
                    expansionParallelOptions,
                    () => new LocalExpansionCollector(),
                    (target, loopState, local) =>
                    {
                        if (cancellationToken.IsCancellationRequested || Volatile.Read(ref limitReached) == 1)
                        {
                            loopState.Stop();
                            return local;
                        }

                        local.ParentsBuffer.Clear();
                        if (!parentLookup.TryGetParents(target, local.ParentsBuffer) || local.ParentsBuffer.Count == 0)
                        {
                            return local;
                        }

                        if (!groupedFrontier.TryGetValue(target, out var nodesForTarget))
                        {
                            return local;
                        }

                        foreach (var node in nodesForTarget)
                        {
                            if (cancellationToken.IsCancellationRequested || Volatile.Read(ref limitReached) == 1)
                            {
                                loopState.Stop();
                                break;
                            }

                            foreach (var parent in local.ParentsBuffer)
                            {
                                if (cancellationToken.IsCancellationRequested || Volatile.Read(ref limitReached) == 1)
                                {
                                    loopState.Stop();
                                    break;
                                }

                                local.PendingProgress++;
                                if ((local.PendingProgress & 4095) == 0)
                                {
                                    var processed = Interlocked.Add(ref mergeExpansionWorkProcessed, local.PendingProgress);
                                    local.PendingProgress = 0;
                                    ReportMergeExpansionProgress(processed);
                                }

                                if (visited is not null)
                                {
                                    var key = (parent.ParentAddress, depth);
                                    if (!visited.TryAdd(key, 0))
                                    {
                                        continue;
                                    }
                                }

                                if (options.NoLoopingPointers && RouteContainsAddress(node, parent.ParentAddress))
                                {
                                    continue;
                                }

                                var chainNode = new PointerChainNode
                                {
                                    CurrentAddress = parent.ParentAddress,
                                    ChildNode = node,
                                    OffsetToChild = parent.Offset,
                                    Depth = node.Depth + 1
                                };

                                if (hasAddressRange && options.RequireAllNodesInAddressRange && !IsAddressInRange(chainNode.CurrentAddress, rangeMin, rangeMax))
                                {
                                    continue;
                                }

                                var hasStaticRoot = moduleLookup.Contains(chainNode.CurrentAddress);
                                if (!(options.StopTraversingAfterStaticRoot && hasStaticRoot))
                                {
                                    local.NextFrontier.Add(chainNode);
                                    if (local.NextFrontier.Count >= 4096)
                                    {
                                        lock (nextFrontierMergeLock)
                                        {
                                            nextFrontier.AddRange(local.NextFrontier);
                                        }

                                        local.NextFrontier.Clear();
                                    }
                                }

                                if (TryMakeResult(chainNode, targetAddress, options.RequireStaticRoot, pointerSizeBytes, hasAddressRange, options.RequireRootInAddressRange, rangeMin, rangeMax, moduleLookup, out var path))
                                {
                                    var slot = Interlocked.Increment(ref resultSlots);
                                    if (slot <= resultLimit)
                                    {
                                        local.Results.Add(path);
                                        if (local.Results.Count >= 512)
                                        {
                                            lock (resultMergeLock)
                                            {
                                                results.AddRange(local.Results);
                                            }

                                            local.Results.Clear();
                                        }
                                    }
                                    else
                                    {
                                        Volatile.Write(ref limitReached, 1);
                                        loopState.Stop();
                                        break;
                                    }
                                }
                            }
                        }

                        return local;
                    },
                    local =>
                    {
                        if (local.PendingProgress > 0)
                        {
                            var processed = Interlocked.Add(ref mergeExpansionWorkProcessed, local.PendingProgress);
                            ReportMergeExpansionProgress(processed);
                        }

                        if (local.NextFrontier.Count > 0)
                        {
                            lock (nextFrontierMergeLock)
                            {
                                nextFrontier.AddRange(local.NextFrontier);
                            }
                        }

                        if (local.Results.Count > 0)
                        {
                            lock (resultMergeLock)
                            {
                                results.AddRange(local.Results);
                            }
                        }
                    });

                {
                    var processedGlobal = Volatile.Read(ref processedWork);
                    var mergeStatus = $"Merging chains d{depth + 1}/{options.MaxDepth} {mergeExpansionWorkTotal}/{mergeExpansionWorkTotal}";
                    ReportProgress(
                        progress,
                        processedGlobal,
                        totalWorkEstimate,
                        mergeStatus,
                        ScanProgressPhase.Merging,
                        mergePhaseTotal,
                        mergePhaseTotal);
                }

                groupedFrontier.Clear();
                frontier = nextFrontier;
                ReportProgress(progress, Volatile.Read(ref processedWork), totalWorkEstimate, scanStatus, ScanProgressPhase.Scanning);
            }
        }
        catch (TempStorageLimitExceededException ex)
        {
            stoppedByTempLimit = true;
            tempStopReason = ex.Message;
        }
        catch (OperationCanceledException)
        {
            canceledByException = true;
        }
        catch (AggregateException ex) when (IsOnlyCancellation(ex))
        {
            canceledByException = true;
        }

        frontier.Clear();
        visited?.Clear();

        var finalStatus = stoppedByTempLimit
            ? $"Pointer scan stopped ({tempStopReason})"
            : (cancellationToken.IsCancellationRequested || canceledByException)
                ? "Pointer scan canceled"
                : Volatile.Read(ref limitReached) == 1
                    ? "Pointer scan result limit reached"
                    : "Pointer scan finished";

        var finalProcessed = Math.Max(1, Volatile.Read(ref processedWork));
        ReportProgress(progress, finalProcessed, finalProcessed, finalStatus);
        return results;
    }

    private MergeShard[] FindParentsForTargets(
        ulong[] sortedTargetAddresses,
        PointerScanOptions options,
        IReadOnlyList<ScanSlice> slices,
        int pointerSizeBytes,
        CancellationToken cancellationToken,
        Action<long>? progressDelta,
        Action<long, long>? mergeProgress)
    {
        var mergeShards = CreateMergeShards();
        if (sortedTargetAddresses.Length == 0 || slices.Count == 0)
        {
            mergeProgress?.Invoke(1, 1);
            return mergeShards;
        }

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = options.NormalizedThreadCount()
        };

        Parallel.ForEach(
            slices,
            parallelOptions,
            () => new LocalParentCollector(MaxReadChunkSize + pointerSizeBytes),
            (slice, loopState, local) =>
            {
                ulong cursor = slice.Start;
                int currentChunkSize = InitialReadChunkSize;
                int alignment = Math.Max(1, options.Alignment);

                if (options.ExcludeReadOnlyNodes && !slice.IsWritable)
                {
                    return local;
                }

                while (cursor < slice.End)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        loopState.Stop();
                        break;
                    }

                    ulong remaining = slice.End - cursor;
                    int primaryChunkSize = (int)Math.Min((ulong)currentChunkSize, remaining);
                    int readCount = primaryChunkSize + pointerSizeBytes - 1;
                    if ((ulong)readCount > remaining)
                    {
                        readCount = (int)remaining;
                    }

                    var readBuffer = local.GetReadBuffer(readCount);
                    if (!_memory.TryReadBytes(cursor, readBuffer, readCount, out var bytesRead) || bytesRead < pointerSizeBytes)
                    {
                        currentChunkSize = Math.Max(MinReadChunkSize, currentChunkSize / 2);
                        cursor += (ulong)Math.Max(MinReadChunkSize, primaryChunkSize);
                        continue;
                    }

                    var span = readBuffer.AsSpan(0, bytesRead);
                    int primaryCount = Math.Min(primaryChunkSize, bytesRead);
                    int maxPosExclusive = Math.Min(primaryCount, span.Length - pointerSizeBytes + 1);

                    for (int pos = 0; pos < maxPosExclusive; pos += alignment)
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            loopState.Stop();
                            break;
                        }

                        ulong pointerValue = pointerSizeBytes == 4
                            ? BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(pos, sizeof(uint)))
                            : BinaryPrimitives.ReadUInt64LittleEndian(span.Slice(pos, sizeof(ulong)));
                        var parentAddress = cursor + (ulong)pos;
                        AddMatchesForPointerValue(sortedTargetAddresses, pointerValue, parentAddress, options.MaxOffset, options.AllowNegativeOffsets, local);

                        if (local.CandidateCount >= LocalParentFlushThreshold)
                        {
                            FlushLocalParents(local, mergeShards);
                        }

                        local.PendingProgress++;
                        if ((local.PendingProgress & 4095) == 0)
                        {
                            progressDelta?.Invoke(4096);
                            local.PendingProgress -= 4096;
                        }
                    }

                    currentChunkSize = Math.Min(MaxReadChunkSize, currentChunkSize * 2);
                    cursor += (ulong)primaryCount;
                }

                return local;
            },
            local =>
            {
                if (local.PendingProgress > 0)
                {
                    progressDelta?.Invoke(local.PendingProgress);
                }

                FlushLocalParents(local, mergeShards);
            });

        ReportMergeMapProgress(mergeShards, mergeProgress);
        return mergeShards;
    }

    private IParentLookup BuildParentLookup(
        MergeShard[] parentShards,
        PointerScanOptions options,
        TempStorageGuard tempStorageGuard,
        CancellationToken cancellationToken)
    {
        if (!options.EnableDiskSpillToTemp)
        {
            return new MemoryParentLookup(parentShards);
        }

        var tempPath = Path.Combine(Path.GetTempPath(), $"MemoryScanner_ptrparents_{Guid.NewGuid():N}.bin");
        var targetCount = 0;
        foreach (var shard in parentShards)
        {
            targetCount += shard.ParentsByTarget.Count;
        }

        var index = new Dictionary<ulong, long>(Math.Max(16, targetCount));
        long reservedBytes = 0;

        try
        {
            using (var stream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.Read, 256 * 1024, FileOptions.SequentialScan))
            using (var writer = new BinaryWriter(stream))
            {
                foreach (var shard in parentShards)
                {
                    foreach (var entry in shard.ParentsByTarget)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        var candidates = entry.Value;
                        if (candidates.Count == 0)
                        {
                            continue;
                        }

                        var blockBytes = sizeof(ulong) + sizeof(int) + ((long)candidates.Count * (sizeof(ulong) + sizeof(int)));
                        tempStorageGuard.Reserve(tempPath, blockBytes);
                        reservedBytes += blockBytes;

                        var blockOffset = stream.Position;
                        writer.Write(entry.Key);
                        writer.Write(candidates.Count);
                        for (var i = 0; i < candidates.Count; i++)
                        {
                            writer.Write(candidates[i].ParentAddress);
                            writer.Write(candidates[i].Offset);
                        }

                        index[entry.Key] = blockOffset;
                        candidates.Clear();
                    }

                    shard.ParentsByTarget.Clear();
                }

                writer.Flush();
                stream.Flush(true);
            }

            return new DiskParentLookup(tempPath, index, reservedBytes, tempStorageGuard);
        }
        catch (IOException ioEx)
        {
            tempStorageGuard.Release(reservedBytes);
            TryDeleteFile(tempPath);
            throw new TempStorageLimitExceededException($"temp storage write failed: {ioEx.Message}");
        }
        catch
        {
            tempStorageGuard.Release(reservedBytes);
            TryDeleteFile(tempPath);
            throw;
        }
    }

    private static void FlushLocalParents(
        LocalParentCollector local,
        MergeShard[] mergeShards)
    {
        if (local.ParentsByTarget.Count == 0)
        {
            return;
        }

        foreach (var entry in local.ParentsByTarget)
        {
            var shard = mergeShards[GetMergeShardIndex(entry.Key)];
            lock (shard.SyncRoot)
            {
                ref var listRef = ref CollectionsMarshal.GetValueRefOrAddDefault(shard.ParentsByTarget, entry.Key, out var exists);
                if (!exists || listRef is null)
                {
                    listRef = new List<PointerParentCandidate>(entry.Value.Count);
                }

                listRef.AddRange(entry.Value);
            }
        }

        local.ClearCandidates();
    }

}
