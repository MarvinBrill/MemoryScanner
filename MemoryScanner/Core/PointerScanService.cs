using MemoryScanner.Models;
using System.Collections.Concurrent;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace MemoryScanner.Core;

public sealed class PointerScanService
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

    private static void ReportMergeMapProgress(MergeShard[] mergeShards, Action<long, long>? mergeProgress)
    {
        if (mergeProgress is null)
        {
            return;
        }

        long totalMergeTargets = 0;
        foreach (var shard in mergeShards)
        {
            totalMergeTargets += shard.ParentsByTarget.Count;
        }

        if (totalMergeTargets <= 0)
        {
            mergeProgress(1, 1);
            return;
        }

        long mergedTargetCount = 0;
        foreach (var shard in mergeShards)
        {
            mergedTargetCount += shard.ParentsByTarget.Count;
            mergeProgress(mergedTargetCount, totalMergeTargets);
        }

        mergeProgress(totalMergeTargets, totalMergeTargets);
    }

    private static MergeShard[] CreateMergeShards()
    {
        var shards = new MergeShard[MergeShardCount];
        for (var i = 0; i < shards.Length; i++)
        {
            shards[i] = new MergeShard();
        }

        return shards;
    }

    private static int GetMergeShardIndex(ulong targetAddress)
    {
        return (int)(targetAddress & (MergeShardCount - 1));
    }

    private static void ClearParentShards(MergeShard[] mergeShards)
    {
        foreach (var shard in mergeShards)
        {
            shard.ParentsByTarget.Clear();
        }
    }

    private static void TryDeleteFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        for (var attempt = 0; attempt < 6; attempt++)
        {
            try
            {
                if (!File.Exists(path))
                {
                    return;
                }

                File.Delete(path);
                return;
            }
            catch
            {
                if (attempt == 5)
                {
                    return;
                }

                Thread.Sleep(40 * (attempt + 1));
            }
        }
    }

    private static bool IsOnlyCancellation(AggregateException ex)
    {
        return ex.Flatten().InnerExceptions.All(inner => inner is OperationCanceledException);
    }

    private static void CleanupStaleTempParentFiles()
    {
        try
        {
            var tempDir = Path.GetTempPath();
            var cutoff = DateTime.UtcNow.AddHours(-4);
            foreach (var path in Directory.EnumerateFiles(tempDir, TempParentFilePattern))
            {
                try
                {
                    var lastWrite = File.GetLastWriteTimeUtc(path);
                    if (lastWrite <= cutoff)
                    {
                        TryDeleteFile(path);
                    }
                }
                catch
                {
                    // Best effort cleanup only.
                }
            }
        }
        catch
        {
            // Best effort cleanup only.
        }
    }

    private static void AddMatchesForPointerValue(
        ulong[] sortedTargetAddresses,
        ulong pointerValue,
        ulong parentAddress,
        int maxOffset,
        bool allowNegativeOffsets,
        LocalParentCollector local)
    {
        if (sortedTargetAddresses.Length == 0)
        {
            return;
        }

        ulong maxDelta = (ulong)Math.Max(0, maxOffset);
        ulong minTarget = sortedTargetAddresses[0];
        ulong maxTarget = sortedTargetAddresses[^1];

        if (!allowNegativeOffsets)
        {
            if (pointerValue > maxTarget)
            {
                return;
            }

            ulong maxReach = pointerValue > ulong.MaxValue - maxDelta ? ulong.MaxValue : pointerValue + maxDelta;
            if (maxReach < minTarget)
            {
                return;
            }

            int startIndex = LowerBound(sortedTargetAddresses, pointerValue);
            for (int i = startIndex; i < sortedTargetAddresses.Length; i++)
            {
                ulong childAddress = sortedTargetAddresses[i];
                ulong delta = childAddress - pointerValue;
                if (delta > maxDelta)
                {
                    break;
                }

                local.AddCandidate(childAddress, parentAddress, (int)delta);
            }

            return;
        }

        ulong pointerMinRelevant = minTarget > maxDelta ? minTarget - maxDelta : 0;
        ulong pointerMaxRelevant = maxTarget > ulong.MaxValue - maxDelta ? ulong.MaxValue : maxTarget + maxDelta;
        if (pointerValue < pointerMinRelevant || pointerValue > pointerMaxRelevant)
        {
            return;
        }

        ulong minSearchTarget = pointerValue > maxDelta ? pointerValue - maxDelta : 0;
        ulong maxSearchTarget = pointerValue > ulong.MaxValue - maxDelta ? ulong.MaxValue : pointerValue + maxDelta;

        int rangeStart = LowerBound(sortedTargetAddresses, minSearchTarget);
        int rangeEnd = UpperBound(sortedTargetAddresses, maxSearchTarget);

        for (int i = rangeStart; i < rangeEnd; i++)
        {
            ulong childAddress = sortedTargetAddresses[i];
            long signedDelta = childAddress >= pointerValue
                ? (long)(childAddress - pointerValue)
                : -(long)(pointerValue - childAddress);

            if (signedDelta < int.MinValue || signedDelta > int.MaxValue)
            {
                continue;
            }

            local.AddCandidate(childAddress, parentAddress, (int)signedDelta);
        }
    }

    private static int LowerBound(ulong[] sortedValues, ulong value)
    {
        int left = 0;
        int right = sortedValues.Length;

        while (left < right)
        {
            int middle = left + ((right - left) >> 1);
            if (sortedValues[middle] < value)
            {
                left = middle + 1;
            }
            else
            {
                right = middle;
            }
        }

        return left;
    }

    private static int UpperBound(ulong[] sortedValues, ulong value)
    {
        int left = 0;
        int right = sortedValues.Length;

        while (left < right)
        {
            int middle = left + ((right - left) >> 1);
            if (sortedValues[middle] <= value)
            {
                left = middle + 1;
            }
            else
            {
                right = middle;
            }
        }

        return left;
    }

    private static long SaturatingMultiply(long left, int right)
    {
        if (left <= 0 || right <= 0)
        {
            return 0;
        }

        if (left > long.MaxValue / right)
        {
            return long.MaxValue;
        }

        return left * right;
    }

    private static Dictionary<ulong, List<PointerChainNode>> GroupFrontierByAddress(IReadOnlyList<PointerChainNode> frontier)
    {
        var grouped = new Dictionary<ulong, List<PointerChainNode>>(Math.Max(16, frontier.Count));
        for (var i = 0; i < frontier.Count; i++)
        {
            var node = frontier[i];
            if (!grouped.TryGetValue(node.CurrentAddress, out var nodes))
            {
                nodes = new List<PointerChainNode>(1);
                grouped[node.CurrentAddress] = nodes;
            }

            nodes.Add(node);
        }

        return grouped;
    }

    private static long CalculateMergeExpansionWork(
        IReadOnlyList<ulong> sortedTargets,
        IReadOnlyDictionary<ulong, List<PointerChainNode>> groupedFrontier,
        IParentLookup parentLookup)
    {
        long total = 0;
        var parents = new List<PointerParentCandidate>(64);

        foreach (var target in sortedTargets)
        {
            parents.Clear();
            if (!parentLookup.TryGetParents(target, parents) || parents.Count == 0)
            {
                continue;
            }

            if (!groupedFrontier.TryGetValue(target, out var nodes) || nodes.Count == 0)
            {
                continue;
            }

            long work = (long)parents.Count * nodes.Count;
            if (work <= 0)
            {
                continue;
            }

            if (long.MaxValue - total < work)
            {
                return long.MaxValue;
            }

            total += work;
        }

        return Math.Max(1, total);
    }

    private static void TryReportProgressThrottled(
        IProgress<ScanProgressInfo>? progress,
        object gate,
        ref long lastReportTicks,
        long processed,
        long total,
        string status,
        ScanProgressPhase phase = ScanProgressPhase.Scanning,
        long phaseProcessed = 0,
        long phaseTotal = 0)
    {
        long now = Stopwatch.GetTimestamp();
        long minDelta = Stopwatch.Frequency / 20;

        lock (gate)
        {
            if (lastReportTicks != 0 && now - lastReportTicks < minDelta)
            {
                return;
            }

            lastReportTicks = now;
        }

        ReportProgress(progress, processed, total, status, phase, phaseProcessed, phaseTotal);
    }

    private static bool RouteContainsAddress(PointerChainNode? node, ulong address)
    {
        var current = node;
        while (current is not null)
        {
            if (current.CurrentAddress == address)
            {
                return true;
            }

            current = current.ChildNode;
        }

        return false;
    }

    private static string FormatOffset(int offset)
    {
        return offset < 0 ? "-0x" + Math.Abs(offset).ToString("X") : "0x" + offset.ToString("X");
    }

    private bool TryMakeResult(
        PointerChainNode chainNode,
        ulong targetAddress,
        bool requireStaticRoot,
        int pointerSizeBytes,
        bool hasAddressRange,
        bool requireRootInAddressRange,
        ulong rangeMin,
        ulong rangeMax,
        ModuleLookup moduleLookup,
        out PointerPath path)
    {
        path = new PointerPath();

        if (hasAddressRange && requireRootInAddressRange && !IsAddressInRange(chainNode.CurrentAddress, rangeMin, rangeMax))
        {
            return false;
        }

        var hasModule = moduleLookup.TryFind(chainNode.CurrentAddress, out var module);
        var isStaticRoot = hasModule;
        if (requireStaticRoot && !isStaticRoot)
        {
            return false;
        }

        string baseExpression;
        string moduleName = string.Empty;
        ulong moduleOffset = 0;

        if (hasModule && module is not null)
        {
            moduleName = module.Name;
            moduleOffset = chainNode.CurrentAddress - module.Base;
            baseExpression = $"{_memory.Process.ProcessName}+0x{moduleOffset:X}";
        }
        else
        {
            baseExpression = $"0x{chainNode.CurrentAddress:X}";
        }

        var offsets = MaterializeOffsets(chainNode);
        var offsetText = string.Join(", ", offsets.Select(FormatOffset));
        path = new PointerPath
        {
            BaseAddress = chainNode.CurrentAddress,
            PointerSizeBytes = pointerSizeBytes,
            BaseModuleName = moduleName,
            BaseModuleOffset = moduleOffset,
            Offsets = offsets,
            FinalAddressPreview = targetAddress,
            DisplayExpression = $"{baseExpression} -> [{offsetText}]"
        };
        return true;
    }

    private static List<int> MaterializeOffsets(PointerChainNode rootNode)
    {
        var offsets = new List<int>(Math.Max(1, rootNode.Depth));
        var current = rootNode;
        while (current.ChildNode is not null)
        {
            offsets.Add(current.OffsetToChild);
            current = current.ChildNode;
        }

        return offsets;
    }

    private static IReadOnlyList<ScanSlice> FilterSlicesByRange(IReadOnlyList<ScanSlice> slices, ulong rangeMin, ulong rangeMax)
    {
        var filtered = new List<ScanSlice>(slices.Count);
        foreach (var slice in slices)
        {
            var start = slice.Start < rangeMin ? rangeMin : slice.Start;

            ulong rangeEndExclusive = rangeMax == ulong.MaxValue ? ulong.MaxValue : rangeMax + 1;
            var end = slice.End > rangeEndExclusive ? rangeEndExclusive : slice.End;

            if (end <= start)
            {
                continue;
            }

            filtered.Add(new ScanSlice(start, end, slice.IsWritable));
        }

        return filtered;
    }

    private static bool IsAddressInRange(ulong address, ulong rangeMin, ulong rangeMax)
    {
        return address >= rangeMin && address <= rangeMax;
    }
    private static IReadOnlyList<ScanSlice> SliceRegions(IReadOnlyList<MemoryRegion> regions, ulong sliceSize)
    {
        var slices = new List<ScanSlice>(regions.Count);
        foreach (var region in regions)
        {
            ulong start = region.BaseAddress;
            ulong end = region.BaseAddress + region.RegionSize;
            if (end <= start)
            {
                continue;
            }

            if (region.RegionSize <= sliceSize)
            {
                slices.Add(new ScanSlice(start, end, region.IsWritable));
                continue;
            }

            for (ulong cursor = start; cursor < end;)
            {
                ulong next = Math.Min(end, cursor + sliceSize);
                slices.Add(new ScanSlice(cursor, next, region.IsWritable));
                cursor = next;
            }
        }

        return slices;
    }

    private static long CalculateRegionSteps(IReadOnlyList<ScanSlice> slices, int alignment, int pointerSizeBytes)
    {
        long total = 0;
        foreach (var slice in slices)
        {
            var size = (long)(slice.End - slice.Start);
            var span = size - pointerSizeBytes + 1;
            if (span <= 0)
            {
                continue;
            }

            total += Math.Max(1, span / Math.Max(1, alignment));
        }

        return Math.Max(1, total);
    }

    private static void ReportProgress(
        IProgress<ScanProgressInfo>? progress,
        long processed,
        long total,
        string status,
        ScanProgressPhase phase = ScanProgressPhase.Scanning,
        long phaseProcessed = 0,
        long phaseTotal = 0)
    {
        progress?.Report(new ScanProgressInfo
        {
            Processed = processed,
            Total = total,
            StatusText = status,
            Phase = phase,
            PhaseProcessed = phaseProcessed,
            PhaseTotal = phaseTotal
        });
    }

    private int ResolvePointerSizeBytes(PointerScanOptions options)
    {
        return options.PointerWidthMode switch
        {
            PointerValueWidthMode.Force32Bit => 4,
            PointerValueWidthMode.Force64Bit => 8,
            _ => IsWow64Process(_memory.Process.Handle, out var wow64) && wow64 ? 4 : 8
        };
    }

    private interface IParentLookup : IDisposable
    {
        bool TryGetParents(ulong targetAddress, List<PointerParentCandidate> buffer);
    }

    private sealed class MemoryParentLookup : IParentLookup
    {
        private readonly MergeShard[] _mergeShards;
        private bool _disposed;

        public MemoryParentLookup(MergeShard[] mergeShards)
        {
            _mergeShards = mergeShards;
        }

        public bool TryGetParents(ulong targetAddress, List<PointerParentCandidate> buffer)
        {
            buffer.Clear();
            if (_disposed)
            {
                return false;
            }

            var shard = _mergeShards[GetMergeShardIndex(targetAddress)];
            if (!shard.ParentsByTarget.TryGetValue(targetAddress, out var parents) || parents.Count == 0)
            {
                return false;
            }

            buffer.AddRange(parents);
            return true;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            ClearParentShards(_mergeShards);
        }
    }

    private sealed class DiskParentLookup : IParentLookup
    {
        private readonly string _path;
        private readonly Dictionary<ulong, long> _indexByTarget;
        private readonly SafeFileHandle _handle;
        private readonly TempStorageGuard _tempStorageGuard;
        private readonly long _reservedBytes;
        private bool _disposed;

        public DiskParentLookup(string path, Dictionary<ulong, long> indexByTarget, long reservedBytes, TempStorageGuard tempStorageGuard)
        {
            _path = path;
            _indexByTarget = indexByTarget;
            _reservedBytes = Math.Max(0, reservedBytes);
            _tempStorageGuard = tempStorageGuard;
            _handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        }

        public bool TryGetParents(ulong targetAddress, List<PointerParentCandidate> buffer)
        {
            buffer.Clear();
            if (_disposed)
            {
                return false;
            }

            if (!_indexByTarget.TryGetValue(targetAddress, out var blockOffset))
            {
                return false;
            }

            Span<byte> header = stackalloc byte[sizeof(ulong) + sizeof(int)];
            ReadExact(_handle, header, blockOffset);
            var storedTarget = BinaryPrimitives.ReadUInt64LittleEndian(header[..sizeof(ulong)]);
            var count = BinaryPrimitives.ReadInt32LittleEndian(header.Slice(sizeof(ulong), sizeof(int)));
            if (storedTarget != targetAddress || count <= 0)
            {
                return false;
            }

            var payloadSize = checked(count * (sizeof(ulong) + sizeof(int)));
            var payload = payloadSize <= 0 ? Array.Empty<byte>() : new byte[payloadSize];
            if (payloadSize > 0)
            {
                ReadExact(_handle, payload, blockOffset + header.Length);
            }

            for (var i = 0; i < count; i++)
            {
                var baseOffset = i * (sizeof(ulong) + sizeof(int));
                var parentAddress = BinaryPrimitives.ReadUInt64LittleEndian(payload.AsSpan(baseOffset, sizeof(ulong)));
                var offset = BinaryPrimitives.ReadInt32LittleEndian(payload.AsSpan(baseOffset + sizeof(ulong), sizeof(int)));
                buffer.Add(new PointerParentCandidate(parentAddress, offset));
            }

            return buffer.Count > 0;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _indexByTarget.Clear();
            _handle.Dispose();
            _tempStorageGuard.Release(_reservedBytes);
            TryDeleteFile(_path);
        }

        private static void ReadExact(SafeFileHandle handle, Span<byte> buffer, long fileOffset)
        {
            var totalRead = 0;
            while (totalRead < buffer.Length)
            {
                var read = RandomAccess.Read(handle, buffer[totalRead..], fileOffset + totalRead);
                if (read <= 0)
                {
                    throw new EndOfStreamException("Unexpected end of temp parent lookup file.");
                }

                totalRead += read;
            }
        }
    }

    private sealed class TempStorageGuard
    {
        private const long OneGbBytes = 1024L * 1024L * 1024L;
        private const long FreeSpaceSafetyMarginBytes = 256L * 1024L * 1024L;

        private readonly bool _enabled;
        private readonly long _maxBytes;
        private long _reservedBytes;

        public TempStorageGuard(PointerScanOptions options)
        {
            _enabled = options.EnableDiskSpillToTemp;
            _maxBytes = Math.Max(1, options.MaxTempStorageGigabytes) * OneGbBytes;
        }

        public void Reserve(string tempPath, long bytes)
        {
            if (!_enabled || bytes <= 0)
            {
                return;
            }

            if (_reservedBytes > _maxBytes - bytes)
            {
                throw new TempStorageLimitExceededException($"temp storage limit ({FormatBytes(_maxBytes)}) reached");
            }

            var root = Path.GetPathRoot(tempPath);
            if (!string.IsNullOrWhiteSpace(root))
            {
                var driveInfo = new DriveInfo(root);
                var required = bytes + FreeSpaceSafetyMarginBytes;
                if (driveInfo.AvailableFreeSpace < required)
                {
                    throw new TempStorageLimitExceededException($"insufficient free temp disk space on {driveInfo.Name.TrimEnd('\\')} (need at least {FormatBytes(required)})");
                }
            }

            _reservedBytes += bytes;
        }

        public void Release(long bytes)
        {
            if (!_enabled || bytes <= 0)
            {
                return;
            }

            _reservedBytes -= bytes;
            if (_reservedBytes < 0)
            {
                _reservedBytes = 0;
            }
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes >= OneGbBytes)
            {
                return $"{bytes / (double)OneGbBytes:0.##} GB";
            }

            const long oneMbBytes = 1024L * 1024L;
            return $"{bytes / (double)oneMbBytes:0.##} MB";
        }
    }

    private sealed class TempStorageLimitExceededException : Exception
    {
        public TempStorageLimitExceededException(string message)
            : base(message)
        {
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr processHandle, out bool wow64Process);

    private sealed class ModuleLookup
    {
        private readonly ModuleRange[] _modulesByBase;
        private readonly ulong[] _bases;

        private ModuleLookup(ModuleRange[] modulesByBase)
        {
            _modulesByBase = modulesByBase;
            _bases = modulesByBase.Select(m => m.Base).ToArray();
        }

        public static ModuleLookup Create(IReadOnlyList<ModuleRange> modules)
        {
            if (modules.Count == 0)
            {
                return new ModuleLookup(Array.Empty<ModuleRange>());
            }

            var ordered = modules
                .OrderBy(m => m.Base)
                .ToArray();

            return new ModuleLookup(ordered);
        }

        public bool Contains(ulong address)
        {
            return TryFind(address, out _);
        }

        public bool TryFind(ulong address, out ModuleRange? module)
        {
            module = null;
            if (_modulesByBase.Length == 0)
            {
                return false;
            }

            var index = Array.BinarySearch(_bases, address);
            if (index >= 0)
            {
                var exact = _modulesByBase[index];
                if (exact.Contains(address))
                {
                    module = exact;
                    return true;
                }
            }

            var probe = index >= 0 ? index : (~index) - 1;
            if (probe < 0 || probe >= _modulesByBase.Length)
            {
                return false;
            }

            var candidate = _modulesByBase[probe];
            if (!candidate.Contains(address))
            {
                return false;
            }

            module = candidate;
            return true;
        }
    }

    private readonly struct PointerParentCandidate
    {
        public PointerParentCandidate(ulong parentAddress, int offset)
        {
            ParentAddress = parentAddress;
            Offset = offset;
        }

        public ulong ParentAddress { get; }
        public int Offset { get; }
    }

    private sealed class PointerChainNode
    {
        public ulong CurrentAddress { get; set; }
        public PointerChainNode? ChildNode { get; set; }
        public int OffsetToChild { get; set; }
        public int Depth { get; set; }
    }


    private sealed class LocalExpansionCollector
    {
        public List<PointerChainNode> NextFrontier { get; } = new(1024);
        public List<PointerPath> Results { get; } = new(128);
        public List<PointerParentCandidate> ParentsBuffer { get; } = new(128);
        public long PendingProgress { get; set; }
    }
    private sealed class LocalParentCollector
    {
        private byte[] _readBuffer;

        public LocalParentCollector(int initialBufferSize)
        {
            _readBuffer = new byte[Math.Max(1024, initialBufferSize)];
        }

        public Dictionary<ulong, List<PointerParentCandidate>> ParentsByTarget { get; } = new();
        public long PendingProgress { get; set; }
        public int CandidateCount { get; private set; }

        public byte[] GetReadBuffer(int requiredSize)
        {
            if (_readBuffer.Length < requiredSize)
            {
                _readBuffer = new byte[requiredSize];
            }

            return _readBuffer;
        }

        public void AddCandidate(ulong childAddress, ulong parentAddress, int offset)
        {
            ref var listRef = ref CollectionsMarshal.GetValueRefOrAddDefault(ParentsByTarget, childAddress, out var exists);
            if (!exists || listRef is null)
            {
                listRef = new List<PointerParentCandidate>(8);
            }

            listRef.Add(new PointerParentCandidate(parentAddress, offset));
            CandidateCount++;
        }

        public void ClearCandidates()
        {
            ParentsByTarget.Clear();
            CandidateCount = 0;
        }
    }


    private sealed class MergeShard
    {
        public object SyncRoot { get; } = new();
        public Dictionary<ulong, List<PointerParentCandidate>> ParentsByTarget { get; } = new();
    }
    private readonly record struct ScanSlice(ulong Start, ulong End, bool IsWritable);
}






























































