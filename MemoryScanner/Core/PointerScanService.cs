using MemoryScanner.Models;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Threading.Tasks;

namespace MemoryScanner.Core;

public sealed class PointerScanService
{
    private const int InitialReadChunkSize = 256 * 1024;
    private const int MinReadChunkSize = 16 * 1024;
    private const int MaxReadChunkSize = 1024 * 1024;
    private const ulong RegionSliceSize = 8UL * 1024 * 1024;

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
        var results = new List<PointerPath>();
        if (!_memory.IsAttached) return results;

        var regions = _regionEnumerator.Enumerate(_memory.Process, options.IncludePrivate, options.IncludeModuleImage, options.IncludeMapped);
        var slices = SliceRegions(regions, RegionSliceSize);
        var frontier = new List<PointerChainNode>
        {
            new() { CurrentAddress = targetAddress, Offsets = new List<int>() }
        };

        var visited = new HashSet<(ulong, int)>();
        int limitReached = 0;

        long regionSteps = CalculateRegionSteps(slices, options.Alignment);
        long processedWork = 0;
        long totalWorkEstimate = Math.Max(1, regionSteps);

        var progressGate = new object();
        long lastReportTicks = 0;

        ReportProgress(progress, 0, totalWorkEstimate, "Pointer scan");

        for (int depth = 0; depth < options.MaxDepth; depth++)
        {
            if (cancellationToken.IsCancellationRequested || Volatile.Read(ref limitReached) == 1)
            {
                break;
            }

            var nextFrontier = new List<PointerChainNode>(Math.Max(128, frontier.Count * 2));
            int frontierCount = Math.Max(1, frontier.Count);
            var status = $"Pointer scan d{depth + 1}/{options.MaxDepth} frontier {frontier.Count}";

            for (int nodeIndex = 0; nodeIndex < frontier.Count; nodeIndex++)
            {
                if (cancellationToken.IsCancellationRequested || Volatile.Read(ref limitReached) == 1)
                {
                    break;
                }

                var node = frontier[nodeIndex];

                var parentResult = FindParents(
                    node.CurrentAddress,
                    options,
                    slices,
                    cancellationToken,
                    delta =>
                    {
                        var processedGlobal = Interlocked.Add(ref processedWork, delta);
                        var totalEstimate = Math.Max(processedGlobal + 1, Volatile.Read(ref totalWorkEstimate));

                        TryReportProgressThrottled(
                            progress,
                            progressGate,
                            ref lastReportTicks,
                            processedGlobal,
                            totalEstimate,
                            status);
                    });

                foreach (var parent in parentResult.Parents)
                {
                    if (cancellationToken.IsCancellationRequested || Volatile.Read(ref limitReached) == 1)
                    {
                        break;
                    }

                    var key = (parent.ParentAddress, depth);
                    if (!visited.Add(key))
                    {
                        continue;
                    }

                    var offsets = new List<int> { parent.Offset };
                    offsets.AddRange(node.Offsets);

                    var chainNode = new PointerChainNode
                    {
                        CurrentAddress = parent.ParentAddress,
                        Offsets = offsets
                    };

                    nextFrontier.Add(chainNode);

                    if (TryMakeResult(chainNode, targetAddress, options.RequireStaticRoot, out var path))
                    {
                        if (results.Count < options.MaxResults)
                        {
                            results.Add(path);
                        }

                        if (results.Count >= options.MaxResults)
                        {
                            Volatile.Write(ref limitReached, 1);
                        }
                    }
                }

                var remainingCurrentNodes = Math.Max(0, frontierCount - nodeIndex - 1);
                var knownPendingNodes = remainingCurrentNodes + Math.Max(0, nextFrontier.Count);
                var knownPendingWork = knownPendingNodes * regionSteps;
                long futureGuardWork = depth < options.MaxDepth - 1 ? regionSteps : 0;
                long processedSnapshot = Volatile.Read(ref processedWork);
                var estimateAfterNode = processedSnapshot + knownPendingWork + futureGuardWork;
                RaiseTotalEstimate(ref totalWorkEstimate, estimateAfterNode);
                ReportProgress(progress, processedSnapshot, Volatile.Read(ref totalWorkEstimate), status);
            }

            if (nextFrontier.Count > 0 && depth < options.MaxDepth - 1)
            {
                var nextDepthKnownWork = Math.Max(1, (long)nextFrontier.Count * regionSteps);
                var processedSnapshot = Volatile.Read(ref processedWork);
                RaiseTotalEstimate(ref totalWorkEstimate, processedSnapshot + nextDepthKnownWork);
            }

            ReportProgress(progress, Volatile.Read(ref processedWork), Volatile.Read(ref totalWorkEstimate), status);

            if (nextFrontier.Count == 0)
            {
                break;
            }

            frontier = nextFrontier;
        }

        var finalStatus = cancellationToken.IsCancellationRequested ? "Pointer scan canceled" : "Pointer scan finished";
        var finalProcessed = Volatile.Read(ref processedWork);
        ReportProgress(progress, finalProcessed, finalProcessed, finalStatus);
        return results;
    }

    private static void RaiseTotalEstimate(ref long totalEstimate, long candidate)
    {
        if (candidate <= 0)
        {
            return;
        }

        while (true)
        {
            var snapshot = Volatile.Read(ref totalEstimate);
            if (candidate <= snapshot)
            {
                return;
            }

            if (Interlocked.CompareExchange(ref totalEstimate, candidate, snapshot) == snapshot)
            {
                return;
            }
        }
    }

    private static void TryReportProgressThrottled(
        IProgress<ScanProgressInfo>? progress,
        object gate,
        ref long lastReportTicks,
        long processed,
        long total,
        string status)
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

        ReportProgress(progress, processed, total, status);
    }

    private bool TryMakeResult(PointerChainNode chainNode, ulong targetAddress, bool requireStaticRoot, out PointerPath path)
    {
        path = new PointerPath();

        var module = _memory.Modules.FirstOrDefault(m => m.Contains(chainNode.CurrentAddress));
        var isStaticRoot = module is not null;
        if (requireStaticRoot && !isStaticRoot)
        {
            return false;
        }

        string baseExpression;
        string moduleName = string.Empty;
        ulong moduleOffset = 0;

        if (module is not null)
        {
            moduleName = module.Name;
            moduleOffset = chainNode.CurrentAddress - module.Base;
            baseExpression = $"{_memory.Process.ProcessName}+0x{moduleOffset:X}";
        }
        else
        {
            baseExpression = $"0x{chainNode.CurrentAddress:X}";
        }

        var offsetText = string.Join(", ", chainNode.Offsets.Select(x => $"0x{x:X}"));
        path = new PointerPath
        {
            BaseAddress = chainNode.CurrentAddress,
            BaseModuleName = moduleName,
            BaseModuleOffset = moduleOffset,
            Offsets = chainNode.Offsets,
            FinalAddressPreview = targetAddress,
            DisplayExpression = $"{baseExpression} -> [{offsetText}]"
        };
        return true;
    }

    private PointerParentResult FindParents(
        ulong childAddress,
        PointerScanOptions options,
        IReadOnlyList<ScanSlice> slices,
        CancellationToken cancellationToken,
        Action<long>? progressDelta)
    {
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = options.NormalizedThreadCount()
        };

        var mergeLock = new object();
        var mergedParents = new List<PointerParentCandidate>(256);

        Parallel.ForEach(
            slices,
            parallelOptions,
            () => new LocalParentCollector(),
            (slice, _, local) =>
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    return local;
                }

                ulong cursor = slice.Start;
                int currentChunkSize = InitialReadChunkSize;
                while (cursor < slice.End)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }

                    ulong remaining = slice.End - cursor;
                    int primaryChunkSize = (int)Math.Min((ulong)currentChunkSize, remaining);
                    int readCount = primaryChunkSize + sizeof(long) - 1;
                    if ((ulong)readCount > remaining)
                    {
                        readCount = (int)remaining;
                    }

                    if (!_memory.TryReadBytes(cursor, readCount, out var block) || block.Length < sizeof(long))
                    {
                        currentChunkSize = Math.Max(MinReadChunkSize, currentChunkSize / 2);
                        cursor += (ulong)Math.Max(MinReadChunkSize, primaryChunkSize);
                        continue;
                    }

                    var span = block.AsSpan();
                    int primaryCount = Math.Min(primaryChunkSize, block.Length);
                    int maxPosExclusive = Math.Min(primaryCount, span.Length - sizeof(long) + 1);

                    for (int pos = 0; pos < maxPosExclusive; pos += options.Alignment)
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }

                        var pointerValue = BinaryPrimitives.ReadUInt64LittleEndian(span.Slice(pos, sizeof(long)));
                        if (childAddress >= pointerValue)
                        {
                            var delta = childAddress - pointerValue;
                            if (delta <= (ulong)options.MaxOffset)
                            {
                                local.Parents.Add(new PointerParentCandidate
                                {
                                    ParentAddress = cursor + (ulong)pos,
                                    Offset = (int)delta
                                });
                            }
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

                if (local.Parents.Count == 0)
                {
                    return;
                }

                lock (mergeLock)
                {
                    mergedParents.AddRange(local.Parents);
                }
            });

        return new PointerParentResult
        {
            Parents = mergedParents
        };
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
                slices.Add(new ScanSlice(start, end));
                continue;
            }

            for (ulong cursor = start; cursor < end;)
            {
                ulong next = Math.Min(end, cursor + sliceSize);
                slices.Add(new ScanSlice(cursor, next));
                cursor = next;
            }
        }

        return slices;
    }

    private static long CalculateRegionSteps(IReadOnlyList<ScanSlice> slices, int alignment)
    {
        long total = 0;
        foreach (var slice in slices)
        {
            var size = (long)(slice.End - slice.Start);
            var span = size - sizeof(long) + 1;
            if (span <= 0)
            {
                continue;
            }

            total += Math.Max(1, span / Math.Max(1, alignment));
        }

        return Math.Max(1, total);
    }

    private static void ReportProgress(IProgress<ScanProgressInfo>? progress, long processed, long total, string status)
    {
        progress?.Report(new ScanProgressInfo
        {
            Processed = processed,
            Total = total,
            StatusText = status
        });
    }

    private sealed class PointerParentCandidate
    {
        public ulong ParentAddress { get; set; }
        public int Offset { get; set; }
    }

    private sealed class PointerParentResult
    {
        public List<PointerParentCandidate> Parents { get; set; } = new();
    }

    private sealed class PointerChainNode
    {
        public ulong CurrentAddress { get; set; }
        public List<int> Offsets { get; set; } = new();
    }

    private sealed class LocalParentCollector
    {
        public List<PointerParentCandidate> Parents { get; } = new(128);
        public long PendingProgress { get; set; }
    }

    private readonly record struct ScanSlice(ulong Start, ulong End);
}
