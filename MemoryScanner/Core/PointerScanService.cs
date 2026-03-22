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
        if (!_memory.IsAttached)
        {
            return results;
        }

        var regions = _regionEnumerator.Enumerate(_memory.Process, options.IncludePrivate, options.IncludeModuleImage, options.IncludeMapped);
        var slices = SliceRegions(regions, RegionSliceSize);
        var frontier = new List<PointerChainNode>
        {
            new() { CurrentAddress = targetAddress, Offsets = new List<int>() }
        };

        var visited = new HashSet<(ulong ParentAddress, int Depth)>();
        int limitReached = 0;
        var resultLimit = options.UseResultLimit ? options.NormalizedResultLimit() : int.MaxValue;

        long regionSteps = CalculateRegionSteps(slices, options.Alignment);
        long processedWork = 0;
        long totalWorkEstimate = Math.Max(1, SaturatingMultiply(regionSteps, Math.Max(1, options.MaxDepth)));

        var progressGate = new object();
        long lastReportTicks = 0;

        ReportProgress(progress, 0, totalWorkEstimate, "Pointer scan");

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
            var sortedTargets = groupedFrontier.Keys.OrderBy(x => x).ToArray();
            if (sortedTargets.Length == 0)
            {
                break;
            }

            var status = $"Pointer scan d{depth + 1}/{options.MaxDepth} targets {sortedTargets.Length}";
            var parentMap = FindParentsForTargets(
                sortedTargets,
                options,
                slices,
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
                        status);
                });

            var nextFrontier = new List<PointerChainNode>(Math.Max(128, frontier.Count * 2));

            foreach (var target in sortedTargets)
            {
                if (cancellationToken.IsCancellationRequested || Volatile.Read(ref limitReached) == 1)
                {
                    break;
                }

                if (!parentMap.TryGetValue(target, out var parents) || parents.Count == 0)
                {
                    continue;
                }

                if (!groupedFrontier.TryGetValue(target, out var nodesForTarget))
                {
                    continue;
                }

                foreach (var node in nodesForTarget)
                {
                    if (cancellationToken.IsCancellationRequested || Volatile.Read(ref limitReached) == 1)
                    {
                        break;
                    }

                    foreach (var parent in parents)
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

                        var offsets = new List<int>(node.Offsets.Count + 1) { parent.Offset };
                        offsets.AddRange(node.Offsets);

                        var chainNode = new PointerChainNode
                        {
                            CurrentAddress = parent.ParentAddress,
                            Offsets = offsets
                        };

                        nextFrontier.Add(chainNode);

                        if (TryMakeResult(chainNode, targetAddress, options.RequireStaticRoot, out var path))
                        {
                            if (results.Count < resultLimit)
                            {
                                results.Add(path);
                            }

                            if (results.Count >= resultLimit)
                            {
                                Volatile.Write(ref limitReached, 1);
                                break;
                            }
                        }
                    }
                }
            }

            frontier = nextFrontier;
            ReportProgress(progress, Volatile.Read(ref processedWork), totalWorkEstimate, status);
        }

        var finalStatus = cancellationToken.IsCancellationRequested
            ? "Pointer scan canceled"
            : Volatile.Read(ref limitReached) == 1
                ? "Pointer scan result limit reached"
                : "Pointer scan finished";

        var finalProcessed = Math.Max(1, Volatile.Read(ref processedWork));
        ReportProgress(progress, finalProcessed, finalProcessed, finalStatus);
        return results;
    }

    private Dictionary<ulong, List<PointerParentCandidate>> FindParentsForTargets(
        ulong[] sortedTargetAddresses,
        PointerScanOptions options,
        IReadOnlyList<ScanSlice> slices,
        CancellationToken cancellationToken,
        Action<long>? progressDelta)
    {
        var mergedParents = new Dictionary<ulong, List<PointerParentCandidate>>(Math.Max(16, sortedTargetAddresses.Length));
        if (sortedTargetAddresses.Length == 0 || slices.Count == 0)
        {
            return mergedParents;
        }

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = options.NormalizedThreadCount(),
            CancellationToken = cancellationToken
        };

        var mergeLock = new object();

        Parallel.ForEach(
            slices,
            parallelOptions,
            () => new LocalParentCollector(),
            (slice, _, local) =>
            {
                ulong cursor = slice.Start;
                int currentChunkSize = InitialReadChunkSize;
                int alignment = Math.Max(1, options.Alignment);

                while (cursor < slice.End)
                {
                    parallelOptions.CancellationToken.ThrowIfCancellationRequested();

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

                    for (int pos = 0; pos < maxPosExclusive; pos += alignment)
                    {
                        if (parallelOptions.CancellationToken.IsCancellationRequested)
                        {
                            break;
                        }

                        var pointerValue = BinaryPrimitives.ReadUInt64LittleEndian(span.Slice(pos, sizeof(long)));
                        var parentAddress = cursor + (ulong)pos;
                        AddMatchesForPointerValue(sortedTargetAddresses, pointerValue, parentAddress, options.MaxOffset, local);

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

                if (local.ParentsByTarget.Count == 0)
                {
                    return;
                }

                lock (mergeLock)
                {
                    foreach (var entry in local.ParentsByTarget)
                    {
                        if (!mergedParents.TryGetValue(entry.Key, out var list))
                        {
                            list = new List<PointerParentCandidate>(entry.Value.Count);
                            mergedParents[entry.Key] = list;
                        }

                        list.AddRange(entry.Value);
                    }
                }
            });

        return mergedParents;
    }

    private static void AddMatchesForPointerValue(
        ulong[] sortedTargetAddresses,
        ulong pointerValue,
        ulong parentAddress,
        int maxOffset,
        LocalParentCollector local)
    {
        int startIndex = LowerBound(sortedTargetAddresses, pointerValue);
        ulong maxDelta = (ulong)Math.Max(0, maxOffset);

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

    private static Dictionary<ulong, List<PointerChainNode>> GroupFrontierByAddress(IEnumerable<PointerChainNode> frontier)
    {
        var grouped = new Dictionary<ulong, List<PointerChainNode>>();
        foreach (var node in frontier)
        {
            if (!grouped.TryGetValue(node.CurrentAddress, out var nodes))
            {
                nodes = new List<PointerChainNode>(1);
                grouped[node.CurrentAddress] = nodes;
            }

            nodes.Add(node);
        }

        return grouped;
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

    private sealed class PointerChainNode
    {
        public ulong CurrentAddress { get; set; }
        public List<int> Offsets { get; set; } = new();
    }

    private sealed class LocalParentCollector
    {
        public Dictionary<ulong, List<PointerParentCandidate>> ParentsByTarget { get; } = new();
        public long PendingProgress { get; set; }

        public void AddCandidate(ulong childAddress, ulong parentAddress, int offset)
        {
            if (!ParentsByTarget.TryGetValue(childAddress, out var list))
            {
                list = new List<PointerParentCandidate>(8);
                ParentsByTarget[childAddress] = list;
            }

            list.Add(new PointerParentCandidate
            {
                ParentAddress = parentAddress,
                Offset = offset
            });
        }
    }

    private readonly record struct ScanSlice(ulong Start, ulong End);
}


