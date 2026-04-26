using MemoryScanner.Models;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;

namespace MemoryScanner.Core;

public sealed partial class PointerScanService
{
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
        return ExceptionUtilities.IsOnlyCancellation(ex);
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

}
