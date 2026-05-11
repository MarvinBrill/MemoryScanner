using MemoryScanner.Models;

namespace MemoryScanner.Core;

internal static class PatternScanPlanner
{
    private const ulong SliceSize = 8UL * 1024UL * 1024UL;
    private const ulong OrderedBalancedSliceSize = 2UL * 1024UL * 1024UL;
    private const ulong OrderedFineSliceSize = 512UL * 1024UL;

    internal static void ResolveDepth(ScanDepthProfile profile, out bool includePrivate, out bool includeImage, out bool scanUnaligned, out int stepMultiplier)
    {
        switch (profile)
        {
            case ScanDepthProfile.Quick:
                includePrivate = false;
                includeImage = true;
                scanUnaligned = false;
                stepMultiplier = 4;
                break;
            case ScanDepthProfile.Deep:
                includePrivate = true;
                includeImage = true;
                scanUnaligned = true;
                stepMultiplier = 1;
                break;
            default:
                includePrivate = true;
                includeImage = true;
                scanUnaligned = false;
                stepMultiplier = 1;
                break;
        }
    }

    internal static ulong ResolveOrderedSliceSize(PatternSearchFocus focus)
    {
        return focus switch
        {
            PatternSearchFocus.Fine => OrderedFineSliceSize,
            _ => OrderedBalancedSliceSize
        };
    }

    internal static int DetermineOrderedBatchWidth(
        PatternSearchFocus focus,
        int normalizedThreadCount,
        bool hasFirstHit,
        bool stopAfterGapEnabled)
    {
        if (normalizedThreadCount <= 1)
        {
            return 1;
        }

        if (hasFirstHit && stopAfterGapEnabled)
        {
            return focus switch
            {
                PatternSearchFocus.Fine => 1,
                _ => Math.Min(2, normalizedThreadCount)
            };
        }

        return focus switch
        {
            PatternSearchFocus.Fine => 1,
            _ => Math.Max(1, Math.Min(2, normalizedThreadCount))
        };
    }

    internal static List<PatternScanSlice> SliceRegions(IReadOnlyList<MemoryRegion> regions, ulong sliceSize)
    {
        var slices = new List<PatternScanSlice>(regions.Count);
        foreach (var region in regions)
        {
            var regionStart = region.BaseAddress;
            var regionEnd = region.BaseAddress + region.RegionSize;
            if (regionEnd <= regionStart)
            {
                continue;
            }

            if (region.RegionSize <= sliceSize)
            {
                slices.Add(new PatternScanSlice(regionStart, regionEnd, regionStart, regionEnd));
                continue;
            }

            for (ulong cursor = regionStart; cursor < regionEnd;)
            {
                var next = Math.Min(regionEnd, cursor + sliceSize);
                slices.Add(new PatternScanSlice(regionStart, regionEnd, cursor, next));
                cursor = next;
            }
        }

        return slices;
    }

    internal static IReadOnlyList<PatternScanSlice> OrderSlices(
        IReadOnlyList<PatternScanSlice> slices,
        PatternSearchOrder searchOrder,
        int customStartPercent)
    {
        if (slices.Count <= 1 || searchOrder == PatternSearchOrder.StartToEnd)
        {
            return slices;
        }

        var ordered = slices.ToList();
        switch (searchOrder)
        {
            case PatternSearchOrder.EndToStart:
                ordered.Sort(static (left, right) => right.SliceStart.CompareTo(left.SliceStart));
                return ordered;

            case PatternSearchOrder.MiddleToOutside:
                ordered.Sort(static (left, right) => left.SliceStart.CompareTo(right.SliceStart));
                return ExpandSlicesFromIndex(ordered, FindSliceIndexByCumulativePercent(ordered, 50));

            case PatternSearchOrder.CustomPercentToOutside:
                ordered.Sort(static (left, right) => left.SliceStart.CompareTo(right.SliceStart));
                return ExpandSlicesFromIndex(ordered, FindSliceIndexByCumulativePercent(ordered, customStartPercent));

            default:
                return ordered;
        }
    }

    internal static IReadOnlyList<PatternScanSlice> SortSlicesByAddress(IReadOnlyList<PatternScanSlice> slices)
    {
        if (slices.Count <= 1)
        {
            return slices;
        }

        var ordered = slices.ToList();
        ordered.Sort(static (left, right) => left.SliceStart.CompareTo(right.SliceStart));
        return ordered;
    }

    internal static string BuildSearchOrderSummary(PatternGeneralRuleOptions options)
    {
        var orderText = options.SearchOrder switch
        {
            PatternSearchOrder.MiddleToOutside => "Order: Middle -> Outside",
            PatternSearchOrder.EndToStart => "Order: End -> Start",
            PatternSearchOrder.CustomPercentToOutside => $"Order: {Math.Clamp(options.CustomSearchStartPercent, 0, 100)}% -> Outside",
            _ => "Order: Start -> End"
        };
        var focusText = options.SearchFocus switch
        {
            PatternSearchFocus.Fine => "Focus: Fine",
            _ => "Focus: Fast"
        };

        return $"{orderText} | {focusText}";
    }

    internal static string BuildOrderedProgressStatus(
        string orderSummary,
        int completedSlices,
        int totalSlices,
        int firstHitSlice,
        bool stopAfterGapEnabled)
    {
        var status = $"Pattern scan running | {orderSummary}";
        if (stopAfterGapEnabled)
        {
            status += " | Gap stop on";
        }

        status += $" | Slice {completedSlices}/{totalSlices}";
        if (firstHitSlice > 0)
        {
            status += $" | First hit slice {firstHitSlice}";
        }

        return status;
    }

    internal static long CalculateTotalSteps(IReadOnlyList<PatternScanSlice> slices, int typeSize, int stepSize)
    {
        long total = 0;
        foreach (var slice in slices)
        {
            var size = (long)(slice.SliceEnd - slice.SliceStart);
            var span = Math.Max(0L, size - typeSize + 1);
            if (span <= 0)
            {
                continue;
            }

            total += Math.Max(1, span / stepSize);
        }

        return Math.Max(1, total);
    }

    internal static double? CalculateAddressPercent(IReadOnlyList<PatternScanSlice> addressOrderedSlices, ulong address)
    {
        if (addressOrderedSlices.Count == 0)
        {
            return null;
        }

        ulong totalBytes = 0;
        foreach (var slice in addressOrderedSlices)
        {
            totalBytes += slice.SliceEnd - slice.SliceStart;
        }

        if (totalBytes == 0)
        {
            return null;
        }

        ulong consumedBytes = 0;
        foreach (var slice in addressOrderedSlices)
        {
            var sliceBytes = slice.SliceEnd - slice.SliceStart;
            if (address < slice.SliceStart)
            {
                return (double)consumedBytes / totalBytes * 100d;
            }

            if (address >= slice.SliceStart && address < slice.SliceEnd)
            {
                var offsetInSlice = address - slice.SliceStart;
                return ((double)consumedBytes + offsetInSlice) / totalBytes * 100d;
            }

            consumedBytes += sliceBytes;
        }

        return 100d;
    }

    private static List<PatternScanSlice> ExpandSlicesFromIndex(List<PatternScanSlice> orderedSlices, int anchorIndex)
    {
        if (orderedSlices.Count <= 1)
        {
            return orderedSlices;
        }

        var result = new List<PatternScanSlice>(orderedSlices.Count)
        {
            orderedSlices[anchorIndex]
        };

        var left = anchorIndex - 1;
        var right = anchorIndex + 1;
        while (left >= 0 || right < orderedSlices.Count)
        {
            if (left < 0)
            {
                result.Add(orderedSlices[right++]);
                continue;
            }

            if (right >= orderedSlices.Count)
            {
                result.Add(orderedSlices[left--]);
                continue;
            }

            var leftDistance = anchorIndex - left;
            var rightDistance = right - anchorIndex;
            if (leftDistance <= rightDistance)
            {
                result.Add(orderedSlices[left--]);
            }
            else
            {
                result.Add(orderedSlices[right++]);
            }
        }

        return result;
    }

    private static int FindSliceIndexByCumulativePercent(IReadOnlyList<PatternScanSlice> orderedSlices, int percent)
    {
        if (orderedSlices.Count == 0)
        {
            return 0;
        }

        var clampedPercent = Math.Clamp(percent, 0, 100);
        if (clampedPercent <= 0)
        {
            return 0;
        }

        if (clampedPercent >= 100)
        {
            return orderedSlices.Count - 1;
        }

        ulong totalBytes = 0;
        for (var index = 0; index < orderedSlices.Count; index++)
        {
            totalBytes += orderedSlices[index].SliceEnd - orderedSlices[index].SliceStart;
        }

        if (totalBytes == 0)
        {
            return Math.Min(orderedSlices.Count - 1, orderedSlices.Count / 2);
        }

        var targetBytes = (totalBytes * (ulong)clampedPercent) / 100UL;
        ulong consumedBytes = 0;
        for (var index = 0; index < orderedSlices.Count; index++)
        {
            consumedBytes += orderedSlices[index].SliceEnd - orderedSlices[index].SliceStart;
            if (consumedBytes >= targetBytes)
            {
                return index;
            }
        }

        return orderedSlices.Count - 1;
    }
}
