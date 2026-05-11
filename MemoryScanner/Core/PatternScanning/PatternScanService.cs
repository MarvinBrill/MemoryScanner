using MemoryScanner.Models;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace MemoryScanner.Core;

public sealed class PatternScanService
{
    private const ulong SliceSize = 8UL * 1024UL * 1024UL;
    private const ulong OrderedBalancedSliceSize = 2UL * 1024UL * 1024UL;
    private const ulong OrderedFineSliceSize = 512UL * 1024UL;
    private const int ReadChunkSize = 1024 * 1024;

    private readonly IMemoryAccessor _memoryAccessor;
    private readonly MemoryRegionEnumerator _regionEnumerator;

    public PatternScanService(IMemoryAccessor memoryAccessor, MemoryRegionEnumerator regionEnumerator)
    {
        _memoryAccessor = memoryAccessor;
        _regionEnumerator = regionEnumerator;
    }

    public IReadOnlyList<AddressPatternScanResult> Scan(
        AddressPatternScanRequest request,
        ScanExecutionOptions options,
        IProgress<ScanProgressInfo>? progress,
        CancellationToken cancellationToken)
    {
        if (!_memoryAccessor.IsAttached)
        {
            return Array.Empty<AddressPatternScanResult>();
        }

        if (!ScanService.TryParseValue(request.StartDataType, request.StartValueText, out var startValue))
        {
            throw new InvalidOperationException("Invalid start value.");
        }

        var startCriterion = CompileStartCriterion(request, startValue);
        var compiledRules = CompileRules(request);
        ResolveDepth(options.DepthProfile, out var includePrivate, out var includeImage, out var scanUnaligned, out var stepMultiplier);
        var requiresOrderedExecution = request.GeneralRules.SearchOrder != PatternSearchOrder.StartToEnd
            || (request.GeneralRules.StopAfterGapFromLastMatchEnabled && request.GeneralRules.MaxAddressesWithoutMatchAfterFirstHit > 0);

        var regions = _regionEnumerator.Enumerate(_memoryAccessor.Process, includePrivate, includeImage, options.IncludeMapped);
        var sliceSize = requiresOrderedExecution
            ? ResolveOrderedSliceSize(request.GeneralRules.SearchFocus)
            : SliceSize;
        var slices = OrderSlices(
            SliceRegions(regions, sliceSize),
            request.GeneralRules.SearchOrder,
            request.GeneralRules.CustomSearchStartPercent);

        var startValueSize = GetTypeReadSize(request.StartDataType, request.StartStringByteLength);
        var startScanStepSize = scanUnaligned
            ? 1
            : Math.Max(1, GetTypeNaturalAlignmentSize(request.StartDataType, request.StartStringByteLength) * stepMultiplier);

        var prefixOverlap = compiledRules.Count == 0
            ? 0
            : Math.Max(0, -compiledRules.Min(r => r.ByteOffset));
        var suffixOverlap = compiledRules.Count == 0
            ? 0
            : Math.Max(0, compiledRules.Max(r => r.ByteOffset + r.ReadSize) - 1);

        if (requiresOrderedExecution)
        {
            return ScanOrderedBatches(
                request,
                options,
                progress,
                cancellationToken,
                slices,
                startCriterion,
                compiledRules,
                startScanStepSize,
                prefixOverlap,
                suffixOverlap);
        }

        var totalSteps = CalculateTotalSteps(slices, startValueSize, startScanStepSize);
        var processedSteps = 0L;
        var lastReportTicks = 0L;
        var progressGate = new object();
        var limit = options.NormalizedResultLimit();
        var resultCount = 0;
        var stopRequested = 0;
        var rows = new List<AddressPatternScanResult>();
        var mergeGate = new object();

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = options.NormalizedThreadCount(),
            CancellationToken = cancellationToken
        };

        try
        {
            Parallel.ForEach(
                slices,
                parallelOptions,
                () => new List<AddressPatternScanResult>(),
                (slice, _, localRows) =>
                {
                    ScanSlice(
                        slice,
                        startCriterion,
                        startScanStepSize,
                        compiledRules,
                        prefixOverlap,
                        suffixOverlap,
                        localRows,
                        ref processedSteps,
                        totalSteps,
                        progress,
                        progressGate,
                        ref lastReportTicks,
                        limit,
                        ref resultCount,
                        ref stopRequested,
                        cancellationToken);

                    return localRows;
                },
                localRows =>
                {
                    if (localRows.Count == 0)
                    {
                        return;
                    }

                    lock (mergeGate)
                    {
                        rows.AddRange(localRows);
                    }
                });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (AggregateException ex) when (ExceptionUtilities.IsOnlyCancellation(ex))
        {
        }

        rows.Sort((left, right) => left.Address.CompareTo(right.Address));
        if (rows.Count > limit)
        {
            rows.RemoveRange(limit, rows.Count - limit);
        }

        progress?.Report(new ScanProgressInfo
        {
            Processed = totalSteps,
            Total = totalSteps,
            StatusText = cancellationToken.IsCancellationRequested
                ? $"Pattern scan canceled ({rows.Count} partial results)"
                : $"Pattern scan finished ({rows.Count} results)"
        });

        return rows;
    }

    private IReadOnlyList<AddressPatternScanResult> ScanOrderedBatches(
        AddressPatternScanRequest request,
        ScanExecutionOptions options,
        IProgress<ScanProgressInfo>? progress,
        CancellationToken cancellationToken,
        IReadOnlyList<PatternScanSlice> slices,
        CompiledStartCriterion startCriterion,
        IReadOnlyList<CompiledPatternRule> compiledRules,
        int startScanStepSize,
        int prefixOverlap,
        int suffixOverlap)
    {
        var totalSteps = CalculateTotalSteps(slices, startCriterion.ReadSize, startScanStepSize);
        var processedSteps = 0L;
        var limit = options.NormalizedResultLimit();
        var rows = new List<AddressPatternScanResult>();
        var stopAfterGapEnabled = request.GeneralRules.StopAfterGapFromLastMatchEnabled
            && request.GeneralRules.MaxAddressesWithoutMatchAfterFirstHit > 0;
        var orderSummary = BuildSearchOrderSummary(request.GeneralRules);

        if (stopAfterGapEnabled)
        {
            return ScanOrderedWithStrictGapStop(
                request,
                progress,
                cancellationToken,
                slices,
                startCriterion,
                compiledRules,
                startScanStepSize,
                prefixOverlap,
                suffixOverlap,
                totalSteps,
                limit,
                orderSummary);
        }

        var completedSlices = 0;
        var firstHitSlice = 0;

        var normalizedThreadCount = Math.Max(1, options.NormalizedThreadCount());
        for (var batchStart = 0; batchStart < slices.Count && !cancellationToken.IsCancellationRequested;)
        {
            var batchWidth = DetermineOrderedBatchWidth(
                request.GeneralRules.SearchFocus,
                normalizedThreadCount,
                false,
                false);
            var batchCount = Math.Min(batchWidth, slices.Count - batchStart);
            var outcomes = new SliceScanOutcome[batchCount];
            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = batchCount,
                CancellationToken = cancellationToken
            };

            try
            {
                Parallel.For(0, batchCount, parallelOptions, index =>
                {
                    outcomes[index] = ScanSliceToOutcome(
                        slices[batchStart + index],
                        startCriterion,
                        startScanStepSize,
                        compiledRules,
                        prefixOverlap,
                        suffixOverlap,
                        cancellationToken);
                });
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (AggregateException ex) when (ExceptionUtilities.IsOnlyCancellation(ex))
            {
                break;
            }

            for (var index = 0; index < batchCount; index++)
            {
                var outcome = outcomes[index];
                processedSteps += outcome.ProcessedSteps;
                completedSlices++;

                if (outcome.Rows.Count > 0)
                {
                    rows.AddRange(outcome.Rows);
                    if (firstHitSlice == 0)
                    {
                        firstHitSlice = completedSlices;
                    }

                    if (rows.Count >= limit)
                    {
                        goto FinalizeOrderedScan;
                    }
                }

                progress?.Report(new ScanProgressInfo
                {
                    Processed = processedSteps,
                    Total = totalSteps,
                    PhaseProcessed = completedSlices,
                    PhaseTotal = slices.Count,
                    StatusText = BuildOrderedProgressStatus(orderSummary, completedSlices, slices.Count, firstHitSlice, false)
                });
            }

            batchStart += batchCount;
        }

FinalizeOrderedScan:
        rows.Sort((left, right) => left.Address.CompareTo(right.Address));
        if (rows.Count > limit)
        {
            rows.RemoveRange(limit, rows.Count - limit);
        }

        progress?.Report(new ScanProgressInfo
        {
            Processed = totalSteps,
            Total = totalSteps,
            PhaseProcessed = slices.Count,
            PhaseTotal = slices.Count,
            StatusText = cancellationToken.IsCancellationRequested
                ? $"Pattern scan canceled | {orderSummary} | Results {rows.Count}"
                : $"Pattern scan finished | {orderSummary} | Results {rows.Count}"
        });

        return rows;
    }

    private IReadOnlyList<AddressPatternScanResult> ScanOrderedWithStrictGapStop(
        AddressPatternScanRequest request,
        IProgress<ScanProgressInfo>? progress,
        CancellationToken cancellationToken,
        IReadOnlyList<PatternScanSlice> slices,
        CompiledStartCriterion startCriterion,
        IReadOnlyList<CompiledPatternRule> compiledRules,
        int startScanStepSize,
        int prefixOverlap,
        int suffixOverlap,
        long totalSteps,
        int limit,
        string orderSummary)
    {
        var rows = new List<AddressPatternScanResult>();
        long processedSteps = 0;
        var completedSlices = 0;
        var firstHitSlice = 0;
        var hasFirstHit = false;
        var consecutiveMisses = 0;
        var gapLimit = Math.Max(1, request.GeneralRules.MaxAddressesWithoutMatchAfterFirstHit);
        var stopAfterGapReached = false;
        var lastReportTicks = 0L;
        var progressGate = new object();

        for (var sliceIndex = 0; sliceIndex < slices.Count && !cancellationToken.IsCancellationRequested; sliceIndex++)
        {
            var slice = slices[sliceIndex];
            var stopInSlice = ScanSliceStrictGap(
                slice,
                startCriterion,
                startScanStepSize,
                compiledRules,
                prefixOverlap,
                suffixOverlap,
                rows,
                ref processedSteps,
                totalSteps,
                progress,
                progressGate,
                ref lastReportTicks,
                ref hasFirstHit,
                ref firstHitSlice,
                sliceIndex + 1,
                ref consecutiveMisses,
                gapLimit,
                limit,
                orderSummary,
                slices.Count,
                cancellationToken);

            completedSlices = sliceIndex + 1;
            if (stopInSlice == StrictGapStopReason.ResultLimit)
            {
                break;
            }

            if (stopInSlice == StrictGapStopReason.GapReached)
            {
                stopAfterGapReached = true;
                break;
            }

            progress?.Report(new ScanProgressInfo
            {
                Processed = processedSteps,
                Total = totalSteps,
                PhaseProcessed = completedSlices,
                PhaseTotal = slices.Count,
                StatusText = BuildOrderedProgressStatus(orderSummary, completedSlices, slices.Count, firstHitSlice, true)
            });
        }

        rows.Sort((left, right) => left.Address.CompareTo(right.Address));
        if (rows.Count > limit)
        {
            rows.RemoveRange(limit, rows.Count - limit);
        }

        progress?.Report(new ScanProgressInfo
        {
            Processed = processedSteps,
            Total = totalSteps,
            PhaseProcessed = completedSlices,
            PhaseTotal = slices.Count,
            StatusText = cancellationToken.IsCancellationRequested
                ? $"Pattern scan canceled | {orderSummary} | Results {rows.Count}"
                : stopAfterGapReached
                    ? $"Pattern scan stopped after gap | {orderSummary} | Results {rows.Count}"
                    : $"Pattern scan finished | {orderSummary} | Results {rows.Count}"
        });

        return rows;
    }

    private void ScanSlice(
        PatternScanSlice slice,
        CompiledStartCriterion startCriterion,
        int startScanStepSize,
        IReadOnlyList<CompiledPatternRule> compiledRules,
        int prefixOverlap,
        int suffixOverlap,
        List<AddressPatternScanResult> localRows,
        ref long processedSteps,
        long totalSteps,
        IProgress<ScanProgressInfo>? progress,
        object progressGate,
        ref long lastReportTicks,
        int limit,
        ref int resultCount,
        ref int stopRequested,
        CancellationToken cancellationToken)
    {
        for (ulong chunkStart = slice.SliceStart;
             chunkStart < slice.SliceEnd && Volatile.Read(ref stopRequested) == 0;
             chunkStart += ReadChunkSize)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var mainEndExclusive = Math.Min(slice.SliceEnd, chunkStart + (ulong)ReadChunkSize);
            if (mainEndExclusive <= chunkStart)
            {
                break;
            }

            var readStart = chunkStart >= (ulong)prefixOverlap
                ? Math.Max(slice.RegionStart, chunkStart - (ulong)prefixOverlap)
                : slice.RegionStart;
            var readEndExclusive = Math.Min(slice.RegionEnd, mainEndExclusive + (ulong)suffixOverlap);
            if (readEndExclusive <= readStart)
            {
                continue;
            }

            var bytesToRead = checked((int)(readEndExclusive - readStart));
            var buffer = ArrayPool<byte>.Shared.Rent(bytesToRead);
            try
            {
                if (!_memoryAccessor.TryReadBytes(readStart, buffer, bytesToRead, out var bytesRead) || bytesRead < bytesToRead)
                {
                    var skipped = CountSkippedSteps(chunkStart, mainEndExclusive, startCriterion.ReadSize, startScanStepSize);
                    Interlocked.Add(ref processedSteps, skipped);
                    TryReportProgressThrottled(progress, progressGate, ref lastReportTicks, Volatile.Read(ref processedSteps), totalSteps, "Pattern scan running...");
                    continue;
                }

                var candidateMaxExclusive = mainEndExclusive >= (ulong)startCriterion.ReadSize
                    ? mainEndExclusive - (ulong)startCriterion.ReadSize + 1
                    : chunkStart;

                for (ulong candidateAddress = chunkStart;
                     candidateAddress < candidateMaxExclusive && Volatile.Read(ref stopRequested) == 0;
                     candidateAddress += (ulong)startScanStepSize)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var candidateIndex = checked((int)(candidateAddress - readStart));
                    if (!TryMatchStartValue(buffer.AsSpan(candidateIndex), startCriterion, out var startValueText))
                    {
                        Interlocked.Increment(ref processedSteps);
                        continue;
                    }

                    if (TryEvaluatePattern(candidateAddress, readStart, buffer, slice.RegionStart, slice.RegionEnd, compiledRules, out var previewText))
                    {
                        localRows.Add(new AddressPatternScanResult
                        {
                            Address = candidateAddress,
                            ValueText = startValueText,
                            DataType = startCriterion.DataType,
                            StringByteLength = startCriterion.StringByteLength,
                            PreviewText = previewText
                        });

                        if (Interlocked.Increment(ref resultCount) >= limit)
                        {
                            Volatile.Write(ref stopRequested, 1);
                        }
                    }

                    var processed = Interlocked.Increment(ref processedSteps);
                    TryReportProgressThrottled(progress, progressGate, ref lastReportTicks, processed, totalSteps, "Pattern scan running...");
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }

    private SliceScanOutcome ScanSliceToOutcome(
        PatternScanSlice slice,
        CompiledStartCriterion startCriterion,
        int startScanStepSize,
        IReadOnlyList<CompiledPatternRule> compiledRules,
        int prefixOverlap,
        int suffixOverlap,
        CancellationToken cancellationToken)
    {
        var rows = new List<AddressPatternScanResult>();
        long processedSteps = 0;

        for (ulong chunkStart = slice.SliceStart; chunkStart < slice.SliceEnd; chunkStart += ReadChunkSize)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var mainEndExclusive = Math.Min(slice.SliceEnd, chunkStart + (ulong)ReadChunkSize);
            if (mainEndExclusive <= chunkStart)
            {
                break;
            }

            var readStart = chunkStart >= (ulong)prefixOverlap
                ? Math.Max(slice.RegionStart, chunkStart - (ulong)prefixOverlap)
                : slice.RegionStart;
            var readEndExclusive = Math.Min(slice.RegionEnd, mainEndExclusive + (ulong)suffixOverlap);
            if (readEndExclusive <= readStart)
            {
                continue;
            }

            var bytesToRead = checked((int)(readEndExclusive - readStart));
            var buffer = ArrayPool<byte>.Shared.Rent(bytesToRead);
            try
            {
                if (!_memoryAccessor.TryReadBytes(readStart, buffer, bytesToRead, out var bytesRead) || bytesRead < bytesToRead)
                {
                    processedSteps += CountSkippedSteps(chunkStart, mainEndExclusive, startCriterion.ReadSize, startScanStepSize);
                    continue;
                }

                var candidateMaxExclusive = mainEndExclusive >= (ulong)startCriterion.ReadSize
                    ? mainEndExclusive - (ulong)startCriterion.ReadSize + 1
                    : chunkStart;

                for (ulong candidateAddress = chunkStart; candidateAddress < candidateMaxExclusive; candidateAddress += (ulong)startScanStepSize)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var candidateIndex = checked((int)(candidateAddress - readStart));
                    if (!TryMatchStartValue(buffer.AsSpan(candidateIndex), startCriterion, out var startValueText))
                    {
                        processedSteps++;
                        continue;
                    }

                    if (TryEvaluatePattern(candidateAddress, readStart, buffer, slice.RegionStart, slice.RegionEnd, compiledRules, out var previewText))
                    {
                        rows.Add(new AddressPatternScanResult
                        {
                            Address = candidateAddress,
                            ValueText = startValueText,
                            DataType = startCriterion.DataType,
                            StringByteLength = startCriterion.StringByteLength,
                            PreviewText = previewText
                        });
                    }

                    processedSteps++;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        return new SliceScanOutcome(rows, processedSteps, slice.SliceEnd - slice.SliceStart);
    }

    private StrictGapStopReason ScanSliceStrictGap(
        PatternScanSlice slice,
        CompiledStartCriterion startCriterion,
        int startScanStepSize,
        IReadOnlyList<CompiledPatternRule> compiledRules,
        int prefixOverlap,
        int suffixOverlap,
        List<AddressPatternScanResult> rows,
        ref long processedSteps,
        long totalSteps,
        IProgress<ScanProgressInfo>? progress,
        object progressGate,
        ref long lastReportTicks,
        ref bool hasFirstHit,
        ref int firstHitSlice,
        int currentSliceNumber,
        ref int consecutiveMisses,
        int gapLimit,
        int resultLimit,
        string orderSummary,
        int totalSlices,
        CancellationToken cancellationToken)
    {
        for (ulong chunkStart = slice.SliceStart; chunkStart < slice.SliceEnd; chunkStart += ReadChunkSize)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var mainEndExclusive = Math.Min(slice.SliceEnd, chunkStart + (ulong)ReadChunkSize);
            if (mainEndExclusive <= chunkStart)
            {
                break;
            }

            var readStart = chunkStart >= (ulong)prefixOverlap
                ? Math.Max(slice.RegionStart, chunkStart - (ulong)prefixOverlap)
                : slice.RegionStart;
            var readEndExclusive = Math.Min(slice.RegionEnd, mainEndExclusive + (ulong)suffixOverlap);
            if (readEndExclusive <= readStart)
            {
                continue;
            }

            var bytesToRead = checked((int)(readEndExclusive - readStart));
            var buffer = ArrayPool<byte>.Shared.Rent(bytesToRead);
            try
            {
                if (!_memoryAccessor.TryReadBytes(readStart, buffer, bytesToRead, out var bytesRead) || bytesRead < bytesToRead)
                {
                    var skipped = CountSkippedSteps(chunkStart, mainEndExclusive, startCriterion.ReadSize, startScanStepSize);
                    processedSteps += skipped;
                    if (hasFirstHit)
                    {
                        consecutiveMisses += checked((int)Math.Min(int.MaxValue, skipped));
                        if (consecutiveMisses >= gapLimit)
                        {
                            return StrictGapStopReason.GapReached;
                        }
                    }

                    TryReportProgressThrottled(
                        progress,
                        progressGate,
                        ref lastReportTicks,
                        processedSteps,
                        totalSteps,
                        BuildOrderedProgressStatus(orderSummary, currentSliceNumber, totalSlices, firstHitSlice, true));
                    continue;
                }

                var candidateMaxExclusive = mainEndExclusive >= (ulong)startCriterion.ReadSize
                    ? mainEndExclusive - (ulong)startCriterion.ReadSize + 1
                    : chunkStart;

                for (ulong candidateAddress = chunkStart; candidateAddress < candidateMaxExclusive; candidateAddress += (ulong)startScanStepSize)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var candidateIndex = checked((int)(candidateAddress - readStart));
                    var isMatch = false;
                    if (TryMatchStartValue(buffer.AsSpan(candidateIndex), startCriterion, out var startValueText)
                        && TryEvaluatePattern(candidateAddress, readStart, buffer, slice.RegionStart, slice.RegionEnd, compiledRules, out var previewText))
                    {
                        rows.Add(new AddressPatternScanResult
                        {
                            Address = candidateAddress,
                            ValueText = startValueText,
                            DataType = startCriterion.DataType,
                            StringByteLength = startCriterion.StringByteLength,
                            PreviewText = previewText
                        });

                        if (firstHitSlice == 0)
                        {
                            firstHitSlice = currentSliceNumber;
                        }

                        hasFirstHit = true;
                        consecutiveMisses = 0;
                        isMatch = true;

                        if (rows.Count >= resultLimit)
                        {
                            processedSteps++;
                            return StrictGapStopReason.ResultLimit;
                        }
                    }

                    if (!isMatch && hasFirstHit)
                    {
                        consecutiveMisses++;
                        if (consecutiveMisses >= gapLimit)
                        {
                            processedSteps++;
                            return StrictGapStopReason.GapReached;
                        }
                    }

                    processedSteps++;
                    TryReportProgressThrottled(
                        progress,
                        progressGate,
                        ref lastReportTicks,
                        processedSteps,
                        totalSteps,
                        BuildOrderedProgressStatus(orderSummary, currentSliceNumber, totalSlices, firstHitSlice, true));
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        return StrictGapStopReason.None;
    }

    private static long CountSkippedSteps(ulong start, ulong endExclusive, int typeSize, int stepSize)
    {
        if (endExclusive <= start || typeSize <= 0 || stepSize <= 0)
        {
            return 0;
        }

        var span = (long)(endExclusive - start);
        var available = Math.Max(0L, span - typeSize + 1);
        if (available <= 0)
        {
            return 0;
        }

        return Math.Max(1L, (available + stepSize - 1) / stepSize);
    }

    private static bool TryEvaluatePattern(
        ulong candidateAddress,
        ulong readStart,
        byte[] buffer,
        ulong regionStart,
        ulong regionEnd,
        IReadOnlyList<CompiledPatternRule> rules,
        out string previewText)
    {
        if (rules.Count == 0)
        {
            previewText = "No extra rules";
            return true;
        }

        var previewParts = new string[rules.Count];
        foreach (var rule in rules)
        {
            var offsetBytes = rule.ByteOffset;
            ulong targetAddress;
            if (offsetBytes >= 0)
            {
                targetAddress = candidateAddress + (ulong)offsetBytes;
            }
            else
            {
                var delta = (ulong)(-offsetBytes);
                if (candidateAddress < delta)
                {
                    previewText = string.Empty;
                    return false;
                }

                targetAddress = candidateAddress - delta;
            }

            if (targetAddress < regionStart)
            {
                previewText = string.Empty;
                return false;
            }

            var readSize = (ulong)rule.ReadSize;
            if (targetAddress > regionEnd || targetAddress + readSize > regionEnd)
            {
                previewText = string.Empty;
                return false;
            }

            var targetIndex = checked((int)(targetAddress - readStart));
            if (targetIndex < 0 || targetIndex + rule.ReadSize > buffer.Length)
            {
                previewText = string.Empty;
                return false;
            }

            if (!TryReadValueFromBuffer(buffer.AsSpan(targetIndex), rule.DataType, rule.StringByteLength, out var currentValue))
            {
                previewText = string.Empty;
                return false;
            }

            if (!ValuesMatch(rule.DataType, rule.Comparison, currentValue, rule.Value, rule.ValueUpper, rule.ValueText, rule.ValueUpperText))
            {
                previewText = string.Empty;
                return false;
            }

            previewParts[rule.OriginalIndex] = $"{FormatSignedStep(rule.RelativeStep)} => {ValueTextFormatter.Format(currentValue)}";
        }

        previewText = string.Join(" | ", previewParts.Where(static part => !string.IsNullOrWhiteSpace(part)));
        return true;
    }

    private static IReadOnlyList<CompiledPatternRule> CompileRules(AddressPatternScanRequest request)
    {
        var compiled = new List<CompiledPatternRule>(request.Rules.Count);
        for (var index = 0; index < request.Rules.Count; index++)
        {
            var rule = request.Rules[index];
            if (!IsRuleComparisonSupported(rule.DataType, rule.Comparison))
            {
                throw new InvalidOperationException($"Comparison '{rule.Comparison}' is not supported for data type '{rule.DataType}'.");
            }

            var stringReadLength = ResolveStringReadLength(rule.DataType, rule.ValueText, rule.ValueToText);
            var readSize = GetTypeReadSize(rule.DataType, stringReadLength);
            if (RequiresValue(rule.Comparison))
            {
                if (!ScanService.TryParseValue(rule.DataType, rule.ValueText, out var value))
                {
                    throw new InvalidOperationException($"Invalid rule value for step {rule.RelativeStep}.");
                }

                object? valueUpper = null;
                if (rule.Comparison == ScanComparison.Between)
                {
                    if (!ScanService.TryParseValue(rule.DataType, rule.ValueToText, out var upper))
                    {
                        throw new InvalidOperationException($"Invalid upper rule value for step {rule.RelativeStep}.");
                    }

                    valueUpper = upper;
                }

                compiled.Add(new CompiledPatternRule(
                    rule.RelativeStep,
                    checked(rule.RelativeStep * request.StepSizeBytes),
                    rule.DataType,
                    rule.Comparison,
                    value,
                    valueUpper,
                    rule.ValueText ?? string.Empty,
                    rule.ValueToText ?? string.Empty,
                    stringReadLength,
                    readSize,
                    index,
                    ComputeRulePriority(rule.DataType, rule.Comparison, rule.ValueText, rule.ValueToText)));
                continue;
            }

            compiled.Add(new CompiledPatternRule(
                rule.RelativeStep,
                checked(rule.RelativeStep * request.StepSizeBytes),
                rule.DataType,
                rule.Comparison,
                null,
                null,
                rule.ValueText ?? string.Empty,
                rule.ValueToText ?? string.Empty,
                stringReadLength,
                readSize,
                index,
                ComputeRulePriority(rule.DataType, rule.Comparison, rule.ValueText, rule.ValueToText)));
        }

        compiled.Sort(static (left, right) =>
        {
            var priorityCompare = left.Priority.CompareTo(right.Priority);
            return priorityCompare != 0 ? priorityCompare : left.OriginalIndex.CompareTo(right.OriginalIndex);
        });

        return compiled;
    }

    private static CompiledStartCriterion CompileStartCriterion(AddressPatternScanRequest request, object startValue)
    {
        return new CompiledStartCriterion(
            request.StartDataType,
            request.StartValueText,
            request.StartStringByteLength,
            GetTypeReadSize(request.StartDataType, request.StartStringByteLength),
            startValue);
    }

    private static bool RequiresValue(ScanComparison comparison)
    {
        return comparison is ScanComparison.Equal
            or ScanComparison.NotEqual
            or ScanComparison.Greater
            or ScanComparison.Less
            or ScanComparison.Between;
    }

    private static bool IsRuleComparisonSupported(MemoryDataType dataType, ScanComparison comparison)
    {
        if (dataType == MemoryDataType.String)
        {
            return comparison is ScanComparison.Equal or ScanComparison.NotEqual;
        }

        return comparison is ScanComparison.Equal
            or ScanComparison.NotEqual
            or ScanComparison.Greater
            or ScanComparison.Less
            or ScanComparison.Between;
    }

    private static bool TryReadValueFromBuffer(ReadOnlySpan<byte> buffer, MemoryDataType dataType, int stringByteLength, out object value)
    {
        value = 0;
        switch (dataType)
        {
            case MemoryDataType.Byte:
                if (buffer.Length < sizeof(byte))
                {
                    return false;
                }

                value = buffer[0];
                return true;
            case MemoryDataType.Int16:
                if (buffer.Length < sizeof(short))
                {
                    return false;
                }

                value = BinaryPrimitives.ReadInt16LittleEndian(buffer);
                return true;
            case MemoryDataType.Int32:
                if (buffer.Length < sizeof(int))
                {
                    return false;
                }

                value = BinaryPrimitives.ReadInt32LittleEndian(buffer);
                return true;
            case MemoryDataType.Int64:
                if (buffer.Length < sizeof(long))
                {
                    return false;
                }

                value = BinaryPrimitives.ReadInt64LittleEndian(buffer);
                return true;
            case MemoryDataType.Float:
                if (buffer.Length < sizeof(float))
                {
                    return false;
                }

                value = BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(buffer));
                return true;
            case MemoryDataType.Double:
                if (buffer.Length < sizeof(double))
                {
                    return false;
                }

                value = BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(buffer));
                return true;
            case MemoryDataType.String:
                var length = Math.Max(1, stringByteLength);
                if (buffer.Length < length)
                {
                    return false;
                }

                value = DecodeStringBytes(buffer[..length]);
                return true;
            default:
                return false;
        }
    }

    private static bool TryMatchStartValue(ReadOnlySpan<byte> buffer, CompiledStartCriterion criterion, out string valueText)
    {
        valueText = string.Empty;
        switch (criterion.DataType)
        {
            case MemoryDataType.Byte:
                if (buffer.Length < sizeof(byte))
                {
                    return false;
                }

                var byteValue = buffer[0];
                if (byteValue != (byte)criterion.TypedValue)
                {
                    return false;
                }

                valueText = ValueTextFormatter.Format(byteValue);
                return true;

            case MemoryDataType.Int16:
                if (buffer.Length < sizeof(short))
                {
                    return false;
                }

                var int16Value = BinaryPrimitives.ReadInt16LittleEndian(buffer);
                if (int16Value != (short)criterion.TypedValue)
                {
                    return false;
                }

                valueText = ValueTextFormatter.Format(int16Value);
                return true;

            case MemoryDataType.Int32:
                if (buffer.Length < sizeof(int))
                {
                    return false;
                }

                var int32Value = BinaryPrimitives.ReadInt32LittleEndian(buffer);
                if (int32Value != (int)criterion.TypedValue)
                {
                    return false;
                }

                valueText = ValueTextFormatter.Format(int32Value);
                return true;

            case MemoryDataType.Int64:
                if (buffer.Length < sizeof(long))
                {
                    return false;
                }

                var int64Value = BinaryPrimitives.ReadInt64LittleEndian(buffer);
                if (int64Value != (long)criterion.TypedValue)
                {
                    return false;
                }

                valueText = ValueTextFormatter.Format(int64Value);
                return true;

            case MemoryDataType.Float:
                if (buffer.Length < sizeof(float))
                {
                    return false;
                }

                var floatValue = BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(buffer));
                if (!FloatValuesEqual(floatValue, (float)criterion.TypedValue, ResolveFloatingTolerance(criterion.RawText), criterion.RawText))
                {
                    return false;
                }

                valueText = ValueTextFormatter.Format(floatValue);
                return true;

            case MemoryDataType.Double:
                if (buffer.Length < sizeof(double))
                {
                    return false;
                }

                var doubleValue = BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(buffer));
                if (!DoubleValuesEqual(doubleValue, (double)criterion.TypedValue, ResolveFloatingTolerance(criterion.RawText), criterion.RawText))
                {
                    return false;
                }

                valueText = ValueTextFormatter.Format(doubleValue);
                return true;

            case MemoryDataType.String:
                var length = Math.Max(1, criterion.StringByteLength);
                if (buffer.Length < length)
                {
                    return false;
                }

                var textValue = DecodeStringBytes(buffer[..length]);
                var expectedText = (string)criterion.TypedValue;
                if (!string.Equals(textValue, expectedText, StringComparison.Ordinal))
                {
                    return false;
                }

                valueText = textValue;
                return true;

            default:
                return false;
        }
    }

    private static string DecodeStringBytes(ReadOnlySpan<byte> bytes)
    {
        var terminatorIndex = bytes.IndexOf((byte)0);
        var content = terminatorIndex >= 0
            ? bytes[..terminatorIndex]
            : bytes;

        if (content.Length == 0)
        {
            return string.Empty;
        }

        return Encoding.UTF8.GetString(content);
    }

    private static int ResolveStringReadLength(MemoryDataType dataType, string? primaryText, string? secondaryText)
    {
        if (dataType != MemoryDataType.String)
        {
            return 0;
        }

        var primaryLength = Encoding.UTF8.GetByteCount(primaryText ?? string.Empty);
        var secondaryLength = Encoding.UTF8.GetByteCount(secondaryText ?? string.Empty);
        return Math.Clamp(Math.Max(primaryLength, secondaryLength) + 1, 1, 4096);
    }

    private static bool ValuesMatch(
        MemoryDataType dataType,
        ScanComparison comparison,
        object currentValue,
        object? expectedValue,
        object? expectedUpperValue,
        string? expectedText,
        string? expectedUpperText)
    {
        return dataType switch
        {
            MemoryDataType.Byte => MatchTyped(comparison, Convert.ToByte(currentValue, CultureInfo.InvariantCulture), Convert.ToByte(expectedValue ?? 0, CultureInfo.InvariantCulture), Convert.ToByte(expectedUpperValue ?? 0, CultureInfo.InvariantCulture)),
            MemoryDataType.Int16 => MatchTyped(comparison, Convert.ToInt16(currentValue, CultureInfo.InvariantCulture), Convert.ToInt16(expectedValue ?? 0, CultureInfo.InvariantCulture), Convert.ToInt16(expectedUpperValue ?? 0, CultureInfo.InvariantCulture)),
            MemoryDataType.Int32 => MatchTyped(comparison, Convert.ToInt32(currentValue, CultureInfo.InvariantCulture), Convert.ToInt32(expectedValue ?? 0, CultureInfo.InvariantCulture), Convert.ToInt32(expectedUpperValue ?? 0, CultureInfo.InvariantCulture)),
            MemoryDataType.Int64 => MatchTyped(comparison, Convert.ToInt64(currentValue, CultureInfo.InvariantCulture), Convert.ToInt64(expectedValue ?? 0, CultureInfo.InvariantCulture), Convert.ToInt64(expectedUpperValue ?? 0, CultureInfo.InvariantCulture)),
            MemoryDataType.Float => MatchFloatLike(
                comparison,
                Convert.ToSingle(currentValue, CultureInfo.InvariantCulture),
                Convert.ToSingle(expectedValue ?? 0f, CultureInfo.InvariantCulture),
                Convert.ToSingle(expectedUpperValue ?? 0f, CultureInfo.InvariantCulture),
                expectedText,
                expectedUpperText),
            MemoryDataType.Double => MatchDoubleLike(
                comparison,
                Convert.ToDouble(currentValue, CultureInfo.InvariantCulture),
                Convert.ToDouble(expectedValue ?? 0d, CultureInfo.InvariantCulture),
                Convert.ToDouble(expectedUpperValue ?? 0d, CultureInfo.InvariantCulture),
                expectedText,
                expectedUpperText),
            MemoryDataType.String => MatchTyped(comparison, Convert.ToString(currentValue, CultureInfo.InvariantCulture) ?? string.Empty, Convert.ToString(expectedValue, CultureInfo.InvariantCulture) ?? string.Empty, Convert.ToString(expectedUpperValue, CultureInfo.InvariantCulture) ?? string.Empty),
            _ => false
        };
    }

    private static bool MatchFloatLike(
        ScanComparison comparison,
        float current,
        float expected,
        float expectedUpper,
        string? expectedText,
        string? expectedUpperText)
    {
        var tolerance = ResolveFloatingTolerance(expectedText);
        var upperTolerance = ResolveFloatingTolerance(expectedUpperText);
        return comparison switch
        {
            ScanComparison.Equal => FloatValuesEqual(current, expected, tolerance, expectedText),
            ScanComparison.NotEqual => !FloatValuesEqual(current, expected, tolerance, expectedText),
            ScanComparison.Greater => current > expected,
            ScanComparison.Less => current < expected,
            ScanComparison.Between => FloatWithinRange(current, expected, expectedUpper, tolerance, upperTolerance),
            _ => false
        };
    }

    private static bool MatchDoubleLike(
        ScanComparison comparison,
        double current,
        double expected,
        double expectedUpper,
        string? expectedText,
        string? expectedUpperText)
    {
        var tolerance = ResolveFloatingTolerance(expectedText);
        var upperTolerance = ResolveFloatingTolerance(expectedUpperText);
        return comparison switch
        {
            ScanComparison.Equal => DoubleValuesEqual(current, expected, tolerance, expectedText),
            ScanComparison.NotEqual => !DoubleValuesEqual(current, expected, tolerance, expectedText),
            ScanComparison.Greater => current > expected,
            ScanComparison.Less => current < expected,
            ScanComparison.Between => DoubleWithinRange(current, expected, expectedUpper, tolerance, upperTolerance),
            _ => false
        };
    }

    private static bool FloatValuesEqual(float current, float expected, double tolerance, string? expectedText)
    {
        if (ValueTextFormatter.Format(current) == ValueTextFormatter.Format(expected))
        {
            return true;
        }

        if (tolerance <= 0)
        {
            return current.Equals(expected);
        }

        return Math.Abs(current - expected) <= tolerance;
    }

    private static bool DoubleValuesEqual(double current, double expected, double tolerance, string? expectedText)
    {
        if (ValueTextFormatter.Format(current) == ValueTextFormatter.Format(expected))
        {
            return true;
        }

        if (tolerance <= 0)
        {
            return current.Equals(expected);
        }

        return Math.Abs(current - expected) <= tolerance;
    }

    private static bool FloatWithinRange(float current, float first, float second, double firstTolerance, double secondTolerance)
    {
        var low = Math.Min(first, second);
        var high = Math.Max(first, second);
        var rangeTolerance = Math.Max(firstTolerance, secondTolerance);
        return current >= low - rangeTolerance && current <= high + rangeTolerance;
    }

    private static bool DoubleWithinRange(double current, double first, double second, double firstTolerance, double secondTolerance)
    {
        var low = Math.Min(first, second);
        var high = Math.Max(first, second);
        var rangeTolerance = Math.Max(firstTolerance, secondTolerance);
        return current >= low - rangeTolerance && current <= high + rangeTolerance;
    }

    private static double ResolveFloatingTolerance(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return 0;
        }

        var trimmed = text.Trim();
        var separatorIndex = Math.Max(trimmed.LastIndexOf('.'), trimmed.LastIndexOf(','));
        if (separatorIndex < 0 || separatorIndex >= trimmed.Length - 1)
        {
            return 0;
        }

        var digits = 0;
        for (var index = separatorIndex + 1; index < trimmed.Length; index++)
        {
            if (!char.IsDigit(trimmed[index]))
            {
                break;
            }

            digits++;
        }

        if (digits <= 0)
        {
            return 0;
        }

        var precision = Math.Min(6, digits);
        return Math.Pow(10, -precision) / 2d;
    }

    private static int ComputeRulePriority(MemoryDataType dataType, ScanComparison comparison, string? valueText, string? valueToText)
    {
        var typeCost = dataType == MemoryDataType.String ? 20 : 0;
        return comparison switch
        {
            ScanComparison.Equal => typeCost,
            ScanComparison.NotEqual => typeCost + 5,
            ScanComparison.Greater => typeCost + 10,
            ScanComparison.Less => typeCost + 10,
            ScanComparison.Between => typeCost + 15 + ComputeRangeSpreadPenalty(dataType, valueText, valueToText),
            _ => typeCost + 50
        };
    }

    private static int ComputeRangeSpreadPenalty(MemoryDataType dataType, string? valueText, string? valueToText)
    {
        if (!ScanService.TryParseValue(dataType, valueText, out var lower) || !ScanService.TryParseValue(dataType, valueToText, out var upper))
        {
            return 100;
        }

        try
        {
            return dataType switch
            {
                MemoryDataType.Byte => Math.Min(100, Math.Abs((byte)lower - (byte)upper) / 4),
                MemoryDataType.Int16 => Math.Min(100, Math.Abs((short)lower - (short)upper) / 64),
                MemoryDataType.Int32 => Math.Min(100, Math.Abs((int)lower - (int)upper) / 2048),
                MemoryDataType.Int64 => Math.Min(100, (int)Math.Min(100, Math.Abs((long)lower - (long)upper) / 2048L)),
                MemoryDataType.Float => Math.Min(100, (int)(Math.Abs((float)lower - (float)upper) / 256f)),
                MemoryDataType.Double => Math.Min(100, (int)(Math.Abs((double)lower - (double)upper) / 256d)),
                _ => 100
            };
        }
        catch
        {
            return 100;
        }
    }

    private static bool MatchTyped<T>(ScanComparison comparison, T current, T expected, T expectedUpper)
        where T : IComparable<T>
    {
        return comparison switch
        {
            ScanComparison.Equal => current.CompareTo(expected) == 0,
            ScanComparison.NotEqual => current.CompareTo(expected) != 0,
            ScanComparison.Greater => current.CompareTo(expected) > 0,
            ScanComparison.Less => current.CompareTo(expected) < 0,
            ScanComparison.Between => IsBetween(current, expected, expectedUpper),
            _ => false
        };
    }

    private static bool IsBetween<T>(T current, T first, T second)
        where T : IComparable<T>
    {
        var low = first.CompareTo(second) <= 0 ? first : second;
        var high = first.CompareTo(second) <= 0 ? second : first;
        return current.CompareTo(low) >= 0 && current.CompareTo(high) <= 0;
    }

    private static string FormatSignedStep(int step)
    {
        return step >= 0 ? $"+{step}" : step.ToString(CultureInfo.InvariantCulture);
    }

    private static void ResolveDepth(ScanDepthProfile profile, out bool includePrivate, out bool includeImage, out bool scanUnaligned, out int stepMultiplier)
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

    private static List<PatternScanSlice> SliceRegions(IReadOnlyList<MemoryRegion> regions, ulong sliceSize)
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

    private static IReadOnlyList<PatternScanSlice> OrderSlices(
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

    private static ulong DistanceToAnchor(PatternScanSlice slice, ulong anchor)
    {
        var sliceMidpoint = slice.SliceStart + ((slice.SliceEnd - slice.SliceStart) / 2);
        return sliceMidpoint >= anchor
            ? sliceMidpoint - anchor
            : anchor - sliceMidpoint;
    }

    private static ulong ResolveOrderedSliceSize(PatternSearchFocus focus)
    {
        return focus switch
        {
            PatternSearchFocus.Coarse => SliceSize,
            PatternSearchFocus.Fine => OrderedFineSliceSize,
            _ => OrderedBalancedSliceSize
        };
    }

    private static int DetermineOrderedBatchWidth(
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
                PatternSearchFocus.Coarse => Math.Max(1, normalizedThreadCount / 2),
                PatternSearchFocus.Fine => 1,
                _ => Math.Min(2, normalizedThreadCount)
            };
        }

        return focus switch
        {
            PatternSearchFocus.Coarse => normalizedThreadCount,
            PatternSearchFocus.Fine => 1,
            _ => Math.Max(1, Math.Min(2, normalizedThreadCount))
        };
    }

    private static string BuildSearchOrderSummary(PatternGeneralRuleOptions options)
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
            PatternSearchFocus.Coarse => "Focus: Coarse",
            PatternSearchFocus.Fine => "Focus: Fine",
            _ => "Focus: Balanced"
        };

        return $"{orderText} | {focusText}";
    }

    private static string BuildOrderedProgressStatus(
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

    private static long CalculateTotalSteps(IReadOnlyList<PatternScanSlice> slices, int typeSize, int stepSize)
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

    private static void TryReportProgressThrottled(
        IProgress<ScanProgressInfo>? progress,
        object gate,
        ref long lastReportTicks,
        long processed,
        long total,
        string status)
    {
        var now = Stopwatch.GetTimestamp();
        var minDelta = Stopwatch.Frequency / 20;

        lock (gate)
        {
            if (lastReportTicks != 0 && now - lastReportTicks < minDelta)
            {
                return;
            }

            lastReportTicks = now;
        }

        progress?.Report(new ScanProgressInfo
        {
            Processed = processed,
            Total = total,
            StatusText = status
        });
    }

    private static int GetTypeNaturalAlignmentSize(MemoryDataType dataType, int stringByteLength)
    {
        return dataType switch
        {
            MemoryDataType.Byte => sizeof(byte),
            MemoryDataType.Int16 => sizeof(short),
            MemoryDataType.Int32 => sizeof(int),
            MemoryDataType.Int64 => sizeof(long),
            MemoryDataType.Float => sizeof(float),
            MemoryDataType.Double => sizeof(double),
            MemoryDataType.String => sizeof(byte),
            _ => sizeof(int)
        };
    }

    private static int GetTypeReadSize(MemoryDataType dataType, int stringByteLength)
    {
        return dataType switch
        {
            MemoryDataType.Byte => sizeof(byte),
            MemoryDataType.Int16 => sizeof(short),
            MemoryDataType.Int32 => sizeof(int),
            MemoryDataType.Int64 => sizeof(long),
            MemoryDataType.Float => sizeof(float),
            MemoryDataType.Double => sizeof(double),
            MemoryDataType.String => Math.Max(1, stringByteLength),
            _ => sizeof(int)
        };
    }

    private readonly record struct CompiledPatternRule(
        int RelativeStep,
        int ByteOffset,
        MemoryDataType DataType,
        ScanComparison Comparison,
        object? Value,
        object? ValueUpper,
        string ValueText,
        string ValueUpperText,
        int StringByteLength,
        int ReadSize,
        int OriginalIndex,
        int Priority);

    private readonly record struct CompiledStartCriterion(
        MemoryDataType DataType,
        string RawText,
        int StringByteLength,
        int ReadSize,
        object TypedValue);

    private readonly record struct PatternScanSlice(
        ulong RegionStart,
        ulong RegionEnd,
        ulong SliceStart,
        ulong SliceEnd);

    private readonly record struct SliceScanOutcome(
        List<AddressPatternScanResult> Rows,
        long ProcessedSteps,
        ulong ScannedBytes);

    private enum StrictGapStopReason
    {
        None,
        GapReached,
        ResultLimit
    }
}
