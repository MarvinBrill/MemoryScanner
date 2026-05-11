using MemoryScanner.Models;
using System.Buffers;

namespace MemoryScanner.Core;

public sealed class PatternScanService
{
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

        var startCriterion = PatternScanCompiler.CompileStartCriterion(request);
        var compiledRules = PatternScanCompiler.CompileRules(request);
        PatternScanPlanner.ResolveDepth(options.DepthProfile, out var includePrivate, out var includeImage, out var scanUnaligned, out var stepMultiplier);
        var requiresOrderedExecution = request.GeneralRules.SearchOrder != PatternSearchOrder.StartToEnd
            || (request.GeneralRules.StopAfterGapFromLastMatchEnabled && request.GeneralRules.MaxAddressesWithoutMatchAfterFirstHit > 0);

        var regions = _regionEnumerator.Enumerate(_memoryAccessor.Process, includePrivate, includeImage, options.IncludeMapped);
        var sliceSize = requiresOrderedExecution
            ? PatternScanPlanner.ResolveOrderedSliceSize(request.GeneralRules.SearchFocus)
            : 8UL * 1024UL * 1024UL;
        var addressOrderedSlices = PatternScanPlanner.SortSlicesByAddress(PatternScanPlanner.SliceRegions(regions, sliceSize));
        var slices = PatternScanPlanner.OrderSlices(
            addressOrderedSlices,
            request.GeneralRules.SearchOrder,
            request.GeneralRules.CustomSearchStartPercent);

        var startValueSize = PatternScanValueReader.GetTypeReadSize(request.StartDataType, request.StartStringByteLength);
        var startScanStepSize = scanUnaligned
            ? 1
            : Math.Max(1, PatternScanValueReader.GetTypeNaturalAlignmentSize(request.StartDataType, request.StartStringByteLength) * stepMultiplier);

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
                suffixOverlap,
                addressOrderedSlices);
        }

        var totalSteps = PatternScanPlanner.CalculateTotalSteps(slices, startValueSize, startScanStepSize);
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

        FinalizeRows(rows, limit, addressOrderedSlices);

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
        int suffixOverlap,
        IReadOnlyList<PatternScanSlice> addressOrderedSlices)
    {
        var totalSteps = PatternScanPlanner.CalculateTotalSteps(slices, startCriterion.ReadSize, startScanStepSize);
        var processedSteps = 0L;
        var limit = options.NormalizedResultLimit();
        var rows = new List<AddressPatternScanResult>();
        var stopAfterGapEnabled = request.GeneralRules.StopAfterGapFromLastMatchEnabled
            && request.GeneralRules.MaxAddressesWithoutMatchAfterFirstHit > 0;
        var orderSummary = PatternScanPlanner.BuildSearchOrderSummary(request.GeneralRules);
        var useStrictGapStop = stopAfterGapEnabled && request.GeneralRules.SearchFocus == PatternSearchFocus.Fine;

        if (useStrictGapStop)
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
                orderSummary,
                addressOrderedSlices);
        }

        var completedSlices = 0;
        var firstHitSlice = 0;
        var hasFirstHit = false;
        ulong scannedBytesSinceLastMatch = 0;
        var stopAfterGapReached = false;
        var maxGapBytes = checked((ulong)Math.Max(1, request.GeneralRules.MaxAddressesWithoutMatchAfterFirstHit) * (ulong)Math.Max(1, startScanStepSize));

        var normalizedThreadCount = Math.Max(1, options.NormalizedThreadCount());
        for (var batchStart = 0; batchStart < slices.Count && !cancellationToken.IsCancellationRequested;)
        {
            var batchWidth = PatternScanPlanner.DetermineOrderedBatchWidth(
                request.GeneralRules.SearchFocus,
                normalizedThreadCount,
                hasFirstHit,
                stopAfterGapEnabled);
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

                    hasFirstHit = true;
                    scannedBytesSinceLastMatch = 0;

                    if (rows.Count >= limit)
                    {
                        goto FinalizeOrderedScan;
                    }
                }
                else if (stopAfterGapEnabled && hasFirstHit)
                {
                    scannedBytesSinceLastMatch += outcome.ScannedBytes;
                }

                progress?.Report(new ScanProgressInfo
                {
                    Processed = processedSteps,
                    Total = totalSteps,
                    PhaseProcessed = completedSlices,
                    PhaseTotal = slices.Count,
                    StatusText = PatternScanPlanner.BuildOrderedProgressStatus(orderSummary, completedSlices, slices.Count, firstHitSlice, stopAfterGapEnabled)
                });

                if (stopAfterGapEnabled
                    && hasFirstHit
                    && scannedBytesSinceLastMatch > maxGapBytes)
                {
                    stopAfterGapReached = true;
                    goto FinalizeOrderedScan;
                }
            }

            batchStart += batchCount;
        }

FinalizeOrderedScan:
        FinalizeRows(rows, limit, addressOrderedSlices);

        progress?.Report(new ScanProgressInfo
        {
            Processed = totalSteps,
            Total = totalSteps,
            PhaseProcessed = slices.Count,
            PhaseTotal = slices.Count,
            StatusText = cancellationToken.IsCancellationRequested
                ? $"Pattern scan canceled | {orderSummary} | Results {rows.Count}"
                : stopAfterGapReached
                    ? $"Pattern scan stopped after gap | {orderSummary} | Results {rows.Count}"
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
        string orderSummary,
        IReadOnlyList<PatternScanSlice> addressOrderedSlices)
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
                StatusText = PatternScanPlanner.BuildOrderedProgressStatus(orderSummary, completedSlices, slices.Count, firstHitSlice, true)
            });
        }

        FinalizeRows(rows, limit, addressOrderedSlices);

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

            if (!TryReadChunk(slice, chunkStart, prefixOverlap, suffixOverlap, out var chunk))
            {
                continue;
            }

            try
            {
                var candidateMaxExclusive = ResolveCandidateMaxExclusive(chunk.MainEndExclusive, startCriterion.ReadSize, chunk.ChunkStart);

                for (ulong candidateAddress = chunk.ChunkStart;
                     candidateAddress < candidateMaxExclusive && Volatile.Read(ref stopRequested) == 0;
                     candidateAddress += (ulong)startScanStepSize)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (!TryCreateMatchResult(
                            candidateAddress,
                            chunk.ReadStart,
                            chunk.Buffer,
                            slice.RegionStart,
                            slice.RegionEnd,
                            startCriterion,
                            compiledRules,
                            out var result))
                    {
                        Interlocked.Increment(ref processedSteps);
                        continue;
                    }

                    localRows.Add(result);

                    if (Interlocked.Increment(ref resultCount) >= limit)
                    {
                        Volatile.Write(ref stopRequested, 1);
                    }

                    var processed = Interlocked.Increment(ref processedSteps);
                    PatternScanProgressReporter.TryReportProgressThrottled(progress, progressGate, ref lastReportTicks, processed, totalSteps, "Pattern scan running...");
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(chunk.Buffer);
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

            if (!TryReadChunk(slice, chunkStart, prefixOverlap, suffixOverlap, out var chunk))
            {
                continue;
            }

            try
            {
                var candidateMaxExclusive = ResolveCandidateMaxExclusive(chunk.MainEndExclusive, startCriterion.ReadSize, chunk.ChunkStart);

                for (ulong candidateAddress = chunk.ChunkStart; candidateAddress < candidateMaxExclusive; candidateAddress += (ulong)startScanStepSize)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (!TryCreateMatchResult(
                            candidateAddress,
                            chunk.ReadStart,
                            chunk.Buffer,
                            slice.RegionStart,
                            slice.RegionEnd,
                            startCriterion,
                            compiledRules,
                            out var result))
                    {
                        processedSteps++;
                        continue;
                    }

                    rows.Add(result);

                    processedSteps++;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(chunk.Buffer);
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

            if (!TryReadChunk(slice, chunkStart, prefixOverlap, suffixOverlap, out var chunk))
            {
                var skipped = PatternScanValueReader.CountSkippedSteps(chunkStart, Math.Min(slice.SliceEnd, chunkStart + (ulong)ReadChunkSize), startCriterion.ReadSize, startScanStepSize);
                processedSteps += skipped;
                if (hasFirstHit)
                {
                    consecutiveMisses += checked((int)Math.Min(int.MaxValue, skipped));
                    if (consecutiveMisses >= gapLimit)
                    {
                        return StrictGapStopReason.GapReached;
                    }
                }

                PatternScanProgressReporter.TryReportProgressThrottled(
                    progress,
                    progressGate,
                    ref lastReportTicks,
                    processedSteps,
                    totalSteps,
                    PatternScanPlanner.BuildOrderedProgressStatus(orderSummary, currentSliceNumber, totalSlices, firstHitSlice, true));
                continue;
            }

            try
            {
                var candidateMaxExclusive = ResolveCandidateMaxExclusive(chunk.MainEndExclusive, startCriterion.ReadSize, chunk.ChunkStart);

                for (ulong candidateAddress = chunk.ChunkStart; candidateAddress < candidateMaxExclusive; candidateAddress += (ulong)startScanStepSize)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var isMatch = false;
                    if (TryCreateMatchResult(
                            candidateAddress,
                            chunk.ReadStart,
                            chunk.Buffer,
                            slice.RegionStart,
                            slice.RegionEnd,
                            startCriterion,
                            compiledRules,
                            out var result))
                    {
                        rows.Add(result);

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
                    PatternScanProgressReporter.TryReportProgressThrottled(
                        progress,
                        progressGate,
                        ref lastReportTicks,
                        processedSteps,
                        totalSteps,
                        PatternScanPlanner.BuildOrderedProgressStatus(orderSummary, currentSliceNumber, totalSlices, firstHitSlice, true));
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(chunk.Buffer);
            }
        }

        return StrictGapStopReason.None;
    }

    private static AddressPatternScanResult CreateResult(
        ulong address,
        string valueText,
        CompiledStartCriterion startCriterion,
        string previewText)
    {
        return new AddressPatternScanResult
        {
            Address = address,
            ValueText = valueText,
            DataType = startCriterion.DataType,
            StringByteLength = startCriterion.StringByteLength,
            PreviewText = previewText
        };
    }

    private bool TryReadChunk(
        PatternScanSlice slice,
        ulong chunkStart,
        int prefixOverlap,
        int suffixOverlap,
        out PatternChunk chunk)
    {
        chunk = default;

        var mainEndExclusive = Math.Min(slice.SliceEnd, chunkStart + (ulong)ReadChunkSize);
        if (mainEndExclusive <= chunkStart)
        {
            return false;
        }

        var readStart = chunkStart >= (ulong)prefixOverlap
            ? Math.Max(slice.RegionStart, chunkStart - (ulong)prefixOverlap)
            : slice.RegionStart;
        var readEndExclusive = Math.Min(slice.RegionEnd, mainEndExclusive + (ulong)suffixOverlap);
        if (readEndExclusive <= readStart)
        {
            return false;
        }

        var bytesToRead = checked((int)(readEndExclusive - readStart));
        var buffer = ArrayPool<byte>.Shared.Rent(bytesToRead);
        if (_memoryAccessor.TryReadBytes(readStart, buffer, bytesToRead, out var bytesRead) && bytesRead >= bytesToRead)
        {
            chunk = new PatternChunk(chunkStart, mainEndExclusive, readStart, buffer);
            return true;
        }

        ArrayPool<byte>.Shared.Return(buffer);
        return false;
    }

    private static ulong ResolveCandidateMaxExclusive(ulong mainEndExclusive, int readSize, ulong chunkStart)
    {
        return mainEndExclusive >= (ulong)readSize
            ? mainEndExclusive - (ulong)readSize + 1
            : chunkStart;
    }

    private static bool TryCreateMatchResult(
        ulong candidateAddress,
        ulong readStart,
        byte[] buffer,
        ulong regionStart,
        ulong regionEnd,
        CompiledStartCriterion startCriterion,
        IReadOnlyList<CompiledPatternRule> compiledRules,
        out AddressPatternScanResult result)
    {
        result = default!;
        var candidateIndex = checked((int)(candidateAddress - readStart));
        if (!PatternScanValueReader.TryMatchStartValue(buffer.AsSpan(candidateIndex), startCriterion, out var startValueText))
        {
            return false;
        }

        if (!PatternScanMatcher.TryEvaluatePattern(candidateAddress, readStart, buffer, regionStart, regionEnd, compiledRules, out var previewText))
        {
            return false;
        }

        result = CreateResult(candidateAddress, startValueText, startCriterion, previewText);
        return true;
    }

    private static void FinalizeRows(
        List<AddressPatternScanResult> rows,
        int limit,
        IReadOnlyList<PatternScanSlice> addressOrderedSlices)
    {
        rows.Sort((left, right) => left.Address.CompareTo(right.Address));
        if (rows.Count > limit)
        {
            rows.RemoveRange(limit, rows.Count - limit);
        }

        foreach (var row in rows)
        {
            row.GlobalAddressPercent = PatternScanPlanner.CalculateAddressPercent(addressOrderedSlices, row.Address);
        }
    }
}
