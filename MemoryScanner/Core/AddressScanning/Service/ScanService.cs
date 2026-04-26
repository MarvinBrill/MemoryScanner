using MemoryScanner.Models;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace MemoryScanner.Core;

public sealed partial class ScanService : IDisposable
{
    private const int InitialReadChunkSize = 256 * 1024;
    private const int MinReadChunkSize = 16 * 1024;
    private const int MaxReadChunkSize = 1024 * 1024;
    private const ulong RegionSliceSize = 8UL * 1024 * 1024;
    private const int CandidateFlushBatchSize = 128;
    private const int CandidateChunkSize = 64 * 1024;

    private readonly IMemoryAccessor _memory;
    private readonly MemoryRegionEnumerator _regionEnumerator;
    private readonly object _snapshotGate = new();
    private readonly EventHandler _processExitHandler;
    private string? _candidateSnapshotPath;
    private int _candidateCount;
    private bool _disposed;
    public int CandidateCount
    {
        get
        {
            lock (_snapshotGate)
            {
                return _candidateCount;
            }
        }
    }
    private delegate bool FirstScanMatcher(ReadOnlySpan<byte> span, int offset, out object value);
    private delegate bool NextScanMatcher(object current, object? previous);
    private delegate T SpanReader<T>(ReadOnlySpan<byte> span, int offset);

    public ScanService(IMemoryAccessor memory, MemoryRegionEnumerator regionEnumerator)
    {
        _memory = memory;
        _regionEnumerator = regionEnumerator;
        _processExitHandler = (_, _) => ClearCandidateSnapshot();
        AppDomain.CurrentDomain.ProcessExit += _processExitHandler;
        AppDomain.CurrentDomain.DomainUnload += _processExitHandler;
    }

    public IReadOnlyList<ScanResult> FirstScan(
        MemoryDataType dataType,
        ScanComparison comparison,
        string? valueText,
        string? valueTextTo,
        ScanExecutionOptions executionOptions,
        IProgress<ScanProgressInfo>? progress,
        CancellationToken cancellationToken)
    {
        if (_disposed)
        {
            return Array.Empty<ScanResult>();
        }

        ClearCandidateSnapshot();
        var results = new List<ScanResult>();
        if (!_memory.IsAttached) return results;
        if (dataType == MemoryDataType.String)
        {
            if (!IsStringFirstScanComparisonSupported(comparison))
            {
                return results;
            }
        }
        else if (!IsFirstScanComparisonSupported(comparison))
        {
            return results;
        }

        object? input = null;
        object? inputUpper = null;
        if (RequiresPrimaryInput(comparison) && !TryParseValue(dataType, valueText, out input))
        {
            return results;
        }

        if (RequiresSecondaryInput(comparison) && !TryParseValue(dataType, valueTextTo, out inputUpper))
        {
            return results;
        }

        var includeResultRows = comparison != ScanComparison.UnknownInitial;
        ResolveDepth(executionOptions.DepthProfile, out var includePrivate, out var includeImage, out var scanUnaligned, out var stepMultiplier);

        var typeSize = 0;
        var stepSize = 1;
        FirstScanMatcher? firstMatcher = null;
        byte[]? stringInputBytes = null;

        if (dataType == MemoryDataType.String)
        {
            stringInputBytes = Encoding.UTF8.GetBytes(Convert.ToString(input, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty);
            if (stringInputBytes.Length == 0)
            {
                return results;
            }

            typeSize = stringInputBytes.Length;
            stepSize = 1;
            firstMatcher = BuildStringFirstScanMatcher(comparison, stringInputBytes);
            if (firstMatcher is null)
            {
                return results;
            }
        }
        else
        {
            if (!TryCreateFirstScanMatcher(dataType, comparison, input, inputUpper, out var numericMatcher))
            {
                return results;
            }

            firstMatcher = numericMatcher;
            typeSize = GetTypeSize(dataType);
            stepSize = scanUnaligned ? 1 : Math.Max(1, typeSize * stepMultiplier);
        }

        var effectiveLimit = executionOptions.NormalizedResultLimit();
        var hasLimit = executionOptions.UseResultLimit;

        var regions = _regionEnumerator.Enumerate(_memory.Process, includePrivate, includeImage, executionOptions.IncludeMapped);
        var slices = SliceRegions(regions, RegionSliceSize);
        var totalSteps = CalculateTotalSteps(slices, typeSize, stepSize);
        ReportProgress(progress, 0, totalSteps, "Scanning memory");

        var gate = new object();
        long processed = 0;
        int limitReached = 0;
        var progressGate = new object();
        long lastProgressTicks = 0;
        using var snapshotWriter = CandidateSnapshotWriter.Create();

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = executionOptions.NormalizedThreadCount()
        };
        var matcher = firstMatcher!;

        try
        {
            Parallel.ForEach(slices, parallelOptions, () => new LocalCollector(), (slice, loopState, local) =>
            {
                if (cancellationToken.IsCancellationRequested || Volatile.Read(ref limitReached) == 1)
                {
                    loopState.Stop();
                    return local;
                }

                ulong cursor = slice.Start;
                int currentChunkSize = InitialReadChunkSize;
                while (cursor < slice.End)
                {
                    if (cancellationToken.IsCancellationRequested || Volatile.Read(ref limitReached) == 1)
                    {
                        loopState.Stop();
                        break;
                    }

                    ulong remaining = slice.End - cursor;
                    int primaryChunkSize = (int)Math.Min((ulong)currentChunkSize, remaining);
                    int readCount = primaryChunkSize + typeSize - 1;
                    if ((ulong)readCount > remaining)
                    {
                        readCount = (int)remaining;
                    }

                    if (!_memory.TryReadBytes(cursor, readCount, out var block) || block.Length < typeSize)
                    {
                        currentChunkSize = Math.Max(MinReadChunkSize, currentChunkSize / 2);
                        cursor += (ulong)Math.Max(MinReadChunkSize, primaryChunkSize);
                        continue;
                    }

                    var span = block.AsSpan();
                    int primaryCount = Math.Min(primaryChunkSize, block.Length);
                    int maxPosExclusive = Math.Min(primaryCount, span.Length - typeSize + 1);

                    for (int pos = 0; pos < maxPosExclusive; pos += stepSize)
                    {
                        if (cancellationToken.IsCancellationRequested || Volatile.Read(ref limitReached) == 1)
                        {
                            loopState.Stop();
                            break;
                        }

                        local.ProcessedCount++;
                        if ((local.ProcessedCount & 2047) == 0)
                        {
                            var done = Interlocked.Add(ref processed, 2048);
                            local.ProcessedCount -= 2048;
                            TryReportProgressThrottled(progress, progressGate, ref lastProgressTicks, done, totalSteps, "Scanning memory");
                        }

                        if (!matcher(span, pos, out var value))
                        {
                            continue;
                        }

                        ulong address = cursor + (ulong)pos;
                        if (dataType == MemoryDataType.String && stringInputBytes is not null)
                        {
                            local.AddMatch(address, value, dataType, includeResultRows, stringInputBytes.Length);
                        }
                        else
                        {
                            local.AddMatch(address, value, dataType, includeResultRows);
                        }

                        if (local.Candidates.Count >= CandidateFlushBatchSize)
                        {
                            FlushLocal(local, results, snapshotWriter, hasLimit, effectiveLimit, ref limitReached, gate, includeResultRows);
                            if (Volatile.Read(ref limitReached) == 1)
                            {
                                loopState.Stop();
                                break;
                            }
                        }
                    }

                    currentChunkSize = Math.Min(MaxReadChunkSize, currentChunkSize * 2);
                    cursor += (ulong)primaryCount;
                }

                return local;
            }, local =>
            {
                FlushLocal(local, results, snapshotWriter, hasLimit, effectiveLimit, ref limitReached, gate, includeResultRows);
                if (local.ProcessedCount > 0)
                {
                    var done = Interlocked.Add(ref processed, local.ProcessedCount);
                    TryReportProgressThrottled(progress, progressGate, ref lastProgressTicks, done, totalSteps, "Scanning memory");
                }
            });
        }
        catch (OperationCanceledException)
        {
        }
        catch (AggregateException ex) when (ex.Flatten().InnerExceptions.All(inner => inner is OperationCanceledException))
        {
        }

        var snapshotCommit = snapshotWriter.Commit();
        SetCandidateSnapshot(snapshotCommit.FilePath, snapshotCommit.Count);

        var finalStatus = cancellationToken.IsCancellationRequested ? "Scan canceled" : "Scan finished";
        ReportProgress(progress, Math.Min(processed, totalSteps), totalSteps, finalStatus);
        return results;
    }

    public IReadOnlyList<ScanResult> NextScan(
        MemoryDataType dataType,
        ScanComparison comparison,
        string? valueText,
        string? valueTextTo,
        ScanExecutionOptions executionOptions,
        IProgress<ScanProgressInfo>? progress,
        CancellationToken cancellationToken)
    {
        var results = new List<ScanResult>();
        if (_disposed || !_memory.IsAttached)
        {
            return results;
        }

        string? sourceSnapshotPath;
        int sourceCandidateCount;
        lock (_snapshotGate)
        {
            sourceSnapshotPath = _candidateSnapshotPath;
            sourceCandidateCount = _candidateCount;
        }

        if (sourceCandidateCount == 0 || string.IsNullOrWhiteSpace(sourceSnapshotPath))
        {
            return results;
        }

        object? input = null;
        object? inputUpper = null;
        if (dataType == MemoryDataType.String)
        {
            if (!IsStringNextScanComparisonSupported(comparison))
            {
                return results;
            }
        }
        else if (comparison == ScanComparison.UnknownInitial)
        {
            return results;
        }
        if (RequiresPrimaryInput(comparison) && !TryParseValue(dataType, valueText, out input))
        {
            return results;
        }
        if (RequiresSecondaryInput(comparison) && !TryParseValue(dataType, valueTextTo, out inputUpper))
        {
            return results;
        }
        var effectiveLimit = executionOptions.NormalizedResultLimit();
        var hasLimit = executionOptions.UseResultLimit;
        const bool includeResultRows = true;

        if (dataType == MemoryDataType.String)
        {
            return NextScanString(
                sourceSnapshotPath,
                sourceCandidateCount,
                comparison,
                input,
                effectiveLimit,
                hasLimit,
                executionOptions.NormalizedThreadCount(),
                progress,
                cancellationToken);
        }

        if (!TryCreateNextScanMatcher(dataType, comparison, input, inputUpper, out var matcher))
        {
            return results;
        }

        if (!File.Exists(sourceSnapshotPath))
        {
            ClearCandidateSnapshot();
            return results;
        }

        var total = Math.Max(1, sourceCandidateCount);
        ReportProgress(progress, 0, total, "Filtering previous results");

        var gate = new object();
        int limitReached = 0;
        long processed = 0;
        var progressGate = new object();
        long lastProgressTicks = 0;
        using var filteredSnapshotWriter = CandidateSnapshotWriter.Create();

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = executionOptions.NormalizedThreadCount()
        };

        try
        {
            foreach (var chunk in EnumerateCandidateChunks(sourceSnapshotPath, CandidateChunkSize, cancellationToken))
            {
                if (cancellationToken.IsCancellationRequested || Volatile.Read(ref limitReached) == 1)
                {
                    break;
                }

                Parallel.ForEach(chunk, parallelOptions, () => new LocalCollector(), (candidate, loopState, local) =>
                {
                    if (cancellationToken.IsCancellationRequested || Volatile.Read(ref limitReached) == 1)
                    {
                        loopState.Stop();
                        return local;
                    }

                    if (candidate.ValueType != dataType || candidate.ValueType == MemoryDataType.String)
                    {
                        local.ProcessedCount++;
                        if ((local.ProcessedCount & 1023) == 0)
                        {
                            var done = Interlocked.Add(ref processed, 1024);
                            local.ProcessedCount -= 1024;
                            TryReportProgressThrottled(progress, progressGate, ref lastProgressTicks, done, total, "Filtering previous results");
                        }

                        return local;
                    }

                    var previousValue = UnpackCandidateValue(in candidate);
                    if (_memory.TryReadValue(candidate.Address, dataType, out var newValue) && matcher(newValue, previousValue))
                    {
                        local.AddMatch(candidate.Address, newValue, dataType, includeResultRows);
                    }

                    local.ProcessedCount++;
                    if ((local.ProcessedCount & 1023) == 0)
                    {
                        var done = Interlocked.Add(ref processed, 1024);
                        local.ProcessedCount -= 1024;
                        TryReportProgressThrottled(progress, progressGate, ref lastProgressTicks, done, total, "Filtering previous results");
                    }

                    if (local.Candidates.Count >= CandidateFlushBatchSize)
                    {
                        FlushLocal(local, results, filteredSnapshotWriter, hasLimit, effectiveLimit, ref limitReached, gate, includeResultRows);
                        if (Volatile.Read(ref limitReached) == 1)
                        {
                            loopState.Stop();
                        }
                    }

                    return local;
                }, local =>
                {
                    FlushLocal(local, results, filteredSnapshotWriter, hasLimit, effectiveLimit, ref limitReached, gate, includeResultRows);
                    if (local.ProcessedCount > 0)
                    {
                        var done = Interlocked.Add(ref processed, local.ProcessedCount);
                        TryReportProgressThrottled(progress, progressGate, ref lastProgressTicks, done, total, "Filtering previous results");
                    }
                });
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (AggregateException ex) when (ex.Flatten().InnerExceptions.All(inner => inner is OperationCanceledException))
        {
        }

        var filteredCommit = filteredSnapshotWriter.Commit();
        SetCandidateSnapshot(filteredCommit.FilePath, filteredCommit.Count);

        var finalStatus = cancellationToken.IsCancellationRequested ? "Scan canceled" : "Scan finished";
        ReportProgress(progress, Math.Min(processed, total), total, finalStatus);
        return results;
    }

    private IReadOnlyList<ScanResult> NextScanString(
        string sourceSnapshotPath,
        int sourceCandidateCount,
        ScanComparison comparison,
        object? input,
        int effectiveLimit,
        bool hasLimit,
        int maxDegreeOfParallelism,
        IProgress<ScanProgressInfo>? progress,
        CancellationToken cancellationToken)
    {
        var results = new List<ScanResult>();

        if (!File.Exists(sourceSnapshotPath))
        {
            ClearCandidateSnapshot();
            return results;
        }

        var inputText = Convert.ToString(input, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
        var inputBytes = Encoding.UTF8.GetBytes(inputText);
        if (inputBytes.Length == 0)
        {
            return results;
        }

        var total = Math.Max(1, sourceCandidateCount);
        ReportProgress(progress, 0, total, "Filtering previous results");

        var gate = new object();
        int limitReached = 0;
        long processed = 0;
        var progressGate = new object();
        long lastProgressTicks = 0;
        using var filteredSnapshotWriter = CandidateSnapshotWriter.Create();

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = maxDegreeOfParallelism
        };

        try
        {
            foreach (var chunk in EnumerateCandidateChunks(sourceSnapshotPath, CandidateChunkSize, cancellationToken))
            {
                if (cancellationToken.IsCancellationRequested || Volatile.Read(ref limitReached) == 1)
                {
                    break;
                }

                Parallel.ForEach(chunk, parallelOptions, () => new LocalCollector(), (candidate, loopState, local) =>
                {
                    if (cancellationToken.IsCancellationRequested || Volatile.Read(ref limitReached) == 1)
                    {
                        loopState.Stop();
                        return local;
                    }

                    local.ProcessedCount++;
                    if ((local.ProcessedCount & 1023) == 0)
                    {
                        var done = Interlocked.Add(ref processed, 1024);
                        local.ProcessedCount -= 1024;
                        TryReportProgressThrottled(progress, progressGate, ref lastProgressTicks, done, total, "Filtering previous results");
                    }

                    if (candidate.ValueType != MemoryDataType.String)
                    {
                        return local;
                    }

                    var byteLength = NormalizeStringCandidateByteLength(candidate.RawValue);
                    if (byteLength <= 0)
                    {
                        return local;
                    }

                    if (!_memory.TryReadBytes(candidate.Address, byteLength, out var currentBytes) || currentBytes.Length < byteLength)
                    {
                        return local;
                    }

                    var isEqual = currentBytes.AsSpan(0, byteLength).SequenceEqual(inputBytes);
                    var keep = comparison switch
                    {
                        ScanComparison.Equal => isEqual,
                        ScanComparison.NotEqual => !isEqual,
                        _ => false
                    };

                    if (!keep)
                    {
                        return local;
                    }

                    var text = DecodeUtf8String(currentBytes.AsSpan(0, byteLength));
                    local.AddMatch(candidate.Address, text, MemoryDataType.String, includeResults: true, stringByteLength: byteLength);

                    if (local.Candidates.Count >= CandidateFlushBatchSize)
                    {
                        FlushLocal(local, results, filteredSnapshotWriter, hasLimit, effectiveLimit, ref limitReached, gate, includeResults: true);
                        if (Volatile.Read(ref limitReached) == 1)
                        {
                            loopState.Stop();
                        }
                    }

                    return local;
                }, local =>
                {
                    FlushLocal(local, results, filteredSnapshotWriter, hasLimit, effectiveLimit, ref limitReached, gate, includeResults: true);
                    if (local.ProcessedCount > 0)
                    {
                        var done = Interlocked.Add(ref processed, local.ProcessedCount);
                        TryReportProgressThrottled(progress, progressGate, ref lastProgressTicks, done, total, "Filtering previous results");
                    }
                });
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (AggregateException ex) when (ex.Flatten().InnerExceptions.All(inner => inner is OperationCanceledException))
        {
        }

        var filteredCommit = filteredSnapshotWriter.Commit();
        SetCandidateSnapshot(filteredCommit.FilePath, filteredCommit.Count);

        var finalStatus = cancellationToken.IsCancellationRequested ? "Scan canceled" : "Scan finished";
        ReportProgress(progress, Math.Min(processed, total), total, finalStatus);
        return results;
    }

    public void Reset()
    {
        ClearCandidateSnapshot();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        AppDomain.CurrentDomain.ProcessExit -= _processExitHandler;
        AppDomain.CurrentDomain.DomainUnload -= _processExitHandler;
        ClearCandidateSnapshot();
    }

}
