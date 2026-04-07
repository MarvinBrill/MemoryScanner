using MemoryScanner.Models;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;

namespace MemoryScanner.Core;

public sealed class ScanService : IDisposable
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
        if (!IsFirstScanComparisonSupported(comparison)) return results;

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
        if (!TryCreateFirstScanMatcher(dataType, comparison, input, inputUpper, out var firstMatcher))
        {
            return results;
        }

        ResolveDepth(executionOptions.DepthProfile, out var includePrivate, out var includeImage, out var scanUnaligned, out var stepMultiplier);
        var typeSize = GetTypeSize(dataType);
        var stepSize = scanUnaligned ? 1 : Math.Max(1, typeSize * stepMultiplier);
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

                        if (!firstMatcher(span, pos, out var value))
                        {
                            continue;
                        }

                        ulong address = cursor + (ulong)pos;
                        local.AddMatch(address, value, dataType, includeResultRows);

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
        if (comparison == ScanComparison.UnknownInitial)
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

    public static bool TryParseValue(MemoryDataType dataType, string? text, out object value)
    {
        value = 0;
        if (string.IsNullOrWhiteSpace(text)) return false;
        var trimmed = text.Trim();

        return dataType switch
        {
            MemoryDataType.Byte => byte.TryParse(trimmed, out var b) ? Assign(b, out value) : false,
            MemoryDataType.Int16 => short.TryParse(trimmed, out var s16) ? Assign(s16, out value) : false,
            MemoryDataType.Int32 => int.TryParse(trimmed, out var i) ? Assign(i, out value) : false,
            MemoryDataType.Int64 => long.TryParse(trimmed, out var l) ? Assign(l, out value) : false,
            MemoryDataType.Float => float.TryParse(trimmed, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var f) ? Assign(f, out value) : false,
            MemoryDataType.Double => double.TryParse(trimmed, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var d) ? Assign(d, out value) : false,
            _ => false
        };
    }

    private static bool Assign<T>(T data, out object value)
    {
        value = data!;
        return true;
    }

    private void ClearCandidateSnapshot()
    {
        string? pathToDelete;
        lock (_snapshotGate)
        {
            pathToDelete = _candidateSnapshotPath;
            _candidateSnapshotPath = null;
            _candidateCount = 0;
        }

        if (!string.IsNullOrWhiteSpace(pathToDelete))
        {
            TryDeleteFile(pathToDelete);
        }
    }

    private void SetCandidateSnapshot(string filePath, int count)
    {
        string? oldPath;
        lock (_snapshotGate)
        {
            oldPath = _candidateSnapshotPath;

            if (_disposed || count <= 0)
            {
                _candidateSnapshotPath = null;
                _candidateCount = 0;

                if (!string.IsNullOrWhiteSpace(filePath))
                {
                    TryDeleteFile(filePath);
                }

                if (!string.IsNullOrWhiteSpace(oldPath) && !string.Equals(oldPath, filePath, StringComparison.OrdinalIgnoreCase))
                {
                    TryDeleteFile(oldPath);
                }

                return;
            }

            _candidateSnapshotPath = filePath;
            _candidateCount = count;
        }

        if (!string.IsNullOrWhiteSpace(oldPath) && !string.Equals(oldPath, filePath, StringComparison.OrdinalIgnoreCase))
        {
            TryDeleteFile(oldPath);
        }
    }

    private static void TryDeleteFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
        }
    }

    private static IEnumerable<ScanCandidate[]> EnumerateCandidateChunks(string snapshotPath, int chunkSize, CancellationToken cancellationToken)
    {
        using var stream = new FileStream(snapshotPath, FileMode.Open, FileAccess.Read, FileShare.Read, 256 * 1024, FileOptions.SequentialScan);
        using var reader = new BinaryReader(stream);

        while (stream.Position + CandidateSnapshotWriter.RecordSize <= stream.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var chunk = new ScanCandidate[chunkSize];
            int count = 0;
            while (count < chunkSize && stream.Position + CandidateSnapshotWriter.RecordSize <= stream.Length)
            {
                var address = reader.ReadUInt64();
                var rawValue = reader.ReadUInt64();
                var valueType = (MemoryDataType)reader.ReadByte();
                chunk[count++] = new ScanCandidate(address, rawValue, valueType);
            }

            if (count == 0)
            {
                yield break;
            }

            if (count == chunk.Length)
            {
                yield return chunk;
            }
            else
            {
                var trimmed = new ScanCandidate[count];
                Array.Copy(chunk, trimmed, count);
                yield return trimmed;
            }
        }
    }

    private static ulong PackCandidateValue(object value, MemoryDataType type)
    {
        return type switch
        {
            MemoryDataType.Byte => Convert.ToByte(value),
            MemoryDataType.Int16 => unchecked((ulong)(ushort)Convert.ToInt16(value)),
            MemoryDataType.Int32 => unchecked((ulong)(uint)Convert.ToInt32(value)),
            MemoryDataType.Int64 => unchecked((ulong)Convert.ToInt64(value)),
            MemoryDataType.Float => unchecked((ulong)(uint)BitConverter.SingleToInt32Bits(Convert.ToSingle(value))),
            MemoryDataType.Double => unchecked((ulong)BitConverter.DoubleToInt64Bits(Convert.ToDouble(value))),
            _ => 0UL
        };
    }

    private static object UnpackCandidateValue(in ScanCandidate candidate)
    {
        return candidate.ValueType switch
        {
            MemoryDataType.Byte => (byte)(candidate.RawValue & 0xFF),
            MemoryDataType.Int16 => unchecked((short)(candidate.RawValue & 0xFFFF)),
            MemoryDataType.Int32 => unchecked((int)(candidate.RawValue & 0xFFFFFFFF)),
            MemoryDataType.Int64 => unchecked((long)candidate.RawValue),
            MemoryDataType.Float => BitConverter.Int32BitsToSingle(unchecked((int)(candidate.RawValue & 0xFFFFFFFF))),
            MemoryDataType.Double => BitConverter.Int64BitsToDouble(unchecked((long)candidate.RawValue)),
            _ => 0
        };
    }

    private static void FlushLocal(
        LocalCollector local,
        List<ScanResult> globalResults,
        CandidateSnapshotWriter snapshotWriter,
        bool hasLimit,
        int effectiveLimit,
        ref int limitReached,
        object gate,
        bool includeResults)
    {
        if (local.Results.Count == 0 && local.Candidates.Count == 0)
        {
            return;
        }

        lock (gate)
        {
            if (!hasLimit)
            {
                if (includeResults)
                {
                    globalResults.AddRange(local.Results);
                }

                snapshotWriter.AddRange(local.Candidates, local.Candidates.Count);
            }
            else
            {
                int remaining = effectiveLimit - snapshotWriter.Count;
                if (remaining > 0)
                {
                    int toCopy = Math.Min(remaining, local.Candidates.Count);
                    for (int i = 0; i < toCopy; i++)
                    {
                        if (includeResults)
                        {
                            globalResults.Add(local.Results[i]);
                        }

                        snapshotWriter.Add(local.Candidates[i]);
                    }
                }

                if (snapshotWriter.Count >= effectiveLimit)
                {
                    Volatile.Write(ref limitReached, 1);
                }
            }
        }

        local.Results.Clear();
        local.Candidates.Clear();
    }

    private static bool TryCreateFirstScanMatcher(
        MemoryDataType type,
        ScanComparison comparison,
        object? input,
        object? inputUpper,
        out FirstScanMatcher matcher)
    {
        switch (type)
        {
            case MemoryDataType.Byte:
                return BuildFirstScanMatcher<byte>(comparison, input, inputUpper, (span, offset) => span[offset], TryCoerce, out matcher);
            case MemoryDataType.Int16:
                return BuildFirstScanMatcher<short>(comparison, input, inputUpper,
                    (span, offset) => BinaryPrimitives.ReadInt16LittleEndian(span.Slice(offset, sizeof(short))),
                    TryCoerce,
                    out matcher);
            case MemoryDataType.Int32:
                return BuildFirstScanMatcher<int>(comparison, input, inputUpper,
                    (span, offset) => BinaryPrimitives.ReadInt32LittleEndian(span.Slice(offset, sizeof(int))),
                    TryCoerce,
                    out matcher);
            case MemoryDataType.Int64:
                return BuildFirstScanMatcher<long>(comparison, input, inputUpper,
                    (span, offset) => BinaryPrimitives.ReadInt64LittleEndian(span.Slice(offset, sizeof(long))),
                    TryCoerce,
                    out matcher);
            case MemoryDataType.Float:
                return BuildFirstScanMatcher<float>(comparison, input, inputUpper,
                    (span, offset) => BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(span.Slice(offset, sizeof(int)))),
                    TryCoerce,
                    out matcher);
            case MemoryDataType.Double:
                return BuildFirstScanMatcher<double>(comparison, input, inputUpper,
                    (span, offset) => BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(span.Slice(offset, sizeof(long)))),
                    TryCoerce,
                    out matcher);
            default:
                matcher = (ReadOnlySpan<byte> span, int offset, out object value) =>
                {
                    value = 0;
                    return false;
                };
                return false;
        }
    }

    private static bool BuildFirstScanMatcher<T>(
        ScanComparison comparison,
        object? input,
        object? inputUpper,
        SpanReader<T> reader,
        CoerceFunc<T> coerce,
        out FirstScanMatcher matcher)
        where T : struct, IComparable<T>
    {
        matcher = (ReadOnlySpan<byte> span, int offset, out object value) =>
        {
            value = default(T);
            return false;
        };

        T inputValue = default;
        bool hasInput = false;
        if (RequiresPrimaryInput(comparison))
        {
            if (input is null || !coerce(input, out inputValue))
            {
                return false;
            }

            hasInput = true;
        }

        T inputUpperValue = default;
        bool hasInputUpper = false;
        if (RequiresSecondaryInput(comparison))
        {
            if (inputUpper is null || !coerce(inputUpper, out inputUpperValue))
            {
                return false;
            }

            hasInputUpper = true;
        }

        matcher = (ReadOnlySpan<byte> span, int offset, out object value) =>
        {
            var current = reader(span, offset);
            if (!MatchFirstTyped(comparison, current, inputValue, inputUpperValue, hasInput, hasInputUpper))
            {
                value = default(T);
                return false;
            }

            value = current;
            return true;
        };

        return true;
    }

    private static bool MatchFirstTyped<T>(
        ScanComparison comparison,
        T current,
        T input,
        T inputUpper,
        bool hasInput,
        bool hasInputUpper)
        where T : struct, IComparable<T>
    {
        return comparison switch
        {
            ScanComparison.UnknownInitial => true,
            ScanComparison.Equal => hasInput && current.CompareTo(input) == 0,
            ScanComparison.NotEqual => hasInput && current.CompareTo(input) != 0,
            ScanComparison.Greater => hasInput && current.CompareTo(input) > 0,
            ScanComparison.Less => hasInput && current.CompareTo(input) < 0,
            ScanComparison.Between => hasInput && hasInputUpper && IsWithinRange(current, input, inputUpper),
            _ => false
        };
    }

    private delegate bool CoerceFunc<T>(object value, out T result);

    private static bool TryCreateNextScanMatcher(
        MemoryDataType dataType,
        ScanComparison comparison,
        object? input,
        object? inputUpper,
        out NextScanMatcher matcher)
    {
        switch (dataType)
        {
            case MemoryDataType.Byte:
                matcher = CreateNextMatcher<byte>(comparison, input, inputUpper, TryCoerce);
                return true;
            case MemoryDataType.Int16:
                matcher = CreateNextMatcher<short>(comparison, input, inputUpper, TryCoerce);
                return true;
            case MemoryDataType.Int32:
                matcher = CreateNextMatcher<int>(comparison, input, inputUpper, TryCoerce);
                return true;
            case MemoryDataType.Int64:
                matcher = CreateNextMatcher<long>(comparison, input, inputUpper, TryCoerce);
                return true;
            case MemoryDataType.Float:
                matcher = CreateNextMatcher<float>(comparison, input, inputUpper, TryCoerce);
                return true;
            case MemoryDataType.Double:
                matcher = CreateNextMatcher<double>(comparison, input, inputUpper, TryCoerce);
                return true;
            default:
                matcher = (_, _) => false;
                return false;
        }
    }

    private static NextScanMatcher CreateNextMatcher<T>(
        ScanComparison comparison,
        object? input,
        object? inputUpper,
        CoerceFunc<T> coerce)
        where T : struct, IComparable<T>
    {
        T inputValue = default;
        var hasInput = input is not null && coerce(input, out inputValue);

        T inputUpperValue = default;
        var hasInputUpper = inputUpper is not null && coerce(inputUpper, out inputUpperValue);

        return (current, previous) =>
        {
            if (!coerce(current, out T currentValue))
            {
                return false;
            }

            T previousValue = default;
            var hasPrevious = previous is not null && coerce(previous, out previousValue);
            return MatchTyped(comparison, currentValue, inputValue, inputUpperValue, previousValue, hasInput, hasInputUpper, hasPrevious);
        };
    }
    private static bool TryCoerce(object value, out byte result)
    {
        result = 0;
        return value switch
        {
            byte b => AssignTry(b, out result),
            sbyte sb when sb >= byte.MinValue => AssignTry((byte)sb, out result),
            short s when s >= byte.MinValue && s <= byte.MaxValue => AssignTry((byte)s, out result),
            ushort us when us <= byte.MaxValue => AssignTry((byte)us, out result),
            int i when i >= byte.MinValue && i <= byte.MaxValue => AssignTry((byte)i, out result),
            uint ui when ui <= byte.MaxValue => AssignTry((byte)ui, out result),
            long l when l >= byte.MinValue && l <= byte.MaxValue => AssignTry((byte)l, out result),
            ulong ul when ul <= byte.MaxValue => AssignTry((byte)ul, out result),
            float f when f >= byte.MinValue && f <= byte.MaxValue && f % 1 == 0 => AssignTry((byte)f, out result),
            double d when d >= byte.MinValue && d <= byte.MaxValue && d % 1 == 0 => AssignTry((byte)d, out result),
            _ => false
        };
    }

    private static bool TryCoerce(object value, out short result)
    {
        result = 0;
        return value switch
        {
            short s => AssignTry(s, out result),
            byte b => AssignTry((short)b, out result),
            sbyte sb => AssignTry((short)sb, out result),
            ushort us when us <= short.MaxValue => AssignTry((short)us, out result),
            int i when i >= short.MinValue && i <= short.MaxValue => AssignTry((short)i, out result),
            uint ui when ui <= short.MaxValue => AssignTry((short)ui, out result),
            long l when l >= short.MinValue && l <= short.MaxValue => AssignTry((short)l, out result),
            ulong ul when ul <= (ulong)short.MaxValue => AssignTry((short)ul, out result),
            float f when f >= short.MinValue && f <= short.MaxValue && f % 1 == 0 => AssignTry((short)f, out result),
            double d when d >= short.MinValue && d <= short.MaxValue && d % 1 == 0 => AssignTry((short)d, out result),
            _ => false
        };
    }
    private static bool TryCoerce(object value, out int result)
    {
        result = 0;
        return value switch
        {
            int i => AssignTry(i, out result),
            byte b => AssignTry(b, out result),
            sbyte sb => AssignTry(sb, out result),
            short s => AssignTry(s, out result),
            ushort us => AssignTry(us, out result),
            long l when l >= int.MinValue && l <= int.MaxValue => AssignTry((int)l, out result),
            uint ui when ui <= int.MaxValue => AssignTry((int)ui, out result),
            ulong ul when ul <= int.MaxValue => AssignTry((int)ul, out result),
            float f when f >= int.MinValue && f <= int.MaxValue && f % 1 == 0 => AssignTry((int)f, out result),
            double d when d >= int.MinValue && d <= int.MaxValue && d % 1 == 0 => AssignTry((int)d, out result),
            _ => false
        };
    }

    private static bool TryCoerce(object value, out long result)
    {
        result = 0;
        return value switch
        {
            long l => AssignTry(l, out result),
            int i => AssignTry(i, out result),
            byte b => AssignTry(b, out result),
            sbyte sb => AssignTry(sb, out result),
            short s => AssignTry(s, out result),
            ushort us => AssignTry(us, out result),
            uint ui => AssignTry(ui, out result),
            ulong ul when ul <= long.MaxValue => AssignTry((long)ul, out result),
            float f when f >= long.MinValue && f <= long.MaxValue && f % 1 == 0 => AssignTry((long)f, out result),
            double d when d >= long.MinValue && d <= long.MaxValue && d % 1 == 0 => AssignTry((long)d, out result),
            _ => false
        };
    }

    private static bool TryCoerce(object value, out float result)
    {
        result = 0;
        return value switch
        {
            float f => AssignTry(f, out result),
            double d when d >= -float.MaxValue && d <= float.MaxValue => AssignTry((float)d, out result),
            int i => AssignTry(i, out result),
            long l => AssignTry(l, out result),
            byte b => AssignTry(b, out result),
            sbyte sb => AssignTry(sb, out result),
            short s => AssignTry(s, out result),
            ushort us => AssignTry(us, out result),
            uint ui => AssignTry(ui, out result),
            ulong ul => AssignTry(ul, out result),
            _ => false
        };
    }

    private static bool TryCoerce(object value, out double result)
    {
        result = 0;
        return value switch
        {
            double d => AssignTry(d, out result),
            float f => AssignTry(f, out result),
            int i => AssignTry(i, out result),
            long l => AssignTry(l, out result),
            byte b => AssignTry(b, out result),
            sbyte sb => AssignTry(sb, out result),
            short s => AssignTry(s, out result),
            ushort us => AssignTry(us, out result),
            uint ui => AssignTry(ui, out result),
            ulong ul => AssignTry(ul, out result),
            _ => false
        };
    }

    private static bool AssignTry<T>(T value, out T result)
    {
        result = value;
        return true;
    }
    private static bool MatchTyped<T>(
        ScanComparison comparison,
        T current,
        T input,
        T inputUpper,
        T previous,
        bool hasInput,
        bool hasInputUpper,
        bool hasPrevious)
        where T : struct, IComparable<T>
    {
        return comparison switch
        {
            ScanComparison.Equal => hasInput && current.CompareTo(input) == 0,
            ScanComparison.NotEqual => hasInput && current.CompareTo(input) != 0,
            ScanComparison.Greater => hasInput && current.CompareTo(input) > 0,
            ScanComparison.Less => hasInput && current.CompareTo(input) < 0,
            ScanComparison.Between => hasInput && hasInputUpper && IsWithinRange(current, input, inputUpper),
            ScanComparison.Increased => hasPrevious && current.CompareTo(previous) > 0,
            ScanComparison.Decreased => hasPrevious && current.CompareTo(previous) < 0,
            ScanComparison.Changed => hasPrevious && current.CompareTo(previous) != 0,
            ScanComparison.Unchanged => hasPrevious && current.CompareTo(previous) == 0,
            _ => false
        };
    }

    private static bool IsWithinRange<T>(T current, T boundaryA, T boundaryB)
        where T : struct, IComparable<T>
    {
        var order = boundaryA.CompareTo(boundaryB);
        var low = order <= 0 ? boundaryA : boundaryB;
        var high = order <= 0 ? boundaryB : boundaryA;

        return current.CompareTo(low) >= 0 && current.CompareTo(high) <= 0;
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

    private static long CalculateTotalSteps(IReadOnlyList<ScanSlice> slices, int typeSize, int stepSize)
    {
        long total = 0;
        foreach (var slice in slices)
        {
            var size = (long)(slice.End - slice.Start);
            var span = Math.Max(0L, size - typeSize + 1);
            if (span <= 0)
            {
                continue;
            }

            total += Math.Max(1, span / stepSize);
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
    private static int GetTypeSize(MemoryDataType dataType) => dataType switch
    {
        MemoryDataType.Byte => sizeof(byte),
        MemoryDataType.Int16 => sizeof(short),
        MemoryDataType.Int32 => sizeof(int),
        MemoryDataType.Int64 => sizeof(long),
        MemoryDataType.Float => sizeof(float),
        MemoryDataType.Double => sizeof(double),
        _ => sizeof(int)
    };

    private static bool RequiresPrimaryInput(ScanComparison comparison)
    {
        return comparison is ScanComparison.Equal
            or ScanComparison.NotEqual
            or ScanComparison.Greater
            or ScanComparison.Less
            or ScanComparison.Between;
    }

    private static bool RequiresSecondaryInput(ScanComparison comparison)
    {
        return comparison == ScanComparison.Between;
    }

    private static bool IsFirstScanComparisonSupported(ScanComparison comparison)
    {
        return comparison is ScanComparison.UnknownInitial
            or ScanComparison.Equal
            or ScanComparison.NotEqual
            or ScanComparison.Greater
            or ScanComparison.Less
            or ScanComparison.Between;
    }
    private static string FormatValue(object value)
    {
        return value switch
        {
            float f => f.ToString("0.######", System.Globalization.CultureInfo.InvariantCulture),
            double d => d.ToString("0.######", System.Globalization.CultureInfo.InvariantCulture),
            _ => Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty
        };
    }

    private readonly record struct ScanCandidate(ulong Address, ulong RawValue, MemoryDataType ValueType);

    private sealed class LocalCollector
    {
        public List<ScanResult> Results { get; } = new(CandidateFlushBatchSize);
        public List<ScanCandidate> Candidates { get; } = new(CandidateFlushBatchSize);
        public long ProcessedCount { get; set; }

        public void AddMatch(ulong address, object value, MemoryDataType type, bool includeResults)
        {
            if (includeResults)
            {
                Results.Add(new ScanResult
                {
                    Address = address,
                    DataType = type,
                    ValueText = FormatValue(value)
                });
            }

            Candidates.Add(new ScanCandidate(address, PackCandidateValue(value, type), type));
        }
    }

    private sealed class CandidateSnapshotWriter : IDisposable
    {
        public const int RecordSize = sizeof(ulong) + sizeof(ulong) + sizeof(byte);

        private readonly FileStream _stream;
        private readonly BinaryWriter _writer;
        private bool _committed;

        public string FilePath { get; }
        public int Count { get; private set; }

        private CandidateSnapshotWriter(string filePath)
        {
            FilePath = filePath;
            _stream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None, 256 * 1024, FileOptions.SequentialScan);
            _writer = new BinaryWriter(_stream);
        }

        public static CandidateSnapshotWriter Create()
        {
            var path = Path.Combine(Path.GetTempPath(), $"MemoryScanner_scan_{Guid.NewGuid():N}.bin");
            return new CandidateSnapshotWriter(path);
        }

        public void Add(in ScanCandidate candidate)
        {
            _writer.Write(candidate.Address);
            _writer.Write(candidate.RawValue);
            _writer.Write((byte)candidate.ValueType);
            Count++;
        }

        public void AddRange(List<ScanCandidate> candidates, int count)
        {
            for (int i = 0; i < count; i++)
            {
                Add(candidates[i]);
            }
        }

        public SnapshotCommit Commit()
        {
            _writer.Flush();
            _stream.Flush(true);
            _committed = true;
            return new SnapshotCommit(FilePath, Count);
        }

        public void Dispose()
        {
            _writer.Dispose();
            _stream.Dispose();

            if (!_committed)
            {
                TryDeleteFile(FilePath);
            }
        }
    }

    private readonly record struct SnapshotCommit(string FilePath, int Count);

    private readonly record struct ScanSlice(ulong Start, ulong End);
}







































