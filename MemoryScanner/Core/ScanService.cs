using MemoryScanner.Models;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Threading.Tasks;

namespace MemoryScanner.Core;

public sealed class ScanService
{
    private const int InitialReadChunkSize = 256 * 1024;
    private const int MinReadChunkSize = 16 * 1024;
    private const int MaxReadChunkSize = 1024 * 1024;
    private const ulong RegionSliceSize = 8UL * 1024 * 1024;

    private readonly IMemoryAccessor _memory;
    private readonly MemoryRegionEnumerator _regionEnumerator;
    private readonly List<ScanCandidate> _candidates = new();

    public ScanService(IMemoryAccessor memory, MemoryRegionEnumerator regionEnumerator)
    {
        _memory = memory;
        _regionEnumerator = regionEnumerator;
    }

    public IReadOnlyList<ScanResult> FirstScan(
        MemoryDataType dataType,
        ScanComparison comparison,
        string? valueText,
        ScanExecutionOptions executionOptions,
        IProgress<ScanProgressInfo>? progress,
        CancellationToken cancellationToken)
    {
        _candidates.Clear();
        var results = new List<ScanResult>();
        if (!_memory.IsAttached) return results;
        if (!IsFirstScanComparisonSupported(comparison)) return results;

        object? input = null;
        if (RequiresInput(comparison) && !TryParseValue(dataType, valueText, out input))
        {
            return results;
        }

        ResolveDepth(executionOptions.DepthProfile, out var includePrivate, out var includeImage, out var scanUnaligned, out var stepMultiplier);
        var typeSize = GetTypeSize(dataType);
        var stepSize = scanUnaligned ? 1 : Math.Max(1, typeSize * stepMultiplier);
        var effectiveLimit = executionOptions.NormalizedResultLimit();
        var hasLimit = executionOptions.UseResultLimit;

        var regions = _regionEnumerator.Enumerate(_memory.Process, includePrivate, includeImage);
        var slices = SliceRegions(regions, RegionSliceSize);
        var totalSteps = CalculateTotalSteps(slices, typeSize, stepSize);
        ReportProgress(progress, 0, totalSteps, "Scanning memory");

        var gate = new object();
        var collectedCandidates = new List<ScanCandidate>();
        long processed = 0;
        int limitReached = 0;
        var progressGate = new object();
        long lastProgressTicks = 0;

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

                        if (!TryReadAndMatchFirst(span, pos, dataType, comparison, input, out var value))
                        {
                            continue;
                        }

                        ulong address = cursor + (ulong)pos;
                        local.AddMatch(address, value, dataType);

                        if (local.Results.Count >= 128)
                        {
                            FlushLocal(local, results, collectedCandidates, hasLimit, effectiveLimit, ref limitReached, gate);
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
                FlushLocal(local, results, collectedCandidates, hasLimit, effectiveLimit, ref limitReached, gate);
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

        _candidates.Clear();
        _candidates.AddRange(collectedCandidates);

        var finalStatus = cancellationToken.IsCancellationRequested ? "Scan canceled" : "Scan finished";
        ReportProgress(progress, Math.Min(processed, totalSteps), totalSteps, finalStatus);
        return results;
    }

    public IReadOnlyList<ScanResult> NextScan(
        MemoryDataType dataType,
        ScanComparison comparison,
        string? valueText,
        ScanExecutionOptions executionOptions,
        IProgress<ScanProgressInfo>? progress,
        CancellationToken cancellationToken)
    {
        var results = new List<ScanResult>();
        if (!_memory.IsAttached || _candidates.Count == 0) return results;

        object? input = null;
        if (RequiresInput(comparison) && !TryParseValue(dataType, valueText, out input))
        {
            return results;
        }

        var effectiveLimit = executionOptions.NormalizedResultLimit();
        var hasLimit = executionOptions.UseResultLimit;

        var snapshot = _candidates.ToArray();
        var total = Math.Max(1, snapshot.Length);
        ReportProgress(progress, 0, total, "Filtering previous results");

        var gate = new object();
        var collectedCandidates = new List<ScanCandidate>();
        int limitReached = 0;
        long processed = 0;
        var progressGate = new object();
        long lastProgressTicks = 0;

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = executionOptions.NormalizedThreadCount()
        };

        try
        {
            Parallel.ForEach(snapshot, parallelOptions, () => new LocalCollector(), (candidate, loopState, local) =>
            {
                if (cancellationToken.IsCancellationRequested || Volatile.Read(ref limitReached) == 1)
                {
                    loopState.Stop();
                    return local;
                }

                if (_memory.TryReadValue(candidate.Address, dataType, out var newValue) && MatchFast(dataType, comparison, newValue, input, candidate.LastValue))
                {
                    local.AddMatch(candidate.Address, newValue, dataType);
                }

                local.ProcessedCount++;
                if ((local.ProcessedCount & 1023) == 0)
                {
                    var done = Interlocked.Add(ref processed, 1024);
                    local.ProcessedCount -= 1024;
                    TryReportProgressThrottled(progress, progressGate, ref lastProgressTicks, done, total, "Filtering previous results");
                }

                if (local.Results.Count >= 128)
                {
                    FlushLocal(local, results, collectedCandidates, hasLimit, effectiveLimit, ref limitReached, gate);
                    if (Volatile.Read(ref limitReached) == 1)
                    {
                        loopState.Stop();
                    }
                }

                return local;
            }, local =>
            {
                FlushLocal(local, results, collectedCandidates, hasLimit, effectiveLimit, ref limitReached, gate);
                if (local.ProcessedCount > 0)
                {
                    var done = Interlocked.Add(ref processed, local.ProcessedCount);
                    TryReportProgressThrottled(progress, progressGate, ref lastProgressTicks, done, total, "Filtering previous results");
                }
            });
        }
        catch (OperationCanceledException)
        {
        }
        catch (AggregateException ex) when (ex.Flatten().InnerExceptions.All(inner => inner is OperationCanceledException))
        {
        }

        _candidates.Clear();
        _candidates.AddRange(collectedCandidates);

        var finalStatus = cancellationToken.IsCancellationRequested ? "Scan canceled" : "Scan finished";
        ReportProgress(progress, Math.Min(processed, total), total, finalStatus);
        return results;
    }

    public void Reset() => _candidates.Clear();

    public static bool TryParseValue(MemoryDataType dataType, string? text, out object value)
    {
        value = 0;
        if (string.IsNullOrWhiteSpace(text)) return false;
        var trimmed = text.Trim();

        return dataType switch
        {
            MemoryDataType.Byte => byte.TryParse(trimmed, out var b) ? Assign(b, out value) : false,
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

    private static void FlushLocal(LocalCollector local, List<ScanResult> globalResults, List<ScanCandidate> globalCandidates, bool hasLimit, int effectiveLimit, ref int limitReached, object gate)
    {
        if (local.Results.Count == 0)
        {
            return;
        }

        lock (gate)
        {
            if (!hasLimit)
            {
                globalResults.AddRange(local.Results);
                globalCandidates.AddRange(local.Candidates);
            }
            else
            {
                int remaining = effectiveLimit - globalResults.Count;
                if (remaining > 0)
                {
                    int toCopy = Math.Min(remaining, local.Results.Count);
                    for (int i = 0; i < toCopy; i++)
                    {
                        globalResults.Add(local.Results[i]);
                        globalCandidates.Add(local.Candidates[i]);
                    }
                }

                if (globalResults.Count >= effectiveLimit)
                {
                    Volatile.Write(ref limitReached, 1);
                }
            }
        }

        local.Results.Clear();
        local.Candidates.Clear();
    }

    private static bool TryReadAndMatchFirst(
        ReadOnlySpan<byte> span,
        int offset,
        MemoryDataType type,
        ScanComparison comparison,
        object? input,
        out object value)
    {
        value = 0;
        if (input is null) return false;

        switch (type)
        {
            case MemoryDataType.Byte:
            {
                var current = span[offset];
                var target = (byte)input;
                if (!MatchDirect(comparison, current, target))
                {
                    return false;
                }

                value = current;
                return true;
            }
            case MemoryDataType.Int32:
            {
                var current = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(offset, sizeof(int)));
                var target = (int)input;
                if (!MatchDirect(comparison, current, target))
                {
                    return false;
                }

                value = current;
                return true;
            }
            case MemoryDataType.Int64:
            {
                var current = BinaryPrimitives.ReadInt64LittleEndian(span.Slice(offset, sizeof(long)));
                var target = (long)input;
                if (!MatchDirect(comparison, current, target))
                {
                    return false;
                }

                value = current;
                return true;
            }
            case MemoryDataType.Float:
            {
                var current = BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(span.Slice(offset, sizeof(int))));
                var target = (float)input;
                if (!MatchDirect(comparison, current, target))
                {
                    return false;
                }

                value = current;
                return true;
            }
            case MemoryDataType.Double:
            {
                var current = BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(span.Slice(offset, sizeof(long))));
                var target = (double)input;
                if (!MatchDirect(comparison, current, target))
                {
                    return false;
                }

                value = current;
                return true;
            }
            default:
                return false;
        }
    }

    private static bool MatchFast(MemoryDataType type, ScanComparison comparison, object current, object? input, object? previous)
    {
        try
        {
            switch (type)
            {
                case MemoryDataType.Byte:
                    if (!TryCoerce(current, out byte currentByte)) return false;
                    byte inputByte = default;
                    bool hasByteInput = input is not null && TryCoerce(input, out inputByte);
                    byte previousByte = default;
                    bool hasBytePrevious = previous is not null && TryCoerce(previous, out previousByte);
                    return MatchTyped(comparison, currentByte, inputByte, previousByte, hasByteInput, hasBytePrevious);

                case MemoryDataType.Int32:
                    if (!TryCoerce(current, out int currentInt)) return false;
                    int inputInt = default;
                    bool hasIntInput = input is not null && TryCoerce(input, out inputInt);
                    int previousInt = default;
                    bool hasIntPrevious = previous is not null && TryCoerce(previous, out previousInt);
                    return MatchTyped(comparison, currentInt, inputInt, previousInt, hasIntInput, hasIntPrevious);

                case MemoryDataType.Int64:
                    if (!TryCoerce(current, out long currentLong)) return false;
                    long inputLong = default;
                    bool hasLongInput = input is not null && TryCoerce(input, out inputLong);
                    long previousLong = default;
                    bool hasLongPrevious = previous is not null && TryCoerce(previous, out previousLong);
                    return MatchTyped(comparison, currentLong, inputLong, previousLong, hasLongInput, hasLongPrevious);

                case MemoryDataType.Float:
                    if (!TryCoerce(current, out float currentFloat)) return false;
                    float inputFloat = default;
                    bool hasFloatInput = input is not null && TryCoerce(input, out inputFloat);
                    float previousFloat = default;
                    bool hasFloatPrevious = previous is not null && TryCoerce(previous, out previousFloat);
                    return MatchTyped(comparison, currentFloat, inputFloat, previousFloat, hasFloatInput, hasFloatPrevious);

                case MemoryDataType.Double:
                    if (!TryCoerce(current, out double currentDouble)) return false;
                    double inputDouble = default;
                    bool hasDoubleInput = input is not null && TryCoerce(input, out inputDouble);
                    double previousDouble = default;
                    bool hasDoublePrevious = previous is not null && TryCoerce(previous, out previousDouble);
                    return MatchTyped(comparison, currentDouble, inputDouble, previousDouble, hasDoubleInput, hasDoublePrevious);

                default:
                    return false;
            }
        }
        catch
        {
            return false;
        }
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
        T previous,
        bool hasInput,
        bool hasPrevious)
        where T : struct, IComparable<T>
    {
        return comparison switch
        {
            ScanComparison.Equal => hasInput && current.CompareTo(input) == 0,
            ScanComparison.NotEqual => hasInput && current.CompareTo(input) != 0,
            ScanComparison.Greater => hasInput && current.CompareTo(input) > 0,
            ScanComparison.Less => hasInput && current.CompareTo(input) < 0,
            ScanComparison.Increased => hasPrevious && current.CompareTo(previous) > 0,
            ScanComparison.Decreased => hasPrevious && current.CompareTo(previous) < 0,
            ScanComparison.Changed => hasPrevious && current.CompareTo(previous) != 0,
            ScanComparison.Unchanged => hasPrevious && current.CompareTo(previous) == 0,
            _ => false
        };
    }

    private static bool MatchDirect<T>(ScanComparison comparison, T current, T input) where T : struct, IComparable<T>
    {
        return comparison switch
        {
            ScanComparison.Equal => current.CompareTo(input) == 0,
            ScanComparison.NotEqual => current.CompareTo(input) != 0,
            ScanComparison.Greater => current.CompareTo(input) > 0,
            ScanComparison.Less => current.CompareTo(input) < 0,
            _ => false
        };
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
        MemoryDataType.Int32 => sizeof(int),
        MemoryDataType.Int64 => sizeof(long),
        MemoryDataType.Float => sizeof(float),
        MemoryDataType.Double => sizeof(double),
        _ => sizeof(int)
    };

    private static bool RequiresInput(ScanComparison comparison)
    {
        return comparison is ScanComparison.Equal or ScanComparison.NotEqual or ScanComparison.Greater or ScanComparison.Less;
    }

    private static bool IsFirstScanComparisonSupported(ScanComparison comparison)
    {
        return comparison is ScanComparison.Equal or ScanComparison.NotEqual or ScanComparison.Greater or ScanComparison.Less;
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

    private sealed class ScanCandidate
    {
        public ulong Address { get; set; }
        public object LastValue { get; set; } = 0;
    }

    private sealed class LocalCollector
    {
        public List<ScanResult> Results { get; } = new(128);
        public List<ScanCandidate> Candidates { get; } = new(128);
        public long ProcessedCount { get; set; }

        public void AddMatch(ulong address, object value, MemoryDataType type)
        {
            Results.Add(new ScanResult
            {
                Address = address,
                DataType = type,
                ValueText = FormatValue(value)
            });

            Candidates.Add(new ScanCandidate
            {
                Address = address,
                LastValue = value
            });
        }
    }

    private readonly record struct ScanSlice(ulong Start, ulong End);
}


















