using MemoryScanner.Models;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace MemoryScanner.Core;

public sealed partial class ScanService
{
    public static bool TryParseValue(MemoryDataType dataType, string? text, out object value)
    {
        value = 0;
        if (dataType == MemoryDataType.String)
        {
            if (text is null)
            {
                return false;
            }

            value = text;
            return text.Length > 0;
        }

        if (string.IsNullOrWhiteSpace(text)) return false;
        var trimmed = text.Trim();

        return dataType switch
        {
            MemoryDataType.Byte => byte.TryParse(trimmed, out var b) ? Assign(b, out value) : false,
            MemoryDataType.Int16 => short.TryParse(trimmed, out var s16) ? Assign(s16, out value) : false,
            MemoryDataType.Int32 => int.TryParse(trimmed, out var i) ? Assign(i, out value) : false,
            MemoryDataType.Int64 => long.TryParse(trimmed, out var l) ? Assign(l, out value) : false,
            MemoryDataType.Float => TryParseFloatValue(trimmed, out value),
            MemoryDataType.Double => TryParseDoubleValue(trimmed, out value),
            MemoryDataType.String => false,
            _ => false
        };
    }

    private static bool TryParseFloatValue(string text, out object value)
    {
        value = 0f;
        if (TryParseFloatingValue(text, out float parsed))
        {
            value = parsed;
            return true;
        }

        return false;
    }

    private static bool TryParseDoubleValue(string text, out object value)
    {
        value = 0d;
        if (TryParseFloatingValue(text, out double parsed))
        {
            value = parsed;
            return true;
        }

        return false;
    }

    private static bool TryParseFloatingValue(string text, out float value)
    {
        value = 0;
        if (float.TryParse(text, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out value))
        {
            return true;
        }

        if (float.TryParse(text, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.CurrentCulture, out value))
        {
            return true;
        }

        return TryParseFloatingValueWithSwappedSeparator(text, out value);
    }

    private static bool TryParseFloatingValue(string text, out double value)
    {
        value = 0;
        if (double.TryParse(text, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out value))
        {
            return true;
        }

        if (double.TryParse(text, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.CurrentCulture, out value))
        {
            return true;
        }

        return TryParseFloatingValueWithSwappedSeparator(text, out value);
    }

    private static bool TryParseFloatingValueWithSwappedSeparator(string text, out float value)
    {
        value = 0;
        var normalized = NormalizeFloatingSeparators(text);
        if (normalized is null)
        {
            return false;
        }

        return float.TryParse(normalized, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out value)
            || float.TryParse(normalized, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.CurrentCulture, out value);
    }

    private static bool TryParseFloatingValueWithSwappedSeparator(string text, out double value)
    {
        value = 0;
        var normalized = NormalizeFloatingSeparators(text);
        if (normalized is null)
        {
            return false;
        }

        return double.TryParse(normalized, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out value)
            || double.TryParse(normalized, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.CurrentCulture, out value);
    }

    private static string? NormalizeFloatingSeparators(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        if (text.IndexOf(',') >= 0 && text.IndexOf('.') < 0)
        {
            return text.Replace(',', '.');
        }

        if (text.IndexOf('.') >= 0 && text.IndexOf(',') < 0)
        {
            return text.Replace('.', ',');
        }

        return null;
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
            MemoryDataType.String => unchecked((ulong)Encoding.UTF8.GetByteCount(Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty)),
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
            MemoryDataType.String => string.Empty,
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

    private static FirstScanMatcher? BuildStringFirstScanMatcher(ScanComparison comparison, byte[] inputBytes)
    {
        if (inputBytes.Length == 0)
        {
            return null;
        }

        return comparison switch
        {
            ScanComparison.Equal => (ReadOnlySpan<byte> span, int offset, out object value) =>
            {
                var current = span.Slice(offset, inputBytes.Length);
                if (!current.SequenceEqual(inputBytes))
                {
                    value = string.Empty;
                    return false;
                }

                value = DecodeUtf8String(current);
                return true;
            },
            ScanComparison.NotEqual => (ReadOnlySpan<byte> span, int offset, out object value) =>
            {
                var current = span.Slice(offset, inputBytes.Length);
                if (current.SequenceEqual(inputBytes))
                {
                    value = string.Empty;
                    return false;
                }

                value = DecodeUtf8String(current);
                return true;
            },
            _ => null
        };
    }

    private static bool IsStringFirstScanComparisonSupported(ScanComparison comparison)
    {
        return comparison is ScanComparison.Equal or ScanComparison.NotEqual;
    }

    private static bool IsStringNextScanComparisonSupported(ScanComparison comparison)
    {
        return comparison is ScanComparison.Equal or ScanComparison.NotEqual;
    }

    private static int NormalizeStringCandidateByteLength(ulong rawValue)
    {
        if (rawValue == 0)
        {
            return 0;
        }

        var clamped = Math.Clamp(rawValue, 1UL, 4096UL);
        return (int)clamped;
    }

    private static string DecodeUtf8String(ReadOnlySpan<byte> bytes)
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
        MemoryDataType.String => sizeof(byte),
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
        return ValueTextFormatter.Format(value);
    }

}
