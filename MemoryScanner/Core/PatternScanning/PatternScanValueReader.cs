using MemoryScanner.Models;
using System.Buffers.Binary;
using System.Text;

namespace MemoryScanner.Core;

internal static class PatternScanValueReader
{
    internal static long CountSkippedSteps(ulong start, ulong endExclusive, int typeSize, int stepSize)
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

    internal static bool TryReadValueFromBuffer(ReadOnlySpan<byte> buffer, MemoryDataType dataType, int stringByteLength, out object value)
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

    internal static bool TryMatchStartValue(ReadOnlySpan<byte> buffer, CompiledStartCriterion criterion, out string valueText)
    {
        valueText = string.Empty;
        if (!TryReadValueFromBuffer(buffer, criterion.DataType, criterion.StringByteLength, out var currentValue))
        {
            return false;
        }

        if (!PatternScanMatcher.ValuesMatch(
                criterion.DataType,
                criterion.Comparison,
                currentValue,
                criterion.TypedValue,
                criterion.TypedUpperValue,
                criterion.RawText,
                criterion.RawUpperText))
        {
            return false;
        }

        valueText = criterion.DataType == MemoryDataType.String
            ? Convert.ToString(currentValue) ?? string.Empty
            : ValueTextFormatter.Format(currentValue);
        return true;
    }

    internal static string DecodeStringBytes(ReadOnlySpan<byte> bytes)
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

    internal static int ResolveStringReadLength(MemoryDataType dataType, string? primaryText, string? secondaryText)
    {
        if (dataType != MemoryDataType.String)
        {
            return 0;
        }

        var primaryLength = Encoding.UTF8.GetByteCount(primaryText ?? string.Empty);
        var secondaryLength = Encoding.UTF8.GetByteCount(secondaryText ?? string.Empty);
        return Math.Clamp(Math.Max(primaryLength, secondaryLength) + 1, 1, 4096);
    }

    internal static int GetTypeNaturalAlignmentSize(MemoryDataType dataType, int stringByteLength)
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

    internal static int GetTypeReadSize(MemoryDataType dataType, int stringByteLength)
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
}
