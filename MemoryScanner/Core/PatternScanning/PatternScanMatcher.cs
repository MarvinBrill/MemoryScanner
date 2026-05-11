using MemoryScanner.Models;
using System.Globalization;

namespace MemoryScanner.Core;

internal static class PatternScanMatcher
{
    internal static bool TryEvaluatePattern(
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

            if (!PatternScanValueReader.TryReadValueFromBuffer(buffer.AsSpan(targetIndex), rule.DataType, rule.StringByteLength, out var currentValue))
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

    internal static int ComputeRulePriority(MemoryDataType dataType, ScanComparison comparison, string? valueText, string? valueToText)
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

    internal static double ResolveFloatingTolerance(string? text)
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

    internal static bool FloatValuesEqual(float current, float expected, double tolerance)
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

    internal static bool DoubleValuesEqual(double current, double expected, double tolerance)
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

    internal static bool ValuesMatch(
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
            ScanComparison.Equal => FloatValuesEqual(current, expected, tolerance),
            ScanComparison.NotEqual => !FloatValuesEqual(current, expected, tolerance),
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
            ScanComparison.Equal => DoubleValuesEqual(current, expected, tolerance),
            ScanComparison.NotEqual => !DoubleValuesEqual(current, expected, tolerance),
            ScanComparison.Greater => current > expected,
            ScanComparison.Less => current < expected,
            ScanComparison.Between => DoubleWithinRange(current, expected, expectedUpper, tolerance, upperTolerance),
            _ => false
        };
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
}
