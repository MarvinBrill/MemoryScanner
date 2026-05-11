using MemoryScanner.Models;

namespace MemoryScanner.Core;

internal static class PatternScanCompiler
{
    internal static CompiledStartCriterion CompileStartCriterion(AddressPatternScanRequest request)
    {
        if (!IsComparisonSupported(request.StartDataType, request.StartComparison))
        {
            throw new InvalidOperationException($"Comparison '{request.StartComparison}' is not supported for start data type '{request.StartDataType}'.");
        }

        if (!TryParseComparisonValues(
                request.StartDataType,
                request.StartComparison,
                request.StartValueText,
                request.StartValueToText,
                "Invalid start value.",
                "Invalid upper start range value.",
                out var startValue,
                out var upperValue))
        {
            throw new InvalidOperationException("Invalid start value.");
        }

        return new CompiledStartCriterion(
            request.StartDataType,
            request.StartComparison,
            request.StartValueText,
            request.StartValueToText,
            request.StartStringByteLength,
            PatternScanValueReader.GetTypeReadSize(request.StartDataType, request.StartStringByteLength),
            startValue!,
            upperValue);
    }

    internal static IReadOnlyList<CompiledPatternRule> CompileRules(AddressPatternScanRequest request)
    {
        var compiled = new List<CompiledPatternRule>(request.Rules.Count);
        for (var index = 0; index < request.Rules.Count; index++)
        {
            var rule = request.Rules[index];
            if (!IsComparisonSupported(rule.DataType, rule.Comparison))
            {
                throw new InvalidOperationException($"Comparison '{rule.Comparison}' is not supported for data type '{rule.DataType}'.");
            }

            var stringReadLength = PatternScanValueReader.ResolveStringReadLength(rule.DataType, rule.ValueText, rule.ValueToText);
            var readSize = PatternScanValueReader.GetTypeReadSize(rule.DataType, stringReadLength);
            if (TryParseComparisonValues(
                    rule.DataType,
                    rule.Comparison,
                    rule.ValueText,
                    rule.ValueToText,
                    $"Invalid rule value for step {rule.RelativeStep}.",
                    $"Invalid upper rule value for step {rule.RelativeStep}.",
                    out var value,
                    out var valueUpper))
            {
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
                    PatternScanMatcher.ComputeRulePriority(rule.DataType, rule.Comparison, rule.ValueText, rule.ValueToText)));
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
                PatternScanMatcher.ComputeRulePriority(rule.DataType, rule.Comparison, rule.ValueText, rule.ValueToText)));
        }

        compiled.Sort(static (left, right) =>
        {
            var priorityCompare = left.Priority.CompareTo(right.Priority);
            return priorityCompare != 0 ? priorityCompare : left.OriginalIndex.CompareTo(right.OriginalIndex);
        });

        return compiled;
    }

    private static bool TryParseComparisonValues(
        MemoryDataType dataType,
        ScanComparison comparison,
        string? valueText,
        string? valueToText,
        string invalidValueMessage,
        string invalidUpperValueMessage,
        out object? value,
        out object? upperValue)
    {
        value = null;
        upperValue = null;

        if (!RequiresValue(comparison))
        {
            return false;
        }

        if (!ScanService.TryParseValue(dataType, valueText, out var parsedValue))
        {
            throw new InvalidOperationException(invalidValueMessage);
        }

        value = parsedValue;

        if (comparison != ScanComparison.Between)
        {
            return true;
        }

        if (!ScanService.TryParseValue(dataType, valueToText, out var parsedUpper))
        {
            throw new InvalidOperationException(invalidUpperValueMessage);
        }

        upperValue = parsedUpper;
        return true;
    }

    private static bool RequiresValue(ScanComparison comparison)
    {
        return comparison is ScanComparison.Equal
            or ScanComparison.NotEqual
            or ScanComparison.Greater
            or ScanComparison.Less
            or ScanComparison.Between;
    }

    private static bool IsComparisonSupported(MemoryDataType dataType, ScanComparison comparison)
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
}
