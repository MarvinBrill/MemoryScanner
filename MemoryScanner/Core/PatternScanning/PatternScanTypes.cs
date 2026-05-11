using MemoryScanner.Models;

namespace MemoryScanner.Core;

internal readonly record struct CompiledPatternRule(
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

internal readonly record struct CompiledStartCriterion(
    MemoryDataType DataType,
    ScanComparison Comparison,
    string RawText,
    string RawUpperText,
    int StringByteLength,
    int ReadSize,
    object TypedValue,
    object? TypedUpperValue);

internal readonly record struct PatternScanSlice(
    ulong RegionStart,
    ulong RegionEnd,
    ulong SliceStart,
    ulong SliceEnd);

internal readonly record struct SliceScanOutcome(
    List<AddressPatternScanResult> Rows,
    long ProcessedSteps,
    ulong ScannedBytes);

internal readonly record struct PatternChunk(
    ulong ChunkStart,
    ulong MainEndExclusive,
    ulong ReadStart,
    byte[] Buffer);

internal enum StrictGapStopReason
{
    None,
    GapReached,
    ResultLimit
}
