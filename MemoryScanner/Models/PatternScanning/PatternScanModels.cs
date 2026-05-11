using System.Collections.ObjectModel;

namespace MemoryScanner.Models;

public enum PatternSearchOrder
{
    StartToEnd,
    MiddleToOutside,
    EndToStart,
    CustomPercentToOutside
}

public enum PatternSearchFocus
{
    Coarse,
    Balanced,
    Fine
}

public sealed class AddressPatternScanRequest
{
    public MemoryDataType StartDataType { get; set; } = MemoryDataType.Int32;
    public string StartValueText { get; set; } = string.Empty;
    public int StartStringByteLength { get; set; }
    public int StepSizeBytes { get; set; } = 4;
    public ObservableCollection<AddressPatternRuleDefinition> Rules { get; set; } = new();
    public PatternGeneralRuleOptions GeneralRules { get; set; } = new();
}

public sealed class AddressPatternRuleDefinition
{
    public int RelativeStep { get; set; }
    public MemoryDataType DataType { get; set; } = MemoryDataType.Int32;
    public ScanComparison Comparison { get; set; } = ScanComparison.Equal;
    public string ValueText { get; set; } = string.Empty;
    public string ValueToText { get; set; } = string.Empty;
}

public sealed class AddressPatternScanResult
{
    public ulong Address { get; set; }
    public string ValueText { get; set; } = string.Empty;
    public MemoryDataType DataType { get; set; }
    public int StringByteLength { get; set; }
    public string PreviewText { get; set; } = string.Empty;
}

public sealed class PatternGeneralRuleOptions
{
    public PatternSearchOrder SearchOrder { get; set; } = PatternSearchOrder.StartToEnd;
    public PatternSearchFocus SearchFocus { get; set; } = PatternSearchFocus.Balanced;
    public int CustomSearchStartPercent { get; set; } = 50;
    public bool StopAfterGapFromLastMatchEnabled { get; set; }
    public int MaxAddressesWithoutMatchAfterFirstHit { get; set; } = 10000;
}

public sealed class PatternScannerPreset
{
    public MemoryDataType StartDataType { get; set; } = MemoryDataType.Int32;
    public string StartValueText { get; set; } = string.Empty;
    public int StartStringByteLength { get; set; }
    public int StepSizeBytes { get; set; } = 4;
    public List<AddressPatternRuleDefinition> Rules { get; set; } = new();
    public PatternGeneralRuleOptions GeneralRules { get; set; } = new();
    public ScanExecutionOptions ScanOptions { get; set; } = new();
}
