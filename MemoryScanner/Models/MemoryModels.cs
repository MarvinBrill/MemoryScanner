using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace MemoryScanner.Models;

public enum MemoryDataType
{
    Byte,
    Int32,
    Int64,
    Float,
    Double,
    Int16
}


public static class MemoryDataTypeUiOrder
{
    public static IReadOnlyList<MemoryDataType> Ordered { get; } = new[]
    {
        MemoryDataType.Byte,
        MemoryDataType.Int16,
        MemoryDataType.Int32,
        MemoryDataType.Int64,
        MemoryDataType.Float,
        MemoryDataType.Double
    };
}
public enum ScanComparison
{
    UnknownInitial,
    Equal,
    NotEqual,
    Greater,
    Less,
    Between,
    Increased,
    Decreased,
    Changed,
    Unchanged
}

public enum WatchEntryKind
{
    DirectAddress,
    PointerChain
}
public enum PointerValueWidthMode
{
    Auto,
    Force32Bit,
    Force64Bit
}


public sealed class WatchEntry : INotifyPropertyChanged
{
    private string _lastValueText = string.Empty;
    private bool _isFrozen;
    private string _status = "Unknown";
    private bool _isProcessBaseDisplay;
    private string _displayAddress = string.Empty;

    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "Entry";
    public WatchEntryKind Kind { get; set; }
    public MemoryDataType DataType { get; set; } = MemoryDataType.Int32;
    public ulong DirectAddress { get; set; }
    public ulong PointerBaseAddress { get; set; }
    public int PointerSizeBytes { get; set; } = 0;
    public string PointerBaseModuleName { get; set; } = string.Empty;
    public ulong PointerBaseModuleOffset { get; set; }
    public ObservableCollection<int> Offsets { get; set; } = new();

    public string DisplayAddress
    {
        get => _displayAddress;
        set
        {
            if (_displayAddress == value) return;
            _displayAddress = value;
            OnPropertyChanged();
        }
    }

    public bool IsProcessBaseDisplay
    {
        get => _isProcessBaseDisplay;
        set
        {
            if (_isProcessBaseDisplay == value) return;
            _isProcessBaseDisplay = value;
            OnPropertyChanged();
        }
    }

    public bool IsFrozen
    {
        get => _isFrozen;
        set
        {
            if (_isFrozen == value) return;
            _isFrozen = value;
            OnPropertyChanged();
        }
    }

    public string FreezeValueText { get; set; } = string.Empty;

    public string LastValueText
    {
        get => _lastValueText;
        set
        {
            if (_lastValueText == value) return;
            _lastValueText = value;
            OnPropertyChanged();
        }
    }

    public string Status
    {
        get => _status;
        set
        {
            if (_status == value) return;
            _status = value;
            OnPropertyChanged();
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

public sealed class ScanResult
{
    public ulong Address { get; set; }
    public string DisplayAddress { get; set; } = string.Empty;
    public string ValueText { get; set; } = string.Empty;
    public MemoryDataType DataType { get; set; }
    public bool IsStatic { get; set; }
}

public sealed class PointerScanOptions
{
    public int MaxDepth { get; set; } = 5;
    public int MaxOffset { get; set; } = 4096;
    public int MaxResults { get; set; } = 5000;
    public bool UseResultLimit { get; set; } = false;
    public int ThreadCount { get; set; } = Math.Max(1, Environment.ProcessorCount / 2);
    public int Alignment { get; set; } = 4;
    public bool IncludePrivate { get; set; } = true;
    public bool IncludeMapped { get; set; } = true;
    public bool IncludeModuleImage { get; set; } = true;
    public bool RequireStaticRoot { get; set; } = true;
    public bool ExcludeReadOnlyNodes { get; set; } = false;
    public bool NoLoopingPointers { get; set; } = true;
    public bool StopTraversingAfterStaticRoot { get; set; } = false;
    public bool AggressiveNodeDeduplication { get; set; } = true;
    public bool AllowNegativeOffsets { get; set; } = false;
    public PointerValueWidthMode PointerWidthMode { get; set; } = PointerValueWidthMode.Auto;
    public bool UseAddressRange { get; set; } = false;
    public ulong AddressRangeFrom { get; set; } = 0;
    public ulong AddressRangeTo { get; set; } = 0;
    public bool RequireRootInAddressRange { get; set; } = false;
    public bool RequireAllNodesInAddressRange { get; set; } = false;
    public bool TrimMemoryAfterCancel { get; set; } = false;

    public int NormalizedThreadCount()
    {
        if (ThreadCount <= 0)
        {
            return 1;
        }

        return Math.Min(ThreadCount, Environment.ProcessorCount);
    }

    public int NormalizedResultLimit()
    {
        return Math.Max(1, MaxResults);
    }

    public bool TryGetNormalizedAddressRange(out ulong min, out ulong max)
    {
        min = 0;
        max = 0;

        if (!UseAddressRange)
        {
            return false;
        }

        if (AddressRangeFrom <= AddressRangeTo)
        {
            min = AddressRangeFrom;
            max = AddressRangeTo;
        }
        else
        {
            min = AddressRangeTo;
            max = AddressRangeFrom;
        }

        return true;
    }
}

public sealed class PointerPath
{
    public ulong BaseAddress { get; set; }
    public int PointerSizeBytes { get; set; } = 0;
    public string BaseModuleName { get; set; } = string.Empty;
    public ulong BaseModuleOffset { get; set; }
    public List<int> Offsets { get; set; } = new();
    public string DisplayExpression { get; set; } = string.Empty;
    public ulong FinalAddressPreview { get; set; }
}

public sealed class ModuleRange
{
    public string Name { get; set; } = string.Empty;
    public ulong Base { get; set; }
    public ulong End { get; set; }

    public bool Contains(ulong address) => address >= Base && address < End;
}













