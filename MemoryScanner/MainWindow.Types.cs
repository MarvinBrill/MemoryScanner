using MemoryScanner.Core;
using MemoryScanner.Models;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace MemoryScanner;

public partial class MainWindow
{
    private sealed class ScanComparisonOption
    {
        public ScanComparisonOption(ScanComparison value, string label)
        {
            Value = value;
            Label = label;
        }

        public ScanComparison Value { get; }
        public string Label { get; }

        public override string ToString()
        {
            return Label;
        }
    }

    public sealed class ScanResultRow : INotifyPropertyChanged
    {
        private string _valueText;
        private readonly ScanResultDisplayContext _displayContext;
        private string? _displayAddress;
        private string? _addressHex;
        private bool _isProcessBaseDisplay;

        public ScanResultRow(ScanResult result, ScanResultDisplayContext displayContext)
        {
            _displayContext = displayContext;
            Address = result.Address;
            DataType = result.DataType;
            StringByteLength = result.StringByteLength;
            _valueText = result.ValueText;
        }

        public ulong Address { get; }
        public string AddressHex => _addressHex ??= $"0x{Address:X}";
        public string DisplayAddress
        {
            get
            {
                EnsureAddressPresentation();
                return _displayAddress!;
            }
        }
        public string ValueText
        {
            get => _valueText;
            set
            {
                if (_valueText == value) return;
                _valueText = value;
                OnPropertyChanged();
            }
        }
        public bool IsProcessBaseDisplay
        {
            get
            {
                EnsureAddressPresentation();
                return _isProcessBaseDisplay;
            }
        }
        public MemoryDataType DataType { get; }
        public int StringByteLength { get; }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void EnsureAddressPresentation()
        {
            if (_displayAddress is not null)
            {
                return;
            }

            var displayAddress = _displayContext.FormatAddress(Address);
            _displayAddress = displayAddress;
            _isProcessBaseDisplay = _displayContext.IsProcessBaseAddress(displayAddress);
        }

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public sealed class ScanResultDisplayContext
    {
        private readonly bool _useProcessBaseFormatting;
        private readonly string? _processBasePrefix;
        private readonly string _processName = "Process";
        private readonly List<ModuleRange> _modules = new();

        public ScanResultDisplayContext(IMemoryAccessor memoryAccessor)
        {
            if (!memoryAccessor.IsAttached)
            {
                return;
            }

            _useProcessBaseFormatting = true;
            _processName = memoryAccessor.Process.ProcessName;
            _processBasePrefix = _processName + "+0x";
            _modules = memoryAccessor.Modules.ToList();
        }

        public string FormatAddress(ulong address)
        {
            if (!_useProcessBaseFormatting)
            {
                return $"0x{address:X}";
            }

            foreach (var module in _modules)
            {
                if (!module.Contains(address))
                {
                    continue;
                }

                var offset = address - module.Base;
                return $"{_processName}+0x{offset:X}";
            }

            return $"0x{address:X}";
        }

        public bool IsProcessBaseAddress(string text)
        {
            return !string.IsNullOrWhiteSpace(_processBasePrefix)
                && text.StartsWith(_processBasePrefix, StringComparison.OrdinalIgnoreCase);
        }
    }
}
