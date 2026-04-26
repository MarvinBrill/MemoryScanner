using MemoryScanner.Core;
using MemoryScanner.Models;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace MemoryScanner.Windows;

public partial class PointerScanWindow
{
    public sealed class PointerPathRow : INotifyPropertyChanged
    {
        private readonly Func<PointerPath, string>? _pointerExpressionFactory;
        private string? _pointerExpressionText;
        private string? _baseAddressText;
        private string? _offsetsDisplay;
        private string _valueText = string.Empty;
        private string _currentAddressText = "<unresolved>";
        private object? _resolvedValue;
        private bool _hasResolvedValue;

        public PointerPathRow(PointerPath path, Func<PointerPath, string>? pointerExpressionFactory = null)
        {
            Path = path;
            _pointerExpressionFactory = pointerExpressionFactory;
        }

        public PointerPath Path { get; }
        public string BaseAddress => _baseAddressText ??= $"0x{Path.BaseAddress:X}";
        public string OffsetsDisplay => _offsetsDisplay ??= string.Join(", ", Path.Offsets.Select(PointerScanWindow.FormatOffset));

        public string PointerExpressionText
        {
            get
            {
                if (_pointerExpressionText is null)
                {
                    _pointerExpressionText = _pointerExpressionFactory?.Invoke(Path) ?? Path.DisplayExpression;
                }

                return _pointerExpressionText;
            }
            set
            {
                if (_pointerExpressionText == value) return;
                _pointerExpressionText = value;
                OnPropertyChanged();
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

        public string CurrentAddressText
        {
            get => _currentAddressText;
            set
            {
                if (_currentAddressText == value) return;
                _currentAddressText = value;
                OnPropertyChanged();
            }
        }

        public void SetResolvedValue(object value)
        {
            _resolvedValue = value;
            _hasResolvedValue = true;
        }

        public void ClearResolvedValue()
        {
            _resolvedValue = null;
            _hasResolvedValue = false;
        }

        public bool TryGetResolvedValue(out object value)
        {
            if (_hasResolvedValue && _resolvedValue is not null)
            {
                value = _resolvedValue;
                return true;
            }

            value = 0;
            return false;
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    private sealed class PointerDisplayContext
    {
        private readonly string _processName = "Process";
        private readonly IReadOnlyList<ModuleRange> _modules = Array.Empty<ModuleRange>();

        public PointerDisplayContext(IMemoryAccessor memoryAccessor)
        {
            if (!memoryAccessor.IsAttached)
            {
                return;
            }

            IsAttached = true;
            _processName = memoryAccessor.Process.ProcessName;
            _modules = memoryAccessor.Modules.ToList();
        }

        public bool IsAttached { get; }

        public string FormatAddress(ulong address)
        {
            if (!IsAttached)
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
    }

    private sealed class PointerScanCompactSession
    {
        public int Version { get; set; } = 1;
        public string ProcessName { get; set; } = string.Empty;
        public DateTime SavedAtUtc { get; set; }
        public ulong TargetAddress { get; set; }
        public MemoryDataType ValueDataType { get; set; } = MemoryDataType.Int32;
        public PointerScanOptions Options { get; set; } = new();
        public List<PointerPathCompact> Results { get; set; } = new();
    }

    private sealed class PointerPathCompact
    {
        public ulong BaseAddress { get; set; }
        public int PointerSizeBytes { get; set; }
        public string BaseModuleName { get; set; } = string.Empty;
        public ulong BaseModuleOffset { get; set; }
        public List<int> Offsets { get; set; } = new();
    }

    private readonly struct PointerSaveProgressInfo
    {
        public PointerSaveProgressInfo(double percent, string stage, string detail)
        {
            Percent = percent;
            Stage = stage;
            Detail = detail;
        }

        public double Percent { get; }
        public string Stage { get; }
        public string Detail { get; }
    }

    private sealed class PointerScanSession
    {
        public string ProcessName { get; set; } = string.Empty;
        public DateTime SavedAtUtc { get; set; }
        public ulong TargetAddress { get; set; }
        public MemoryDataType ValueDataType { get; set; } = MemoryDataType.Int32;
        public PointerScanOptions Options { get; set; } = new();
        public List<PointerPath> Results { get; set; } = new();
    }
}
