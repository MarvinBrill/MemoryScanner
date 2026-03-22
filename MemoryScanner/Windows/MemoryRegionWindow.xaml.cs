using MemoryScanner.Core;
using MemoryScanner.Models;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace MemoryScanner.Windows;

public partial class MemoryRegionWindow : Window
{
    private readonly IMemoryAccessor _memoryAccessor;
    private readonly ulong _centerAddress;
    private readonly DispatcherTimer _timer;
    private readonly ICollectionView _downView;
    private readonly ICollectionView _upView;

    private bool _filterEnabled;
    private ScanComparison _filterComparison = ScanComparison.Equal;
    private object? _filterInput;

    public ObservableCollection<RegionRow> DownRows { get; } = new();
    public ObservableCollection<RegionRow> UpRows { get; } = new();

    public List<WatchEntry> SelectedEntries { get; private set; } = new();

    public MemoryRegionWindow(IMemoryAccessor memoryAccessor, ulong centerAddress, MemoryDataType initialType)
    {
        _memoryAccessor = memoryAccessor;
        _centerAddress = centerAddress;

        InitializeComponent();

        DownGrid.ItemsSource = DownRows;
        UpGrid.ItemsSource = UpRows;

        _downView = CollectionViewSource.GetDefaultView(DownRows);
        _upView = CollectionViewSource.GetDefaultView(UpRows);
        _downView.Filter = FilterRow;
        _upView.Filter = FilterRow;

        DataTypeBox.ItemsSource = Enum.GetValues<MemoryDataType>();
        DataTypeBox.SelectedItem = initialType;

        FilterComparisonBox.ItemsSource = Enum.GetValues<ScanComparison>();
        FilterComparisonBox.SelectedItem = ScanComparison.Equal;

        CenterAddressText.Text = _memoryAccessor.IsAttached
            ? $"Center: {_memoryAccessor.FormatAddress(_centerAddress)}"
            : $"Center: 0x{_centerAddress:X}";

        _timer = new DispatcherTimer();
        _timer.Tick += Timer_OnTick;

        ApplySettings(showMessageOnError: false);
    }

    private void Apply_OnClick(object sender, RoutedEventArgs e)
    {
        ApplySettings(showMessageOnError: true);
    }

    private void RefreshNow_OnClick(object sender, RoutedEventArgs e)
    {
        RefreshValues();
    }

    private void ApplyFilter_OnClick(object sender, RoutedEventArgs e)
    {
        if (!TryBuildFilter(out var comparison, out var input, showMessageOnError: true))
        {
            return;
        }

        _filterEnabled = true;
        _filterComparison = comparison;
        _filterInput = input;
        EnableFilterBox.IsChecked = true;
        RefreshFilterViews();
    }

    private void ClearFilter_OnClick(object sender, RoutedEventArgs e)
    {
        _filterEnabled = false;
        _filterInput = null;
        EnableFilterBox.IsChecked = false;
        RefreshFilterViews();
    }

    private void TakeSelected_OnClick(object sender, RoutedEventArgs e)
    {
        var selected = DownGrid.SelectedItems.OfType<RegionRow>()
            .Concat(UpGrid.SelectedItems.OfType<RegionRow>())
            .GroupBy(x => x.Address)
            .Select(g => g.First())
            .ToList();

        if (selected.Count == 0)
        {
            MessageBox.Show(this, "No rows selected.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        SelectedEntries = BuildWatchEntries(selected);
        DialogResult = true;
    }

    private void DataGridRow_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (sender is not DataGridRow row)
        {
            return;
        }

        if (!row.IsSelected)
        {
            return;
        }

        var source = e.OriginalSource as DependencyObject;
        if (FindAncestor<DataGridCell>(source) is null)
        {
            return;
        }

        row.IsSelected = false;
        e.Handled = true;
    }

    private static T? FindAncestor<T>(DependencyObject? current) where T : DependencyObject
    {
        while (current is not null)
        {
            if (current is T match)
            {
                return match;
            }

            current = VisualTreeHelper.GetParent(current);
        }

        return null;
    }

    private void Timer_OnTick(object? sender, EventArgs e)
    {
        RefreshValues();
    }

    private void ApplySettings(bool showMessageOnError)
    {
        if (!TryReadSettings(out var dataType, out var downCount, out var upCount, out var refreshMs))
        {
            if (showMessageOnError)
            {
                MessageBox.Show(this, "Invalid settings. Check data type/count/refresh values.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            return;
        }

        RebuildRows(dataType, downCount, upCount);

        if (refreshMs <= 0)
        {
            _timer.Stop();
        }
        else
        {
            _timer.Interval = TimeSpan.FromMilliseconds(refreshMs);
            _timer.Start();
        }

        RefreshValues();
    }

    private bool TryReadSettings(out MemoryDataType dataType, out int downCount, out int upCount, out int refreshMs)
    {
        dataType = MemoryDataType.Int32;
        downCount = 100;
        upCount = 100;
        refreshMs = 200;

        if (DataTypeBox.SelectedItem is not MemoryDataType selectedType)
        {
            return false;
        }

        if (!int.TryParse(DownCountText.Text, out downCount) || downCount < 0 || downCount > 200000)
        {
            return false;
        }

        if (!int.TryParse(UpCountText.Text, out upCount) || upCount < 0 || upCount > 200000)
        {
            return false;
        }

        if (!int.TryParse(RefreshMsText.Text, out refreshMs) || refreshMs < 0 || refreshMs > 60000)
        {
            return false;
        }

        dataType = selectedType;
        return true;
    }

    private bool TryBuildFilter(out ScanComparison comparison, out object? input, bool showMessageOnError)
    {
        comparison = ScanComparison.Equal;
        input = null;

        if (FilterComparisonBox.SelectedItem is not ScanComparison selected)
        {
            if (showMessageOnError)
            {
                MessageBox.Show(this, "Select a filter condition.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            return false;
        }

        comparison = selected;

        if (!RequiresInput(comparison))
        {
            return true;
        }

        if (DataTypeBox.SelectedItem is not MemoryDataType selectedType)
        {
            if (showMessageOnError)
            {
                MessageBox.Show(this, "Select data type first.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            return false;
        }

        if (!ScanService.TryParseValue(selectedType, FilterValueText.Text, out var parsed))
        {
            if (showMessageOnError)
            {
                MessageBox.Show(this, "Invalid filter value for selected data type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            return false;
        }

        input = parsed;
        return true;
    }

    private void RebuildRows(MemoryDataType dataType, int downCount, int upCount)
    {
        DownRows.Clear();
        UpRows.Clear();

        var step = (ulong)GetTypeSize(dataType);

        for (int i = 1; i <= downCount; i++)
        {
            var offset = step * (ulong)i;
            if (_centerAddress < offset)
            {
                break;
            }

            var address = _centerAddress - offset;
            var displayAddress = FormatAddress(address);
            DownRows.Add(new RegionRow(address, dataType, displayAddress, IsProcessBaseAddressText(displayAddress)));
        }

        for (int i = 1; i <= upCount; i++)
        {
            var offset = step * (ulong)i;
            if (_centerAddress > ulong.MaxValue - offset)
            {
                break;
            }

            var address = _centerAddress + offset;
            var displayAddress = FormatAddress(address);
            UpRows.Add(new RegionRow(address, dataType, displayAddress, IsProcessBaseAddressText(displayAddress)));
        }
    }

    private void RefreshValues()
    {
        foreach (var row in DownRows)
        {
            UpdateRowValue(row);
        }

        foreach (var row in UpRows)
        {
            UpdateRowValue(row);
        }

        if (_filterEnabled)
        {
            RefreshFilterViews();
        }
    }

    private void UpdateRowValue(RegionRow row)
    {
        if (_memoryAccessor.TryReadValue(row.Address, row.DataType, out var value))
        {
            row.SetValue(value, FormatValue(value));
        }
        else
        {
            row.SetInvalid();
        }
    }

    private void RefreshFilterViews()
    {
        _downView.Refresh();
        _upView.Refresh();
    }

    private bool FilterRow(object obj)
    {
        if (obj is not RegionRow row)
        {
            return false;
        }

        if (!_filterEnabled)
        {
            return true;
        }

        var current = row.CurrentValue;
        if (current is null)
        {
            return false;
        }

        return _filterComparison switch
        {
            ScanComparison.Equal => Compare(current, _filterInput) == 0,
            ScanComparison.NotEqual => Compare(current, _filterInput) != 0,
            ScanComparison.Greater => Compare(current, _filterInput) > 0,
            ScanComparison.Less => Compare(current, _filterInput) < 0,
            ScanComparison.Increased => row.PreviousValue is not null && Compare(current, row.PreviousValue) > 0,
            ScanComparison.Decreased => row.PreviousValue is not null && Compare(current, row.PreviousValue) < 0,
            ScanComparison.Changed => row.PreviousValue is not null && Compare(current, row.PreviousValue) != 0,
            ScanComparison.Unchanged => row.PreviousValue is not null && Compare(current, row.PreviousValue) == 0,
            _ => true
        };
    }

    private static bool RequiresInput(ScanComparison comparison)
    {
        return comparison is ScanComparison.Equal or ScanComparison.NotEqual or ScanComparison.Greater or ScanComparison.Less;
    }

    private static int Compare(object left, object? right)
    {
        if (right is null)
        {
            return 1;
        }

        return left switch
        {
            byte b => b.CompareTo(Convert.ToByte(right)),
            int i => i.CompareTo(Convert.ToInt32(right)),
            long l => l.CompareTo(Convert.ToInt64(right)),
            float f => f.CompareTo(Convert.ToSingle(right)),
            double d => d.CompareTo(Convert.ToDouble(right)),
            _ => 0
        };
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

    private string FormatAddress(ulong address)
    {
        return _memoryAccessor.IsAttached ? _memoryAccessor.FormatAddress(address) : $"0x{address:X}";
    }

    private bool IsProcessBaseAddressText(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || !_memoryAccessor.IsAttached)
        {
            return false;
        }

        var processPrefix = _memoryAccessor.Process.ProcessName + "+0x";
        return text.StartsWith(processPrefix, StringComparison.OrdinalIgnoreCase);
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

    private static List<WatchEntry> BuildWatchEntries(IEnumerable<RegionRow> rows)
    {
        return rows.Select(row => new WatchEntry
        {
            Name = $"Address_{row.Address:X}",
            Kind = WatchEntryKind.DirectAddress,
            DirectAddress = row.Address,
            DataType = row.DataType
        }).ToList();
    }

    protected override void OnClosed(EventArgs e)
    {
        _timer.Stop();
        base.OnClosed(e);
    }

    public sealed class RegionRow : INotifyPropertyChanged
    {
        private string _valueText = string.Empty;

        public RegionRow(ulong address, MemoryDataType dataType, string displayAddress, bool isProcessBaseDisplay)
        {
            Address = address;
            DataType = dataType;
            DisplayAddress = displayAddress;
            IsProcessBaseDisplay = isProcessBaseDisplay;
            AddressHex = $"0x{address:X}";
        }

        public ulong Address { get; }
        public MemoryDataType DataType { get; }
        public string DisplayAddress { get; }
        public bool IsProcessBaseDisplay { get; }
        public string AddressHex { get; }
        public object? CurrentValue { get; private set; }
        public object? PreviousValue { get; private set; }

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

        public void SetValue(object value, string valueText)
        {
            PreviousValue = CurrentValue;
            CurrentValue = value;
            ValueText = valueText;
        }

        public void SetInvalid()
        {
            PreviousValue = CurrentValue;
            CurrentValue = null;
            ValueText = "<invalid>";
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
