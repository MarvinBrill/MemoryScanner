using MemoryScanner.Core;
using MemoryScanner.Models;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace MemoryScanner.Windows;

public partial class NearbyAddressesWindow : Window
{
    private readonly IMemoryAccessor _memoryAccessor;
    private readonly ulong _centerAddress;
    private readonly DispatcherTimer _timer;
    private readonly ICollectionView _rowsView;

    private bool _filterEnabled;
    private ScanComparison _filterComparison = ScanComparison.Equal;
    private object? _filterInput;

    private MemoryDataType _currentDataType;
    private int _entriesPerPage = 200;
    private ulong _pageStartAddress;

    public ObservableCollection<NearbyRow> Rows { get; } = new();

    public List<WatchEntry> SelectedEntries { get; private set; } = new();
    public event Action<WatchEntry>? QuickTakeRequested;

    public NearbyAddressesWindow(IMemoryAccessor memoryAccessor, ulong centerAddress, MemoryDataType initialType)
    {
        _memoryAccessor = memoryAccessor;
        _centerAddress = centerAddress;
        _currentDataType = initialType;

        InitializeComponent();

        NearbyGrid.ItemsSource = Rows;

        _rowsView = CollectionViewSource.GetDefaultView(Rows);
        _rowsView.Filter = FilterRow;

        DataTypeBox.ItemsSource = MemoryDataTypeUiOrder.Ordered;
        DataTypeBox.SelectedItem = initialType;

        FilterComparisonBox.ItemsSource = Enum.GetValues<ScanComparison>();
        FilterComparisonBox.SelectedItem = ScanComparison.Equal;

        CenterAddressText.Text = _memoryAccessor.IsAttached
            ? $"Center: {_memoryAccessor.FormatAddress(_centerAddress)}"
            : $"Center: {FormatRawAddress(_centerAddress)}";

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

    private void PrevPage_OnClick(object sender, RoutedEventArgs e)
    {
        var step = (ulong)GetTypeSize(_currentDataType);
        var span = MultiplyClamped(step, (ulong)_entriesPerPage);

        _pageStartAddress = _pageStartAddress >= span
            ? _pageStartAddress - span
            : 0;

        RebuildRows();
        RefreshValues();
    }

    private void NextPage_OnClick(object sender, RoutedEventArgs e)
    {
        var step = (ulong)GetTypeSize(_currentDataType);
        var span = MultiplyClamped(step, (ulong)_entriesPerPage);

        if (_pageStartAddress > ulong.MaxValue - span)
        {
            _pageStartAddress = ulong.MaxValue - span;
        }
        else
        {
            _pageStartAddress += span;
        }

        RebuildRows();
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
        _rowsView.Refresh();
    }

    private void ClearFilter_OnClick(object sender, RoutedEventArgs e)
    {
        _filterEnabled = false;
        _filterInput = null;
        EnableFilterBox.IsChecked = false;
        _rowsView.Refresh();
    }

    private void TakeSelected_OnClick(object sender, RoutedEventArgs e)
    {
        var selected = NearbyGrid.SelectedItems.OfType<NearbyRow>()
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

    private void NearbyGrid_OnMouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        var source = e.OriginalSource as DependencyObject;
        if (FindAncestor<DataGridColumnHeader>(source) is not null)
        {
            return;
        }

        var rowContainer = FindAncestor<DataGridRow>(source);
        if (rowContainer?.Item is not NearbyRow row)
        {
            return;
        }

        var entry = BuildWatchEntry(row);
        var selectedName = PromptForText("Add Nearby Address", "Entry name:", entry.Name);
        if (selectedName is null)
        {
            return;
        }

        entry.Name = string.IsNullOrWhiteSpace(selectedName) ? entry.Name : selectedName.Trim();
        QuickTakeRequested?.Invoke(entry);
        e.Handled = true;
    }

    private void DataGridRow_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        // Do not intercept double-clicks, otherwise NearbyGrid_OnMouseDoubleClick won't fire.
        if (e.ClickCount > 1)
        {
            return;
        }

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
        if (!TryReadSettings(out var dataType, out var entriesPerPage, out var refreshMs))
        {
            if (showMessageOnError)
            {
                MessageBox.Show(this, "Invalid settings. Check data type/page size/refresh values.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            return;
        }

        _currentDataType = dataType;
        _entriesPerPage = entriesPerPage;
        _pageStartAddress = ComputeInitialPageStart(_centerAddress, dataType, entriesPerPage);

        RebuildRows();

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

    private bool TryReadSettings(out MemoryDataType dataType, out int entriesPerPage, out int refreshMs)
    {
        dataType = MemoryDataType.Int32;
        entriesPerPage = 200;
        refreshMs = 200;

        if (DataTypeBox.SelectedItem is not MemoryDataType selectedType)
        {
            return false;
        }

        if (!int.TryParse(EntriesPerPageText.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out entriesPerPage) ||
            entriesPerPage <= 0 ||
            entriesPerPage > 200000)
        {
            return false;
        }

        if (!int.TryParse(RefreshMsText.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out refreshMs) || refreshMs < 0 || refreshMs > 60000)
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

        if (!ScanService.TryParseValue(_currentDataType, FilterValueText.Text, out var parsed))
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

    private void RebuildRows()
    {
        Rows.Clear();

        var step = (ulong)GetTypeSize(_currentDataType);
        if (step == 0)
        {
            return;
        }

        for (var i = 0; i < _entriesPerPage; i++)
        {
            var offset = MultiplyClamped(step, (ulong)i);
            if (_pageStartAddress > ulong.MaxValue - offset)
            {
                break;
            }

            var address = _pageStartAddress + offset;
            var displayAddress = FormatAddress(address);
            Rows.Add(new NearbyRow(address, _currentDataType, displayAddress, IsProcessBaseAddressText(displayAddress)));
        }

        UpdatePageInfo();
    }

    private void RefreshValues()
    {
        foreach (var row in Rows)
        {
            UpdateRowValue(row);
        }

        if (_filterEnabled)
        {
            _rowsView.Refresh();
        }
    }

    private void UpdatePageInfo()
    {
        if (Rows.Count == 0)
        {
            PageInfoText.Text = "n/a";
            PrevPageButton.IsEnabled = false;
            NextPageButton.IsEnabled = false;
            return;
        }

        var from = Rows[0].Address;
        var to = Rows[Rows.Count - 1].Address;
        PageInfoText.Text = $"{FormatRawAddress(from)} .. {FormatRawAddress(to)}";
        PrevPageButton.IsEnabled = from > 0;
        NextPageButton.IsEnabled = to < ulong.MaxValue;
    }

    private void UpdateRowValue(NearbyRow row)
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

    private bool FilterRow(object obj)
    {
        if (obj is not NearbyRow row)
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

        try
        {
            return left switch
            {
                byte b => b.CompareTo(Convert.ToByte(right, CultureInfo.InvariantCulture)),
                short s => s.CompareTo(Convert.ToInt16(right, CultureInfo.InvariantCulture)),
                int i => i.CompareTo(Convert.ToInt32(right, CultureInfo.InvariantCulture)),
                long l => l.CompareTo(Convert.ToInt64(right, CultureInfo.InvariantCulture)),
                float f => f.CompareTo(Convert.ToSingle(right, CultureInfo.InvariantCulture)),
                double d => d.CompareTo(Convert.ToDouble(right, CultureInfo.InvariantCulture)),
                _ => 0
            };
        }
        catch
        {
            return 0;
        }
    }

    private static string FormatValue(object value)
    {
        return value switch
        {
            float f => f.ToString("0.######", CultureInfo.InvariantCulture),
            double d => d.ToString("0.######", CultureInfo.InvariantCulture),
            _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty
        };
    }

    private string FormatAddress(ulong address)
    {
        return _memoryAccessor.IsAttached ? _memoryAccessor.FormatAddress(address) : FormatRawAddress(address);
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

    private static ulong ComputeInitialPageStart(ulong center, MemoryDataType dataType, int entriesPerPage)
    {
        var step = (ulong)GetTypeSize(dataType);
        if (step == 0)
        {
            return 0;
        }

        var half = (ulong)(entriesPerPage / 2);
        var backOffset = MultiplyClamped(step, half);
        return center >= backOffset ? center - backOffset : 0;
    }

    private static ulong MultiplyClamped(ulong left, ulong right)
    {
        if (left == 0 || right == 0)
        {
            return 0;
        }

        if (ulong.MaxValue / left < right)
        {
            return ulong.MaxValue;
        }

        return left * right;
    }

    private static string FormatRawAddress(ulong address)
    {
        return $"0x{address:X}";
    }

    private static int GetTypeSize(MemoryDataType dataType) => dataType switch
    {
        MemoryDataType.Byte => sizeof(byte),
        MemoryDataType.Int16 => sizeof(short),
        MemoryDataType.Int32 => sizeof(int),
        MemoryDataType.Int64 => sizeof(long),
        MemoryDataType.Float => sizeof(float),
        MemoryDataType.Double => sizeof(double),
        _ => sizeof(int)
    };

    private static List<WatchEntry> BuildWatchEntries(IEnumerable<NearbyRow> rows)
    {
        return rows.Select(BuildWatchEntry).ToList();
    }

    private static WatchEntry BuildWatchEntry(NearbyRow row)
    {
        return new WatchEntry
        {
            Name = $"Address_{row.Address:X}",
            Kind = WatchEntryKind.DirectAddress,
            DirectAddress = row.Address,
            DataType = row.DataType
        };
    }

    private string? PromptForText(string title, string label, string defaultValue)
    {
        var window = new Window
        {
            Title = title,
            Width = 420,
            Height = 180,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = this,
            ResizeMode = ResizeMode.NoResize
        };

        var root = new Grid { Margin = new Thickness(10) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var text = new TextBlock { Text = label, Margin = new Thickness(0, 0, 0, 8) };
        Grid.SetRow(text, 0);
        root.Children.Add(text);

        var input = new TextBox { Text = defaultValue, Margin = new Thickness(0, 0, 0, 12) };
        Grid.SetRow(input, 1);
        root.Children.Add(input);

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var ok = new Button { Content = "OK", Width = 90, Height = 30, Margin = new Thickness(0, 0, 8, 0), IsDefault = true };
        var cancel = new Button { Content = "Cancel", Width = 90, Height = 30, IsCancel = true };

        ok.Click += (_, _) => window.DialogResult = true;
        cancel.Click += (_, _) => window.DialogResult = false;

        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);

        Grid.SetRow(buttons, 2);
        root.Children.Add(buttons);

        window.Content = root;
        return window.ShowDialog() == true ? input.Text : null;
    }

    protected override void OnClosed(EventArgs e)
    {
        _timer.Stop();
        base.OnClosed(e);
    }

    public sealed class NearbyRow : INotifyPropertyChanged
    {
        private string _valueText = string.Empty;

        public NearbyRow(ulong address, MemoryDataType dataType, string displayAddress, bool isProcessBaseDisplay)
        {
            Address = address;
            DataType = dataType;
            DisplayAddress = displayAddress;
            IsProcessBaseDisplay = isProcessBaseDisplay;
            AddressHex = FormatRawAddress(address);
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
                if (_valueText == value)
                {
                    return;
                }

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
