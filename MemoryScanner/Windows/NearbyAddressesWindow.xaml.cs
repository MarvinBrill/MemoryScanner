using MemoryScanner.Core;
using MemoryScanner.Models;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace MemoryScanner.Windows;

public partial class NearbyAddressesWindow : Window
{
    private const string UnavailableValueText = "???";
    private const int MinNearbyRefreshBatchSize = 32;
    private const int MaxNearbyRefreshBatchSize = 512;
    private const int RelativePointerLastOffsetMaxDelta = 0x4000;
    private const int RelativePointerSecondaryOffsetMaxDelta = 0x800;
    private const int RelativePointerSecondaryStep = 4;
    private const int RelativePointerMaxResults = 256;
    private static readonly IReadOnlyList<ValueFilterConditionOption> _valueFilterOptions = new[]
    {
        new ValueFilterConditionOption(ScanComparison.Equal, "Equal"),
        new ValueFilterConditionOption(ScanComparison.NotEqual, "Not Equal"),
        new ValueFilterConditionOption(ScanComparison.Greater, "Greater"),
        new ValueFilterConditionOption(ScanComparison.Less, "Less"),
        new ValueFilterConditionOption(ScanComparison.Between, "Between")
    };

    private readonly IMemoryAccessor _memoryAccessor;
    private readonly ulong _centerAddress;
    private readonly DispatcherTimer _timer;
    private readonly string _centerDisplayText;
    private readonly bool _centerDisplayUseAccent;
    private readonly WatchEntry? _relativePointerSeed;

    private MemoryDataType _currentDataType;
    private int _entriesPerPage = 200;
    private ulong _pageStartAddress;
    private int _refreshCursor;
    private readonly List<NearbyRow> _allRows = new();
    private NearbyValueFilter? _activeFilter;

    public ObservableCollection<NearbyRow> Rows { get; } = new();

    public List<WatchEntry> SelectedEntries { get; private set; } = new();
    public event Action<WatchEntry>? QuickTakeRequested;

    public NearbyAddressesWindow(
        IMemoryAccessor memoryAccessor,
        ulong centerAddress,
        MemoryDataType initialType,
        string? centerDisplayText = null,
        bool centerDisplayUseAccent = false,
        WatchEntry? relativePointerSeed = null)
    {
        _memoryAccessor = memoryAccessor;
        _centerAddress = centerAddress;
        _currentDataType = initialType;
        _centerDisplayText = centerDisplayText ?? (_memoryAccessor.IsAttached
            ? _memoryAccessor.FormatAddress(_centerAddress)
            : FormatRawAddress(_centerAddress));
        _centerDisplayUseAccent = centerDisplayUseAccent;
        _relativePointerSeed = relativePointerSeed is not null ? ClonePointerSeed(relativePointerSeed) : null;

        InitializeComponent();

        NearbyGrid.ItemsSource = Rows;

        DataTypeBox.ItemsSource = MemoryDataTypeUiOrder.Ordered;
        DataTypeBox.SelectedItem = initialType;
        FilterConditionBox.ItemsSource = _valueFilterOptions;
        FilterConditionBox.SelectedItem = _valueFilterOptions.FirstOrDefault(x => x.Value == ScanComparison.Equal) ?? _valueFilterOptions.First();

        CenterAddressValueText.Text = _centerDisplayText;
        CenterAddressValueText.Foreground = _centerDisplayUseAccent
            ? new SolidColorBrush(Color.FromRgb(0x4C, 0xD9, 0x64))
             : Brushes.Black;
        RelativePointerScanMenuItem.IsEnabled = _relativePointerSeed is not null;

        _timer = new DispatcherTimer();
        _timer.Tick += Timer_OnTick;

        UiUpdateRoutineSettings.ValueRefreshIntervalChanged += OnGlobalValueRefreshIntervalChanged;

        UpdateFilterInputUi();
        UpdateFilterUiForDataType();
        UpdateFilterStatusText();
        ApplySettings(showMessageOnError: false);
    }

    private void Apply_OnClick(object sender, RoutedEventArgs e)
    {
        ApplySettings(showMessageOnError: true);
    }

    private void DataTypeBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateFilterUiForDataType();
    }

    private void FilterConditionBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateFilterInputUi();
    }

    private void ApplyFilter_OnClick(object sender, RoutedEventArgs e)
    {
        var selectedType = DataTypeBox.SelectedItem is MemoryDataType dataType ? dataType : _currentDataType;
        if (selectedType != _currentDataType)
        {
            MessageBox.Show(this, "Apply Data Type/Page settings first, then apply the filter.", "Filter", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var effectiveType = _currentDataType;
        if (effectiveType == MemoryDataType.String)
        {
            MessageBox.Show(this, "Value filter is currently disabled for String.", "Filter", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (!TryCreateValueFilter(effectiveType, out var filter))
        {
            return;
        }

        _activeFilter = filter;
        ApplyFilterToVisibleRows();
        UpdateFilterStatusText();
        RefreshVisibleRowsOnly();
    }

    private void ClearFilter_OnClick(object sender, RoutedEventArgs e)
    {
        _activeFilter = null;
        ApplyFilterToVisibleRows();
        UpdateFilterStatusText();
        RefreshVisibleRowsOnly();
    }

    private void NearbyGrid_OnScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        if (Math.Abs(e.VerticalChange) < double.Epsilon && Math.Abs(e.ViewportHeightChange) < double.Epsilon)
        {
            return;
        }

        RefreshVisibleRowsOnly();
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
    private async void FindPointerRouteForSelectedAddress_OnClick(object sender, RoutedEventArgs e)
    {
        if (_relativePointerSeed is null)
        {
            MessageBox.Show(this, "This action is only available when Nearby Addresses was opened from a pointer entry.", "Pointer Context Required", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (!_memoryAccessor.IsAttached)
        {
            MessageBox.Show(this, "Select a process first.", "No Process", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (NearbyGrid.SelectedItem is not NearbyRow selectedRow)
        {
            MessageBox.Show(this, "Select a target row first.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var options = ShowRelativePointerRouteOptionsDialog(selectedRow.Address);
        if (options is null)
        {
            return;
        }

        RelativePointerScanMenuItem.IsEnabled = false;
        var previousCursor = Mouse.OverrideCursor;
        Mouse.OverrideCursor = Cursors.Wait;

        List<RelativePointerCandidate> candidates;
        try
        {
            candidates = await Task.Run(() => FindRelativePointerCandidates(selectedRow.Address, options));
        }
        finally
        {
            Mouse.OverrideCursor = previousCursor;
            RelativePointerScanMenuItem.IsEnabled = _relativePointerSeed is not null;
        }

        if (candidates.Count == 0)
        {
            MessageBox.Show(this, "No matching pointer route found for the selected address with the nearby brute-force strategy.", "No Pointer Route", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var chosen = ShowPointerCandidatePicker(candidates);
        if (chosen is null)
        {
            return;
        }

        var entry = BuildWatchEntryFromRelativePointerCandidate(chosen, selectedRow.DataType);
        var selectedName = PromptForText("Take Pointer Route", "Entry name:", entry.Name);
        if (selectedName is null)
        {
            return;
        }

        entry.Name = string.IsNullOrWhiteSpace(selectedName) ? entry.Name : selectedName.Trim();
        QuickTakeRequested?.Invoke(entry);
    }

    private void DataGridRow_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (sender is not DataGridRow row)
        {
            return;
        }

        if (!row.IsSelected)
        {
            row.IsSelected = true;
        }

        NearbyGrid.SelectedItem = row.Item;
        NearbyGrid.CurrentItem = row.Item;
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

    private static T? FindDescendant<T>(DependencyObject? root) where T : DependencyObject
    {
        if (root is null)
        {
            return null;
        }

        var childCount = VisualTreeHelper.GetChildrenCount(root);
        for (var i = 0; i < childCount; i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is T match)
            {
                return match;
            }

            var nested = FindDescendant<T>(child);
            if (nested is not null)
            {
                return nested;
            }
        }

        return null;
    }

    private void Timer_OnTick(object? sender, EventArgs e)
    {
        RefreshValues();
    }

    private void OnGlobalValueRefreshIntervalChanged(object? sender, int milliseconds)
    {
        _ = Dispatcher.InvokeAsync(() =>
        {
            ApplyGlobalValueRefreshInterval(milliseconds);
            RefreshValues();
        });
    }

    private void ApplyGlobalValueRefreshInterval(int milliseconds)
    {
        var intervalMs = milliseconds < 1 ? UiUpdateRoutineSettings.DefaultIntervalMs : milliseconds;
        _timer.Interval = TimeSpan.FromMilliseconds(intervalMs);
        if (!_timer.IsEnabled)
        {
            _timer.Start();
        }
    }

    private void ApplySettings(bool showMessageOnError)
    {
        if (!TryReadSettings(out var dataType, out var entriesPerPage))
        {
            if (showMessageOnError)
            {
                MessageBox.Show(this, "Invalid settings. Check data type and page size.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            return;
        }

        _currentDataType = dataType;
        _entriesPerPage = entriesPerPage;
        _pageStartAddress = ComputeInitialPageStart(_centerAddress, dataType, entriesPerPage);
        if (_activeFilter is not null && (_activeFilter.DataType != dataType || dataType == MemoryDataType.String))
        {
            _activeFilter = null;
        }

        RebuildRows();
        ApplyGlobalValueRefreshInterval(UiUpdateRoutineSettings.ValueRefreshIntervalMs);
        UpdateFilterUiForDataType();
        UpdateFilterStatusText();
        RefreshValues();
    }

    private bool TryReadSettings(out MemoryDataType dataType, out int entriesPerPage)
    {
        dataType = MemoryDataType.Int32;
        entriesPerPage = 200;

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

        dataType = selectedType;
        return true;
    }

    private void UpdateFilterInputUi()
    {
        var selectedType = DataTypeBox.SelectedItem is MemoryDataType dataType ? dataType : _currentDataType;
        var showRange = FilterConditionBox.SelectedItem is ValueFilterConditionOption option &&
                        option.Value == ScanComparison.Between &&
                        selectedType != MemoryDataType.String;

        FilterToLabelText.Visibility = showRange ? Visibility.Visible : Visibility.Collapsed;
        FilterValueToText.Visibility = showRange ? Visibility.Visible : Visibility.Collapsed;
    }

    private void UpdateFilterUiForDataType()
    {
        var selectedType = DataTypeBox.SelectedItem is MemoryDataType dataType
            ? dataType
            : _currentDataType;
        var enabled = selectedType != MemoryDataType.String;

        FilterConditionBox.IsEnabled = enabled;
        FilterValueText.IsEnabled = enabled;
        FilterValueToText.IsEnabled = enabled;
        ApplyFilterButton.IsEnabled = enabled;
        ClearFilterButton.IsEnabled = enabled && _activeFilter is not null;

        if (!enabled && _activeFilter is not null)
        {
            _activeFilter = null;
            ApplyFilterToVisibleRows();
        }

        UpdateFilterInputUi();
        UpdateFilterStatusText();
    }

    private void UpdateFilterStatusText()
    {
        ClearFilterButton.IsEnabled = _currentDataType != MemoryDataType.String && _activeFilter is not null;

        if (_currentDataType == MemoryDataType.String)
        {
            FilterStatusText.Text = "Filter: Off (String not supported)";
            return;
        }

        if (_activeFilter is null)
        {
            FilterStatusText.Text = $"Filter: Off ({Rows.Count}/{_allRows.Count})";
            return;
        }

        FilterStatusText.Text = $"Filter: {_activeFilter.DisplayText} ({Rows.Count}/{_allRows.Count})";
    }

    private bool TryCreateValueFilter(MemoryDataType dataType, out NearbyValueFilter filter)
    {
        filter = default!;

        if (FilterConditionBox.SelectedItem is not ValueFilterConditionOption option)
        {
            MessageBox.Show(this, "Select a filter condition.", "Filter", MessageBoxButton.OK, MessageBoxImage.Information);
            return false;
        }

        var comparison = option.Value;
        if (!ScanService.TryParseValue(dataType, FilterValueText.Text, out var parsedValue))
        {
            MessageBox.Show(this, "Enter a valid filter value.", "Filter", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        object? parsedValueTo = null;
        if (comparison == ScanComparison.Between)
        {
            if (!ScanService.TryParseValue(dataType, FilterValueToText.Text, out parsedValueTo))
            {
                MessageBox.Show(this, "Enter a valid upper value for range filter.", "Filter", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
        }

        filter = new NearbyValueFilter(
            dataType,
            comparison,
            parsedValue,
            parsedValueTo,
            comparison == ScanComparison.Between
                ? $"{option.Label} {FormatValue(parsedValue)} .. {FormatValue(parsedValueTo!)}"
                : $"{option.Label} {FormatValue(parsedValue)}");
        return true;
    }

    private void ApplyFilterToVisibleRows()
    {
        var selectedAddresses = NearbyGrid.SelectedItems.OfType<NearbyRow>().Select(x => x.Address).ToHashSet();
        var currentAddress = (NearbyGrid.CurrentItem as NearbyRow)?.Address;

        Rows.Clear();
        IEnumerable<NearbyRow> source = _allRows;
        if (_activeFilter is not null && _currentDataType != MemoryDataType.String)
        {
            source = source.Where(MatchesActiveFilter);
        }

        foreach (var row in source)
        {
            Rows.Add(row);
        }

        _refreshCursor = 0;
        RestoreSelection(selectedAddresses, currentAddress);
        UpdatePageInfo();
    }

    private bool MatchesActiveFilter(NearbyRow row)
    {
        if (_activeFilter is null)
        {
            return true;
        }

        if (row.CurrentValue is null)
        {
            UpdateRowValue(row);
        }

        if (row.CurrentValue is null)
        {
            return false;
        }

        if (!TryCompareValuesByType(row.CurrentValue, _activeFilter.Value, _activeFilter.DataType, out var order))
        {
            return false;
        }

        return _activeFilter.Comparison switch
        {
            ScanComparison.Equal => order == 0,
            ScanComparison.NotEqual => order != 0,
            ScanComparison.Greater => order > 0,
            ScanComparison.Less => order < 0,
            ScanComparison.Between => MatchesBetweenFilter(row.CurrentValue, _activeFilter),
            _ => true
        };
    }

    private static bool MatchesBetweenFilter(object currentValue, NearbyValueFilter filter)
    {
        if (filter.ValueTo is null)
        {
            return false;
        }

        if (!TryCompareValuesByType(currentValue, filter.Value, filter.DataType, out var first) ||
            !TryCompareValuesByType(currentValue, filter.ValueTo, filter.DataType, out var second))
        {
            return false;
        }

        if (!TryCompareValuesByType(filter.Value, filter.ValueTo, filter.DataType, out var boundaryOrder))
        {
            return false;
        }

        if (boundaryOrder <= 0)
        {
            return first >= 0 && second <= 0;
        }

        return second >= 0 && first <= 0;
    }

    private static bool TryCompareValuesByType(object leftValue, object rightValue, MemoryDataType dataType, out int order)
    {
        order = 0;

        try
        {
            switch (dataType)
            {
                case MemoryDataType.Byte:
                    order = Convert.ToByte(leftValue, CultureInfo.InvariantCulture)
                        .CompareTo(Convert.ToByte(rightValue, CultureInfo.InvariantCulture));
                    return true;
                case MemoryDataType.Int16:
                    order = Convert.ToInt16(leftValue, CultureInfo.InvariantCulture)
                        .CompareTo(Convert.ToInt16(rightValue, CultureInfo.InvariantCulture));
                    return true;
                case MemoryDataType.Int32:
                    order = Convert.ToInt32(leftValue, CultureInfo.InvariantCulture)
                        .CompareTo(Convert.ToInt32(rightValue, CultureInfo.InvariantCulture));
                    return true;
                case MemoryDataType.Int64:
                    order = Convert.ToInt64(leftValue, CultureInfo.InvariantCulture)
                        .CompareTo(Convert.ToInt64(rightValue, CultureInfo.InvariantCulture));
                    return true;
                case MemoryDataType.Float:
                    order = Convert.ToSingle(leftValue, CultureInfo.InvariantCulture)
                        .CompareTo(Convert.ToSingle(rightValue, CultureInfo.InvariantCulture));
                    return true;
                case MemoryDataType.Double:
                    order = Convert.ToDouble(leftValue, CultureInfo.InvariantCulture)
                        .CompareTo(Convert.ToDouble(rightValue, CultureInfo.InvariantCulture));
                    return true;
                default:
                    return false;
            }
        }
        catch
        {
            return false;
        }
    }

    private void RestoreSelection(HashSet<ulong> selectedAddresses, ulong? currentAddress)
    {
        if (selectedAddresses.Count == 0 && currentAddress is null)
        {
            return;
        }

        NearbyGrid.SelectedItems.Clear();
        NearbyRow? currentRow = null;

        foreach (var row in Rows)
        {
            if (selectedAddresses.Contains(row.Address))
            {
                NearbyGrid.SelectedItems.Add(row);
            }

            if (currentAddress.HasValue && row.Address == currentAddress.Value)
            {
                currentRow = row;
            }
        }

        if (currentRow is not null)
        {
            NearbyGrid.CurrentItem = currentRow;
        }
        else if (NearbyGrid.SelectedItems.Count > 0)
        {
            NearbyGrid.CurrentItem = NearbyGrid.SelectedItems[0];
        }
    }

    private void RefreshVisibleRowsOnly()
    {
        foreach (var row in GetVisibleRows())
        {
            UpdateRowValue(row);
        }
    }

    private IReadOnlyList<NearbyRow> GetVisibleRows()
    {
        if (Rows.Count == 0)
        {
            return Array.Empty<NearbyRow>();
        }

        var scrollViewer = FindDescendant<ScrollViewer>(NearbyGrid);
        if (scrollViewer is null)
        {
            return Rows;
        }

        var rowHeight = NearbyGrid.RowHeight;
        if (double.IsNaN(rowHeight) || rowHeight <= 0)
        {
            rowHeight = 22d;
        }

        int startIndex;
        int visibleCount;

        if (scrollViewer.CanContentScroll)
        {
            startIndex = (int)Math.Floor(scrollViewer.VerticalOffset);
            visibleCount = (int)Math.Ceiling(scrollViewer.ViewportHeight) + 2;
        }
        else
        {
            startIndex = (int)Math.Floor(scrollViewer.VerticalOffset / rowHeight);
            visibleCount = (int)Math.Ceiling(scrollViewer.ViewportHeight / rowHeight) + 2;
        }

        if (startIndex < 0)
        {
            startIndex = 0;
        }

        if (startIndex >= Rows.Count)
        {
            startIndex = Rows.Count - 1;
        }

        visibleCount = Math.Max(1, visibleCount);
        var count = Math.Min(visibleCount, Rows.Count - startIndex);
        if (count <= 0)
        {
            return Array.Empty<NearbyRow>();
        }

        var visible = new List<NearbyRow>(count);
        for (var i = 0; i < count; i++)
        {
            visible.Add(Rows[startIndex + i]);
        }

        return visible;
    }

    private void RebuildRows()
    {
        _allRows.Clear();

        var step = (ulong)GetTypeSize(_currentDataType);
        if (step == 0)
        {
            Rows.Clear();
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
            _allRows.Add(new NearbyRow(
                address,
                _currentDataType,
                displayAddress,
                IsProcessBaseAddressText(displayAddress),
                address == _centerAddress));
        }

        _refreshCursor = 0;
        ApplyFilterToVisibleRows();
        UpdatePageInfo();
        UpdateFilterStatusText();
        ScrollToCenterAddressRow();
    }

    private void RefreshValues()
    {
        if (_allRows.Count == 0)
        {
            return;
        }

        var visibleRows = GetVisibleRows();
        HashSet<NearbyRow>? visibleSet = null;
        if (visibleRows.Count > 0)
        {
            visibleSet = new HashSet<NearbyRow>();
            foreach (var row in visibleRows)
            {
                UpdateRowValue(row);
                visibleSet.Add(row);
            }
        }

        var batchSize = Math.Clamp(_allRows.Count / 20, MinNearbyRefreshBatchSize, MaxNearbyRefreshBatchSize);
        var scanned = 0;
        var processed = 0;

        while (processed < batchSize && scanned < _allRows.Count)
        {
            if (_refreshCursor >= _allRows.Count)
            {
                _refreshCursor = 0;
            }

            var row = _allRows[_refreshCursor++];
            scanned++;

            if (visibleSet is not null && visibleSet.Contains(row))
            {
                continue;
            }

            UpdateRowValue(row);
            processed++;
        }
    }

    private void UpdatePageInfo()
    {
        if (_allRows.Count == 0)
        {
            PageInfoText.Text = "n/a";
            PrevPageButton.IsEnabled = false;
            NextPageButton.IsEnabled = false;
            return;
        }

        var from = _allRows[0].Address;
        var to = _allRows[_allRows.Count - 1].Address;
        PageInfoText.Text = $"{FormatRawAddress(from)} .. {FormatRawAddress(to)}";
        PrevPageButton.IsEnabled = from > 0;
        NextPageButton.IsEnabled = to < ulong.MaxValue;
    }

    private void ScrollToCenterAddressRow()
    {
        var centerRow = Rows.FirstOrDefault(x => x.IsCenterRow);
        if (centerRow is null)
        {
            return;
        }

        NearbyGrid.SelectedItem = centerRow;

        _ = Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(() =>
        {
            CenterRowInViewport(centerRow);

            // Second pass: DataGrid can still adjust scroll position after first layout.
            _ = Dispatcher.BeginInvoke(DispatcherPriority.ContextIdle, new Action(() => CenterRowInViewport(centerRow)));
        }));
    }

    private void CenterRowInViewport(NearbyRow centerRow)
    {
        NearbyGrid.ScrollIntoView(centerRow);
        NearbyGrid.UpdateLayout();

        var scrollViewer = FindDescendant<ScrollViewer>(NearbyGrid);
        if (scrollViewer is null)
        {
            return;
        }

        var index = Rows.IndexOf(centerRow);
        if (index < 0)
        {
            return;
        }

        var visibleRows = EstimateVisibleRows(scrollViewer, centerRow);
        var targetOffset = Math.Max(0d, index - ((visibleRows - 1d) / 2d));
        scrollViewer.ScrollToVerticalOffset(targetOffset);
    }

    private double EstimateVisibleRows(ScrollViewer scrollViewer, NearbyRow centerRow)
    {
        if (scrollViewer.CanContentScroll)
        {
            // Item-based scrolling: ViewportHeight already represents item units.
            return Math.Max(1d, scrollViewer.ViewportHeight);
        }

        var rowHeight = NearbyGrid.RowHeight;
        if (double.IsNaN(rowHeight) || rowHeight <= 0)
        {
            if (NearbyGrid.ItemContainerGenerator.ContainerFromItem(centerRow) is DataGridRow rowContainer && rowContainer.ActualHeight > 0)
            {
                rowHeight = rowContainer.ActualHeight;
            }
            else
            {
                rowHeight = 22d;
            }
        }

        return Math.Max(1d, scrollViewer.ViewportHeight / rowHeight);
    }

    private void UpdateRowValue(NearbyRow row)
    {
        if (!_memoryAccessor.IsAttached)
        {
            row.SetUnavailable(UnavailableValueText);
            return;
        }

        if (_memoryAccessor.TryReadValue(row.Address, row.DataType, out var value))
        {
            row.SetValue(value, FormatValue(value));
        }
        else
        {
            row.SetInvalid();
        }
    }

    private RelativePointerRouteRuntimeOptions? ShowRelativePointerRouteOptionsDialog(ulong targetAddress)
    {
        var defaults = BuildDefaultRouteOptions(targetAddress);

        var dialog = new Window
        {
            Title = "Relative Pointer Route Options",
            Width = 600,
            Height = 520,
            Owner = this,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.NoResize
        };

        var root = new Grid { Margin = new Thickness(12) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var info = new TextBlock
        {
            Text = "Options for local brute-force around the current pointer chain. Auto range adapts to distance between center and selected address.",
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 10)
        };
        Grid.SetRow(info, 0);
        root.Children.Add(info);

        var form = new Grid();
        form.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(250) });
        form.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        for (var i = 0; i < 9; i++)
        {
            form.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        }

        var autoRangeCheck = new CheckBox { Content = "Use automatic ranges (by address distance)", IsChecked = defaults.UseAutoRange, Margin = new Thickness(0, 0, 0, 8) };
        Grid.SetRow(autoRangeCheck, 0);
        Grid.SetColumnSpan(autoRangeCheck, 2);
        form.Children.Add(autoRangeCheck);

        var distanceLabel = new TextBlock { Text = $"Distance to center: 0x{ComputeAddressDistance(_centerAddress, targetAddress):X}", Margin = new Thickness(0, 0, 0, 8), Foreground = Brushes.DimGray };
        Grid.SetRow(distanceLabel, 1);
        Grid.SetColumnSpan(distanceLabel, 2);
        form.Children.Add(distanceLabel);

        AddFormRow(form, 2, "Secondary sweep range (hex/dec):", out var secondaryRangeBox, defaults.SecondaryOffsetSweepRange.ToString(CultureInfo.InvariantCulture));
        AddFormRow(form, 3, "Last-offset max delta (hex/dec):", out var lastDeltaBox, defaults.LastOffsetMaxDelta.ToString(CultureInfo.InvariantCulture));
        AddFormRow(form, 4, "Secondary offset step:", out var stepBox, defaults.SecondaryOffsetStep.ToString(CultureInfo.InvariantCulture));
        AddFormRow(form, 5, "Max results:", out var maxResultsBox, defaults.MaxResults.ToString(CultureInfo.InvariantCulture));
        AddFormRow(form, 6, "Max runtime (ms, 0 = unlimited):", out var maxRuntimeBox, defaults.MaxRuntimeMs.ToString(CultureInfo.InvariantCulture));

        var enableSecondaryCheck = new CheckBox { Content = "Enable secondary sweep stage", IsChecked = defaults.EnableSecondarySweep, Margin = new Thickness(0, 4, 0, 0) };
        Grid.SetRow(enableSecondaryCheck, 7);
        Grid.SetColumnSpan(enableSecondaryCheck, 2);
        form.Children.Add(enableSecondaryCheck);

        var stopOnFirstCheck = new CheckBox { Content = "Stop when first hit is found", IsChecked = defaults.StopOnFirstHit, Margin = new Thickness(0, 4, 0, 0) };
        Grid.SetRow(stopOnFirstCheck, 8);
        Grid.SetColumnSpan(stopOnFirstCheck, 2);
        form.Children.Add(stopOnFirstCheck);

        Grid.SetRow(form, 1);
        root.Children.Add(form);

        RelativePointerRouteRuntimeOptions? selectedOptions = null;
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 10, 0, 0) };
        var startButton = new Button { Content = "Start", Width = 100, Height = 30, Margin = new Thickness(0, 0, 8, 0), IsDefault = true };
        var cancelButton = new Button { Content = "Cancel", Width = 100, Height = 30, IsCancel = true };

        void ApplyAutoRangeUiState()
        {
            var useAuto = autoRangeCheck.IsChecked == true;
            secondaryRangeBox.IsEnabled = !useAuto;
            lastDeltaBox.IsEnabled = !useAuto;
        }

        autoRangeCheck.Checked += (_, _) => ApplyAutoRangeUiState();
        autoRangeCheck.Unchecked += (_, _) => ApplyAutoRangeUiState();
        ApplyAutoRangeUiState();

        startButton.Click += (_, _) =>
        {
            if (!TryReadRouteOptions(
                    targetAddress,
                    autoRangeCheck.IsChecked == true,
                    secondaryRangeBox.Text,
                    lastDeltaBox.Text,
                    stepBox.Text,
                    maxResultsBox.Text,
                    maxRuntimeBox.Text,
                    enableSecondaryCheck.IsChecked == true,
                    stopOnFirstCheck.IsChecked == true,
                    out var parsed,
                    out var error))
            {
                MessageBox.Show(dialog, error, "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            selectedOptions = parsed;
            dialog.DialogResult = true;
        };

        cancelButton.Click += (_, _) => dialog.DialogResult = false;
        buttons.Children.Add(startButton);
        buttons.Children.Add(cancelButton);

        Grid.SetRow(buttons, 2);
        root.Children.Add(buttons);

        dialog.Content = root;
        return dialog.ShowDialog() == true ? selectedOptions : null;
    }

    private static void AddFormRow(Grid grid, int rowIndex, string label, out TextBox textBox, string initialValue)
    {
        var text = new TextBlock { Text = label, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 8) };
        Grid.SetRow(text, rowIndex);
        Grid.SetColumn(text, 0);
        grid.Children.Add(text);

        textBox = new TextBox { Text = initialValue, Margin = new Thickness(0, 0, 0, 8), VerticalContentAlignment = VerticalAlignment.Center };
        Grid.SetRow(textBox, rowIndex);
        Grid.SetColumn(textBox, 1);
        grid.Children.Add(textBox);
    }

    private RelativePointerRouteRuntimeOptions BuildDefaultRouteOptions(ulong targetAddress)
    {
        var distance = ComputeAddressDistance(_centerAddress, targetAddress);
        return BuildRuntimeRouteOptions(new RelativePointerRouteOptions
        {
            UseAutoRange = true,
            SecondaryOffsetSweepRange = RelativePointerSecondaryOffsetMaxDelta,
            LastOffsetMaxDelta = RelativePointerLastOffsetMaxDelta,
            SecondaryOffsetStep = RelativePointerSecondaryStep,
            MaxResults = RelativePointerMaxResults,
            MaxRuntimeMs = 0,
            EnableSecondarySweep = true,
            StopOnFirstHit = false
        }, distance);
    }

    private bool TryReadRouteOptions(
        ulong targetAddress,
        bool useAutoRange,
        string secondaryRangeText,
        string lastDeltaText,
        string stepText,
        string maxResultsText,
        string maxRuntimeText,
        bool enableSecondarySweep,
        bool stopOnFirstHit,
        out RelativePointerRouteRuntimeOptions options,
        out string error)
    {
        options = BuildDefaultRouteOptions(targetAddress);
        error = string.Empty;

        if (!TryParseIntFlexible(stepText, out var step) || step <= 0)
        {
            error = "Secondary offset step must be a positive integer.";
            return false;
        }

        if (!TryParseIntFlexible(maxResultsText, out var maxResults) || maxResults <= 0)
        {
            error = "Max results must be greater than 0.";
            return false;
        }

        if (!TryParseIntFlexible(maxRuntimeText, out var maxRuntime) || maxRuntime < 0)
        {
            error = "Max runtime must be 0 or greater.";
            return false;
        }

        var distance = ComputeAddressDistance(_centerAddress, targetAddress);
        var source = new RelativePointerRouteOptions
        {
            UseAutoRange = useAutoRange,
            SecondaryOffsetSweepRange = RelativePointerSecondaryOffsetMaxDelta,
            LastOffsetMaxDelta = RelativePointerLastOffsetMaxDelta,
            SecondaryOffsetStep = step,
            MaxResults = maxResults,
            MaxRuntimeMs = maxRuntime,
            EnableSecondarySweep = enableSecondarySweep,
            StopOnFirstHit = stopOnFirstHit
        };

        if (!useAutoRange)
        {
            if (!TryParseIntFlexible(secondaryRangeText, out var secondaryRange) || secondaryRange < 0)
            {
                error = "Secondary sweep range must be 0 or greater.";
                return false;
            }

            if (!TryParseIntFlexible(lastDeltaText, out var lastDelta) || lastDelta < 0)
            {
                error = "Last-offset max delta must be 0 or greater.";
                return false;
            }

            source.SecondaryOffsetSweepRange = secondaryRange;
            source.LastOffsetMaxDelta = lastDelta;
        }

        options = BuildRuntimeRouteOptions(source, distance);
        return true;
    }

    private static RelativePointerRouteRuntimeOptions BuildRuntimeRouteOptions(RelativePointerRouteOptions source, ulong distance)
    {
        var step = Math.Max(1, source.SecondaryOffsetStep);

        var secondaryRange = source.SecondaryOffsetSweepRange;
        var lastDelta = source.LastOffsetMaxDelta;

        if (source.UseAutoRange)
        {
            var dist = distance > int.MaxValue ? int.MaxValue : (int)distance;
            secondaryRange = Clamp(dist / 2 + 0x200, 0x200, 0x20000);
            lastDelta = Clamp(dist + 0x1000, 0x400, 0x40000);
        }

        secondaryRange = AlignUp(secondaryRange, step);
        lastDelta = Math.Max(0, AlignUp(lastDelta, step));

        return new RelativePointerRouteRuntimeOptions
        {
            UseAutoRange = source.UseAutoRange,
            SecondaryOffsetSweepRange = Math.Max(0, secondaryRange),
            LastOffsetMaxDelta = Math.Max(0, lastDelta),
            SecondaryOffsetStep = step,
            MaxResults = Math.Max(1, source.MaxResults),
            MaxRuntimeMs = Math.Max(0, source.MaxRuntimeMs),
            EnableSecondarySweep = source.EnableSecondarySweep,
            StopOnFirstHit = source.StopOnFirstHit
        };
    }

    private static bool TryParseIntFlexible(string text, out int value)
    {
        text = (text ?? string.Empty).Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return int.TryParse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
        }

        return int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private static int AlignUp(int value, int alignment)
    {
        if (alignment <= 1)
        {
            return value;
        }

        if (value <= 0)
        {
            return 0;
        }

        var remainder = value % alignment;
        return remainder == 0 ? value : value + (alignment - remainder);
    }

    private static int Clamp(int value, int min, int max)
    {
        if (value < min)
        {
            return min;
        }

        if (value > max)
        {
            return max;
        }

        return value;
    }

    private static ulong ComputeAddressDistance(ulong left, ulong right)
    {
        return left >= right ? left - right : right - left;
    }

    private List<RelativePointerCandidate> FindRelativePointerCandidates(ulong targetAddress, RelativePointerRouteRuntimeOptions options)
    {
        var resultsByKey = new Dictionary<string, RelativePointerCandidate>(StringComparer.Ordinal);
        var timer = Stopwatch.StartNew();

        if (_relativePointerSeed is null)
        {
            return new List<RelativePointerCandidate>();
        }

        var originalOffsets = _relativePointerSeed.Offsets.ToArray();
        if (originalOffsets.Length == 0)
        {
            return new List<RelativePointerCandidate>();
        }

        var pointerBaseAddress = ResolvePointerBaseAddress(_relativePointerSeed);
        var pointerSizeBytes = ResolvePointerSizeBytes(_relativePointerSeed.PointerSizeBytes);
        var baseText = FormatPointerSeedBase(_relativePointerSeed, pointerBaseAddress);

        bool ShouldStop()
        {
            if (resultsByKey.Count >= options.MaxResults)
            {
                return true;
            }

            return options.MaxRuntimeMs > 0 && timer.ElapsedMilliseconds >= options.MaxRuntimeMs;
        }

        void TryAddCandidate(IReadOnlyList<int> candidateOffsets)
        {
            if (ShouldStop())
            {
                return;
            }

            if (!TryResolvePointerChain(pointerBaseAddress, pointerSizeBytes, candidateOffsets, out var resolvedAddress))
            {
                return;
            }

            if (resolvedAddress != targetAddress)
            {
                return;
            }

            var key = string.Join(",", candidateOffsets);
            if (resultsByKey.ContainsKey(key))
            {
                return;
            }

            var score = ComputeDeviationScore(originalOffsets, candidateOffsets);
            var expression = BuildPointerExpression(baseText, candidateOffsets);
            var valueText = _memoryAccessor.TryReadValue(resolvedAddress, _currentDataType, out var value)
                ? FormatValue(value)
                : "<invalid>";

            resultsByKey[key] = new RelativePointerCandidate(candidateOffsets.ToArray(), resolvedAddress, expression, valueText, score);
        }

        if (TryReadLastStagePointerValue(pointerBaseAddress, pointerSizeBytes, originalOffsets, out var lastStagePointerValue) &&
            TryComputeRequiredOffset(lastStagePointerValue, targetAddress, out var requiredLastOffset))
        {
            var candidate = (int[])originalOffsets.Clone();
            candidate[^1] = requiredLastOffset;
            TryAddCandidate(candidate);
            if (options.StopOnFirstHit && resultsByKey.Count > 0)
            {
                return resultsByKey.Values
                    .OrderBy(x => x.Score)
                    .ThenBy(x => x.Expression, StringComparer.Ordinal)
                    .ToList();
            }
        }

        if (options.EnableSecondarySweep && originalOffsets.Length >= 2)
        {
            var baseCandidate = (int[])originalOffsets.Clone();
            for (var delta = -options.SecondaryOffsetSweepRange; delta <= options.SecondaryOffsetSweepRange; delta += options.SecondaryOffsetStep)
            {
                if (ShouldStop())
                {
                    break;
                }

                if (!TryAddDelta(originalOffsets[^2], delta, out var secondLastOffset))
                {
                    continue;
                }

                baseCandidate[^2] = secondLastOffset;

                if (!TryReadLastStagePointerValue(pointerBaseAddress, pointerSizeBytes, baseCandidate, out var adjustedLastStagePointerValue))
                {
                    continue;
                }

                if (!TryComputeRequiredOffset(adjustedLastStagePointerValue, targetAddress, out var adjustedLastOffset))
                {
                    continue;
                }

                var candidate = (int[])baseCandidate.Clone();
                candidate[^1] = adjustedLastOffset;

                if (Math.Abs((long)candidate[^1] - originalOffsets[^1]) > options.LastOffsetMaxDelta)
                {
                    continue;
                }

                TryAddCandidate(candidate);
                if (options.StopOnFirstHit && resultsByKey.Count > 0)
                {
                    break;
                }
            }
        }

        return resultsByKey.Values
            .OrderBy(x => x.Score)
            .ThenBy(x => x.Expression, StringComparer.Ordinal)
            .ToList();
    }

    private bool TryReadLastStagePointerValue(ulong pointerBaseAddress, int pointerSizeBytes, IReadOnlyList<int> offsets, out ulong pointerValue)
    {
        pointerValue = 0;

        if (offsets.Count == 0)
        {
            return false;
        }

        var stepsBeforeLastRead = offsets.Count - 1;
        if (!TryTraversePointerPrefix(pointerBaseAddress, pointerSizeBytes, offsets, stepsBeforeLastRead, out var lastReadAddress))
        {
            return false;
        }

        return TryReadPointerValue(lastReadAddress, pointerSizeBytes, out pointerValue);
    }

    private bool TryResolvePointerChain(ulong pointerBaseAddress, int pointerSizeBytes, IReadOnlyList<int> offsets, out ulong finalAddress)
    {
        finalAddress = pointerBaseAddress;
        if (offsets.Count == 0)
        {
            return true;
        }

        var current = pointerBaseAddress;
        for (var i = 0; i < offsets.Count; i++)
        {
            if (!TryReadPointerValue(current, pointerSizeBytes, out var pointerValue))
            {
                return false;
            }

            if (!TryAddSignedOffset(pointerValue, offsets[i], out current))
            {
                return false;
            }

            if (pointerSizeBytes == 4 && current > uint.MaxValue)
            {
                return false;
            }
        }

        finalAddress = current;
        return true;
    }

    private bool TryTraversePointerPrefix(ulong pointerBaseAddress, int pointerSizeBytes, IReadOnlyList<int> offsets, int steps, out ulong currentAddress)
    {
        currentAddress = pointerBaseAddress;

        if (steps <= 0)
        {
            return true;
        }

        if (steps > offsets.Count)
        {
            return false;
        }

        var current = pointerBaseAddress;
        for (var i = 0; i < steps; i++)
        {
            if (!TryReadPointerValue(current, pointerSizeBytes, out var pointerValue))
            {
                return false;
            }

            if (!TryAddSignedOffset(pointerValue, offsets[i], out current))
            {
                return false;
            }

            if (pointerSizeBytes == 4 && current > uint.MaxValue)
            {
                return false;
            }
        }

        currentAddress = current;
        return true;
    }

    private bool TryReadPointerValue(ulong address, int pointerSizeBytes, out ulong pointerValue)
    {
        pointerValue = 0;

        if (!_memoryAccessor.TryReadBytes(address, pointerSizeBytes, out var data) || data.Length < pointerSizeBytes)
        {
            return false;
        }

        pointerValue = pointerSizeBytes == 4
            ? BitConverter.ToUInt32(data, 0)
            : BitConverter.ToUInt64(data, 0);

        return true;
    }

    private static bool TryAddSignedOffset(ulong value, int offset, out ulong result)
    {
        if (offset >= 0)
        {
            var positive = (ulong)offset;
            if (value > ulong.MaxValue - positive)
            {
                result = 0;
                return false;
            }

            result = value + positive;
            return true;
        }

        var negative = (ulong)(-(long)offset);
        if (value < negative)
        {
            result = 0;
            return false;
        }

        result = value - negative;
        return true;
    }

    private static bool TryComputeRequiredOffset(ulong pointerValue, ulong targetAddress, out int offset)
    {
        offset = 0;

        long delta;
        if (targetAddress >= pointerValue)
        {
            var diff = targetAddress - pointerValue;
            if (diff > int.MaxValue)
            {
                return false;
            }

            delta = (long)diff;
        }
        else
        {
            var diff = pointerValue - targetAddress;
            if (diff > int.MaxValue)
            {
                return false;
            }

            delta = -(long)diff;
        }

        offset = (int)delta;
        return true;
    }

    private static bool TryAddDelta(int value, int delta, out int result)
    {
        var updated = (long)value + delta;
        if (updated < int.MinValue || updated > int.MaxValue)
        {
            result = 0;
            return false;
        }

        result = (int)updated;
        return true;
    }

    private static long ComputeDeviationScore(IReadOnlyList<int> baseline, IReadOnlyList<int> candidate)
    {
        var max = Math.Max(baseline.Count, candidate.Count);
        long score = 0;
        for (var i = 0; i < max; i++)
        {
            var left = i < baseline.Count ? baseline[i] : 0;
            var right = i < candidate.Count ? candidate[i] : 0;
            score += Math.Abs((long)left - right);
        }

        return score;
    }

    private ulong ResolvePointerBaseAddress(WatchEntry entry)
    {
        var pointerBaseAddress = entry.PointerBaseAddress;
        if (string.IsNullOrWhiteSpace(entry.PointerBaseModuleName))
        {
            return pointerBaseAddress;
        }

        var module = _memoryAccessor.Modules.FirstOrDefault(m =>
            string.Equals(m.Name, entry.PointerBaseModuleName, StringComparison.OrdinalIgnoreCase));
        if (module is null)
        {
            return pointerBaseAddress;
        }

        return module.Base + entry.PointerBaseModuleOffset;
    }

    private int ResolvePointerSizeBytes(int hint)
    {
        if (hint == 4 || hint == 8)
        {
            return hint;
        }

        try
        {
            var module = _memoryAccessor.Process.MainModule;
            if (module is null)
            {
                return 8;
            }

            var baseAddress = (ulong)module.BaseAddress.ToInt64();
            return baseAddress <= uint.MaxValue ? 4 : 8;
        }
        catch
        {
            return 8;
        }
    }

    private string FormatPointerSeedBase(WatchEntry entry, ulong resolvedBase)
    {
        if (!string.IsNullOrWhiteSpace(entry.PointerBaseModuleName))
        {
            return $"{entry.PointerBaseModuleName}+0x{entry.PointerBaseModuleOffset:X}";
        }

        return _memoryAccessor.FormatAddress(resolvedBase);
    }

    private static string BuildPointerExpression(string baseText, IReadOnlyList<int> offsets)
    {
        if (offsets.Count == 0)
        {
            return baseText;
        }

        var offsetText = string.Join(", ", offsets.Select(FormatSignedOffset));
        return $"{baseText} [{offsetText}]";
    }

    private static string FormatSignedOffset(int offset)
    {
        if (offset < 0)
        {
            return $"-0x{Math.Abs((long)offset):X}";
        }

        return $"+0x{offset:X}";
    }

    private RelativePointerCandidate? ShowPointerCandidatePicker(IReadOnlyList<RelativePointerCandidate> candidates)
    {
        var chooser = new Window
        {
            Title = "Relative Pointer Routes",
            Width = 980,
            Height = 560,
            Owner = this,
            WindowStartupLocation = WindowStartupLocation.CenterOwner
        };

        var root = new Grid { Margin = new Thickness(10) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var info = new TextBlock
        {
            Text = "Candidates found by local offset brute-force around the current pointer chain.",
            Margin = new Thickness(0, 0, 0, 8)
        };
        Grid.SetRow(info, 0);
        root.Children.Add(info);

        var rows = candidates.Select(x => new RelativePointerCandidateRow(x)).ToList();
        var grid = new DataGrid
        {
            AutoGenerateColumns = false,
            ItemsSource = rows,
            IsReadOnly = true,
            SelectionMode = DataGridSelectionMode.Single,
            CanUserAddRows = false,
            CanUserDeleteRows = false
        };
        grid.Columns.Add(new DataGridTextColumn { Header = "Pointer", Binding = new System.Windows.Data.Binding(nameof(RelativePointerCandidateRow.Expression)), Width = new DataGridLength(2.6, DataGridLengthUnitType.Star) });
        grid.Columns.Add(new DataGridTextColumn { Header = "Final Address", Binding = new System.Windows.Data.Binding(nameof(RelativePointerCandidateRow.FinalAddressText)), Width = new DataGridLength(1.3, DataGridLengthUnitType.Star) });
        grid.Columns.Add(new DataGridTextColumn { Header = "Value", Binding = new System.Windows.Data.Binding(nameof(RelativePointerCandidateRow.ValueText)), Width = new DataGridLength(1.1, DataGridLengthUnitType.Star) });
        grid.Columns.Add(new DataGridTextColumn { Header = "Score", Binding = new System.Windows.Data.Binding(nameof(RelativePointerCandidateRow.Score)), Width = new DataGridLength(0.8, DataGridLengthUnitType.Star) });
        if (rows.Count > 0)
        {
            grid.SelectedIndex = 0;
        }

        Grid.SetRow(grid, 1);
        root.Children.Add(grid);

        RelativePointerCandidate? selectedCandidate = null;
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 8, 0, 0) };
        var take = new Button { Content = "Take Selected", Width = 130, Height = 30, Margin = new Thickness(0, 0, 8, 0), IsDefault = true };
        var cancel = new Button { Content = "Cancel", Width = 100, Height = 30, IsCancel = true };

        take.Click += (_, _) =>
        {
            if (grid.SelectedItem is not RelativePointerCandidateRow row)
            {
                MessageBox.Show(chooser, "Select one candidate.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            selectedCandidate = row.Candidate;
            chooser.DialogResult = true;
        };

        cancel.Click += (_, _) => chooser.DialogResult = false;

        buttons.Children.Add(take);
        buttons.Children.Add(cancel);

        Grid.SetRow(buttons, 2);
        root.Children.Add(buttons);

        chooser.Content = root;
        return chooser.ShowDialog() == true ? selectedCandidate : null;
    }

    private WatchEntry BuildWatchEntryFromRelativePointerCandidate(RelativePointerCandidate candidate, MemoryDataType dataType)
    {
        if (_relativePointerSeed is null)
        {
            throw new InvalidOperationException("Relative pointer seed is missing.");
        }

        return new WatchEntry
        {
            Name = $"Ptr_{candidate.FinalAddress:X}",
            Kind = WatchEntryKind.PointerChain,
            DataType = dataType,
            PointerBaseAddress = _relativePointerSeed.PointerBaseAddress,
            PointerSizeBytes = _relativePointerSeed.PointerSizeBytes,
            PointerBaseModuleName = _relativePointerSeed.PointerBaseModuleName,
            PointerBaseModuleOffset = _relativePointerSeed.PointerBaseModuleOffset,
            Offsets = new ObservableCollection<int>(candidate.Offsets)
        };
    }

    private static WatchEntry ClonePointerSeed(WatchEntry source)
    {
        return new WatchEntry
        {
            Name = source.Name,
            Kind = source.Kind,
            DataType = source.DataType,
            DirectAddress = source.DirectAddress,
            PointerBaseAddress = source.PointerBaseAddress,
            PointerSizeBytes = source.PointerSizeBytes,
            PointerBaseModuleName = source.PointerBaseModuleName,
            PointerBaseModuleOffset = source.PointerBaseModuleOffset,
            Offsets = new ObservableCollection<int>(source.Offsets)
        };
    }

    private sealed class ValueFilterConditionOption
    {
        public ValueFilterConditionOption(ScanComparison value, string label)
        {
            Value = value;
            Label = label;
        }

        public ScanComparison Value { get; }
        public string Label { get; }

        public override string ToString() => Label;
    }

    private sealed class NearbyValueFilter
    {
        public NearbyValueFilter(MemoryDataType dataType, ScanComparison comparison, object value, object? valueTo, string displayText)
        {
            DataType = dataType;
            Comparison = comparison;
            Value = value;
            ValueTo = valueTo;
            DisplayText = displayText;
        }

        public MemoryDataType DataType { get; }
        public ScanComparison Comparison { get; }
        public object Value { get; }
        public object? ValueTo { get; }
        public string DisplayText { get; }
    }

    private sealed class RelativePointerRouteOptions
    {
        public bool UseAutoRange { get; set; }
        public int SecondaryOffsetSweepRange { get; set; }
        public int LastOffsetMaxDelta { get; set; }
        public int SecondaryOffsetStep { get; set; }
        public int MaxResults { get; set; }
        public int MaxRuntimeMs { get; set; }
        public bool EnableSecondarySweep { get; set; }
        public bool StopOnFirstHit { get; set; }
    }

    private sealed class RelativePointerRouteRuntimeOptions
    {
        public bool UseAutoRange { get; set; }
        public int SecondaryOffsetSweepRange { get; set; }
        public int LastOffsetMaxDelta { get; set; }
        public int SecondaryOffsetStep { get; set; }
        public int MaxResults { get; set; }
        public int MaxRuntimeMs { get; set; }
        public bool EnableSecondarySweep { get; set; }
        public bool StopOnFirstHit { get; set; }
    }

    private sealed class RelativePointerCandidate
    {
        public RelativePointerCandidate(int[] offsets, ulong finalAddress, string expression, string valueText, long score)
        {
            Offsets = offsets;
            FinalAddress = finalAddress;
            Expression = expression;
            ValueText = valueText;
            Score = score;
        }

        public int[] Offsets { get; }
        public ulong FinalAddress { get; }
        public string Expression { get; }
        public string ValueText { get; }
        public long Score { get; }
    }


    private sealed class RelativePointerCandidateRow
    {
        public RelativePointerCandidateRow(RelativePointerCandidate candidate)
        {
            Candidate = candidate;
            Expression = candidate.Expression;
            FinalAddressText = FormatRawAddress(candidate.FinalAddress);
            ValueText = candidate.ValueText;
            Score = candidate.Score;
        }

        public RelativePointerCandidate Candidate { get; }
        public string Expression { get; }
        public string FinalAddressText { get; }
        public string ValueText { get; }
        public long Score { get; }
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
        MemoryDataType.String => sizeof(byte),
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
        UiUpdateRoutineSettings.ValueRefreshIntervalChanged -= OnGlobalValueRefreshIntervalChanged;
        base.OnClosed(e);
    }

    public sealed class NearbyRow : INotifyPropertyChanged
    {
        private string _valueText = string.Empty;

        public NearbyRow(ulong address, MemoryDataType dataType, string displayAddress, bool isProcessBaseDisplay, bool isCenterRow)
        {
            Address = address;
            DataType = dataType;
            DisplayAddress = displayAddress;
            IsProcessBaseDisplay = isProcessBaseDisplay;
            IsCenterRow = isCenterRow;
            AddressHex = FormatRawAddress(address);
        }

        public ulong Address { get; }
        public MemoryDataType DataType { get; }
        public string DisplayAddress { get; }
        public bool IsProcessBaseDisplay { get; }
        public bool IsCenterRow { get; }
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

        public void SetUnavailable(string text)
        {
            PreviousValue = CurrentValue;
            CurrentValue = null;
            ValueText = text;
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}


















