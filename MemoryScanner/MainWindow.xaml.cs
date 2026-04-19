using MemoryScanner.Core;
using MemoryScanner.Models;
using MemoryScanner.Windows;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace MemoryScanner;

public partial class MainWindow : Window
{
    private const string UnavailableValueText = "???";
    private const int MinWatchRefreshBatchSize = 24;
    private const int MaxWatchRefreshBatchSize = 256;
    private const int MinScanResultRefreshBatchSize = 32;
    private const int MaxScanResultRefreshBatchSize = 512;
    private const int ScanResultQuickDoubleClickThresholdMs = 300;
    private readonly ObservableCollection<WatchEntry> _watchEntries = new();
    private readonly BulkObservableCollection<ScanResultRow> _scanResults = new();
    private readonly List<ScanResultRow> _allScanResults = new();

    private readonly IMemoryAccessor _memoryAccessor;
    private readonly MemoryRegionEnumerator _regionEnumerator;
    private readonly ScanService _scanService;
    private readonly PointerScanService _pointerScanService;
    private readonly ProfileStorageService _profileStorageService;
    private readonly DispatcherTimer _refreshTimer;
    private readonly DispatcherTimer _scanResultRefreshTimer;

    private CancellationTokenSource? _scanCts;
    private bool _isScanRunning;
    private bool _hasCompletedFirstScan;
    private ScanExecutionOptions _scanOptions = new();
    private bool _resumeWatchRefreshAfterScan;
    private bool _resumeScanResultRefreshAfterScan;
    private string? _currentWatchListFilePath;
    private int _watchRefreshCursor;
    private int _scanResultRefreshCursor;
    private bool _watchInvalidStateApplied;
    private Point _watchDragStartPoint;
    private WatchEntry? _watchDragSourceEntry;
    private DateTime _lastScanResultClickUtc;
    private ScanResultRow? _lastScanResultClickedRow;
    private bool _allowScanResultDoubleClickAction;

    public MainWindow()
    {
        InitializeComponent();

        _memoryAccessor = new MemoryAccessor64();
        _regionEnumerator = new MemoryRegionEnumerator();
        _scanService = new ScanService(_memoryAccessor, _regionEnumerator);
        _pointerScanService = new PointerScanService(_memoryAccessor, _regionEnumerator);
        _profileStorageService = new ProfileStorageService();

        WatchGrid.ItemsSource = _watchEntries;
        ScanResultGrid.ItemsSource = _scanResults;

        ScanTypeBox.ItemsSource = MemoryDataTypeUiOrder.Ordered;
        ScanTypeBox.SelectedItem = MemoryDataType.Int32;

        UpdateScanComparisonChoices();

        _refreshTimer = new DispatcherTimer();
        _refreshTimer.Tick += RefreshTimer_OnTick;

        _scanResultRefreshTimer = new DispatcherTimer();
        _scanResultRefreshTimer.Tick += ScanResultRefreshTimer_OnTick;

        UiUpdateRoutineSettings.ValueRefreshIntervalChanged += OnGlobalValueRefreshIntervalChanged;
        ApplyGlobalValueRefreshInterval(UiUpdateRoutineSettings.ValueRefreshIntervalMs);

        SetScanIdleUi();
        UpdateTakeSelectedButtonState();
        UpdateWindowTitle();
    }

    private void SelectProcess_OnClick(object sender, RoutedEventArgs e)
    {
        var dialog = new ProcessSelectionWindow { Owner = this };
        if (dialog.ShowDialog() != true || dialog.SelectedProcess is null)
        {
            return;
        }

        if (!_memoryAccessor.TryAttach(dialog.SelectedProcess, out var error))
        {
            MessageBox.Show(this, $"Attach failed: {error}", "Attach Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        ProcessInfoText.Text = $"Attached: {_memoryAccessor.Process.ProcessName} (PID {_memoryAccessor.Process.Id})";
        _scanService.Reset();
        _hasCompletedFirstScan = false;
        UpdateScanComparisonChoices();
        _allScanResults.Clear();
        _scanResults.Clear();
        _scanResultRefreshCursor = 0;
        ScanProgressBar.Value = 0;
        UpdateScanActionButtonsState();
        UpdateTakeSelectedButtonState();
        UpdateIdleProgressText();
        UpdateAllWatchDisplayAddresses();
        RefreshWatchValues();
        RefreshScanResultValues();
    }

    private void AddWatchEntry_OnClick(object sender, RoutedEventArgs e)
    {
        var dialog = new AddWatchEntryWindow(processName: GetAttachedProcessName(), modules: GetAttachedModuleSnapshot()) { Owner = this };
        if (dialog.ShowDialog() != true || dialog.CreatedEntry is null)
        {
            return;
        }

        AddWatchEntry(dialog.CreatedEntry);
    }

    private void RemoveWatchEntry_OnClick(object sender, RoutedEventArgs e)
    {
        if (WatchGrid.SelectedItem is WatchEntry entry)
        {
            _watchEntries.Remove(entry);
            _watchInvalidStateApplied = false;
        }
    }

    private void CopyWatchListFormat_OnClick(object sender, RoutedEventArgs e)
    {
        var exportText = BuildWatchEntryCopyText();
        ShowCopyWatchListDialog(exportText);
    }

    private void WatchGrid_OnMouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        var source = e.OriginalSource as DependencyObject;
        var cell = FindVisualParent<DataGridCell>(source);
        if (cell?.Column is null || cell.DataContext is not WatchEntry entry)
        {
            return;
        }

        WatchGrid.SelectedItem = entry;

        if (ReferenceEquals(cell.Column, WatchNameColumn))
        {
            EditWatchName_OnClick(sender, new RoutedEventArgs());
            e.Handled = true;
            return;
        }

        if (ReferenceEquals(cell.Column, WatchAddressColumn))
        {
            EditWatchAddressPointer_OnClick(sender, new RoutedEventArgs());
            e.Handled = true;
            return;
        }

        if (ReferenceEquals(cell.Column, WatchTypeColumn))
        {
            EditWatchDataType_OnClick(sender, new RoutedEventArgs());
            e.Handled = true;
            return;
        }

        if (ReferenceEquals(cell.Column, WatchValueColumn))
        {
            WriteValue_OnClick(sender, new RoutedEventArgs());
            e.Handled = true;
        }
    }

    private void RefreshWatchValues_OnClick(object sender, RoutedEventArgs e)
    {
        RefreshWatchValues();
    }

    private void WriteValue_OnClick(object sender, RoutedEventArgs e)
    {
        if (!_memoryAccessor.IsAttached)
        {
            MessageBox.Show(this, "Select a process first.", "No Process", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (WatchGrid.SelectedItem is not WatchEntry entry)
        {
            return;
        }

        var input = PromptForText("Write Value", $"New value for '{entry.Name}' ({entry.DataType}):", entry.LastValueText);
        if (input is null)
        {
            return;
        }

        if (!ScanService.TryParseValue(entry.DataType, input, out var parsed))
        {
            MessageBox.Show(this, "Invalid value for selected data type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!_memoryAccessor.TryResolveWatchAddress(entry, out var address, out _))
        {
            MessageBox.Show(this, "Could not resolve target address.", "Resolve Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!_memoryAccessor.TryWriteValue(address, entry.DataType, parsed))
        {
            MessageBox.Show(this, "Write failed.", "Memory Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        entry.LastValueText = input;
        entry.FreezeValueText = input;
        entry.Status = "Valid";
    }

    private void WriteValueFromContext_OnClick(object sender, RoutedEventArgs e)
    {
        WriteValue_OnClick(sender, e);
    }

    private void CopyWatchAddress_OnClick(object sender, RoutedEventArgs e)
    {
        if (WatchGrid.SelectedItem is not WatchEntry entry)
        {
            return;
        }

        string textToCopy;
        if (_memoryAccessor.IsAttached && _memoryAccessor.TryResolveWatchAddress(entry, out var resolvedAddress, out _))
        {
            textToCopy = $"0x{resolvedAddress:X}";
        }
        else if (!string.IsNullOrWhiteSpace(entry.DisplayAddress))
        {
            textToCopy = entry.DisplayAddress;
        }
        else
        {
            textToCopy = entry.Kind == WatchEntryKind.DirectAddress
                ? $"0x{entry.DirectAddress:X}"
                : $"0x{entry.PointerBaseAddress:X}";
        }

        try
        {
            Clipboard.SetText(textToCopy);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Clipboard Error", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void EditWatchName_OnClick(object sender, RoutedEventArgs e)
    {
        if (WatchGrid.SelectedItem is not WatchEntry entry)
        {
            return;
        }

        var updated = PromptForText("Edit Name", "Entry name:", entry.Name);
        if (updated is null)
        {
            return;
        }

        entry.Name = string.IsNullOrWhiteSpace(updated) ? "Entry" : updated.Trim();
        WatchGrid.Items.Refresh();
    }

    private void EditWatchAddressPointer_OnClick(object sender, RoutedEventArgs e)
    {
        if (WatchGrid.SelectedItem is not WatchEntry entry)
        {
            return;
        }

        var dialog = new AddWatchEntryWindow(entry, addressOnlyEditMode: true, processName: GetAttachedProcessName(), modules: GetAttachedModuleSnapshot()) { Owner = this };
        if (dialog.ShowDialog() != true || dialog.CreatedEntry is null)
        {
            return;
        }

        var edited = dialog.CreatedEntry;
        entry.Kind = edited.Kind;
        entry.DirectAddress = edited.DirectAddress;
        entry.PointerBaseAddress = edited.PointerBaseAddress;
        entry.PointerSizeBytes = edited.PointerSizeBytes;
        entry.PointerBaseModuleName = edited.PointerBaseModuleName;
        entry.PointerBaseModuleOffset = edited.PointerBaseModuleOffset;
        entry.Offsets = new ObservableCollection<int>(edited.Offsets);
        entry.Status = "Unknown";

        UpdateWatchDisplayForCurrentState(entry);
        WatchGrid.Items.Refresh();

        if (_memoryAccessor.IsAttached)
        {
            RefreshWatchValues();
        }
    }

    private void EditWatchDataType_OnClick(object sender, RoutedEventArgs e)
    {
        if (WatchGrid.SelectedItem is not WatchEntry entry)
        {
            return;
        }

        var selectedType = PromptForDataType(entry.DataType);
        if (selectedType is null)
        {
            return;
        }

        entry.DataType = selectedType.Value;
        entry.Status = "Unknown";
        WatchGrid.Items.Refresh();

        if (_memoryAccessor.IsAttached)
        {
            RefreshWatchValues();
        }
    }

    private void UpdateWatchDisplayForCurrentState(WatchEntry entry)
    {
        if (entry.Kind == WatchEntryKind.DirectAddress && _memoryAccessor.IsAttached)
        {
            TryRebaseDirectEntryFromModuleReference(entry);
            CaptureDirectEntryModuleReference(entry);
        }

        NormalizeProcessBaseEntryKind(entry);

        if (entry.Kind == WatchEntryKind.DirectAddress)
        {
            if (_memoryAccessor.IsAttached)
            {
                entry.DisplayAddress = _memoryAccessor.FormatAddress(entry.DirectAddress);
            }
            else
            {
                entry.DisplayAddress = string.IsNullOrWhiteSpace(entry.PointerBaseModuleName)
                    ? $"0x{entry.DirectAddress:X}"
                    : $"{entry.PointerBaseModuleName}+0x{entry.PointerBaseModuleOffset:X}";
            }

            entry.IsProcessBaseDisplay = IsProcessBaseAddressText(entry.DisplayAddress);
            return;
        }

        if (_memoryAccessor.IsAttached)
        {
            TryRebasePointerEntryFromModuleReference(entry);
        }

        if (!HasPointerOffsets(entry))
        {
            entry.DisplayAddress = FormatPointerBaseForDisplay(entry);
            entry.IsProcessBaseDisplay = true;
            return;
        }

        if (_memoryAccessor.IsAttached && _memoryAccessor.TryResolveWatchAddress(entry, out var resolvedAddress, out _))
        {
            entry.DisplayAddress = $"P-> {_memoryAccessor.FormatAddress(resolvedAddress)}";
        }
        else
        {
            entry.DisplayAddress = "P-> <unresolved>";
        }

        entry.IsProcessBaseDisplay = true;
    }

    private bool HasPointerOffsets(WatchEntry entry)
    {
        return entry.Offsets is { Count: > 0 };
    }

    private string FormatPointerBaseForDisplay(WatchEntry entry)
    {
        if (_memoryAccessor.IsAttached)
        {
            var pointerBaseAddress = entry.PointerBaseAddress;
            if (!string.IsNullOrWhiteSpace(entry.PointerBaseModuleName))
            {
                var match = _memoryAccessor.Modules.FirstOrDefault(m =>
                    string.Equals(m.Name, entry.PointerBaseModuleName, StringComparison.OrdinalIgnoreCase));
                if (match is not null)
                {
                    pointerBaseAddress = match.Base + entry.PointerBaseModuleOffset;
                }
            }

            return _memoryAccessor.FormatAddress(pointerBaseAddress);
        }

        if (!string.IsNullOrWhiteSpace(entry.PointerBaseModuleName))
        {
            return $"{entry.PointerBaseModuleName}+0x{entry.PointerBaseModuleOffset:X}";
        }

        return $"0x{entry.PointerBaseAddress:X}";
    }

    private void NormalizeProcessBaseEntryKind(WatchEntry entry)
    {
        if (entry.Kind != WatchEntryKind.DirectAddress)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(entry.PointerBaseModuleName))
        {
            return;
        }

        entry.Kind = WatchEntryKind.PointerChain;
        entry.PointerBaseAddress = entry.DirectAddress;
        entry.Offsets ??= new ObservableCollection<int>();
    }

    private string? GetAttachedProcessName()
    {
        return _memoryAccessor.IsAttached ? _memoryAccessor.Process.ProcessName : null;
    }

    private IReadOnlyList<ModuleRange>? GetAttachedModuleSnapshot()
    {
        return _memoryAccessor.IsAttached
            ? _memoryAccessor.Modules.ToList()
            : null;
    }

    private async void FirstScan_OnClick(object sender, RoutedEventArgs e)
    {
        await RunScanAsync(isFirstScan: true);
    }

    private async void NextScan_OnClick(object sender, RoutedEventArgs e)
    {
        await RunScanAsync(isFirstScan: false);
    }

    private void ResetScan_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning)
        {
            return;
        }

        _scanService.Reset();
        _hasCompletedFirstScan = false;
        UpdateScanComparisonChoices();
        _allScanResults.Clear();
        _scanResults.Clear();
        _scanResultRefreshCursor = 0;
        ScanProgressBar.Value = 0;
        UpdateIdleProgressText();
        UpdateScanActionButtonsState();
        UpdateTakeSelectedButtonState();
    }

    private void CancelScan_OnClick(object sender, RoutedEventArgs e)
    {
        _scanCts?.Cancel();
    }

    private void ScanOptions_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning)
        {
            return;
        }

        var dialog = new ScanOptionsWindow(_scanOptions) { Owner = this };
        if (dialog.ShowDialog() == true && dialog.SelectedOptions is not null)
        {
            _scanOptions = dialog.SelectedOptions;
            if (!_isScanRunning)
            {
                UpdateIdleProgressText();
            }
        }
    }

    private void ValueUpdateRoutine_OnClick(object sender, RoutedEventArgs e)
    {
        var current = UiUpdateRoutineSettings.ValueRefreshIntervalMs.ToString();
        var input = PromptForText(
            "Value Update Routine",
            "Refresh interval for all value lists in milliseconds (>= 1):",
            current);

        if (input is null)
        {
            return;
        }

        if (!int.TryParse(input.Trim(), out var milliseconds) || !UiUpdateRoutineSettings.TrySetValueRefreshInterval(milliseconds))
        {
            MessageBox.Show(this, "Please enter a valid integer >= 1.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!_isScanRunning)
        {
            UpdateIdleProgressText();
        }
    }

    private void OnGlobalValueRefreshIntervalChanged(object? sender, int milliseconds)
    {
        Dispatcher.Invoke(() =>
        {
            ApplyGlobalValueRefreshInterval(milliseconds);
            if (!_isScanRunning)
            {
                UpdateIdleProgressText();
            }
        });
    }

    private void ApplyGlobalValueRefreshInterval(int milliseconds)
    {
        var interval = TimeSpan.FromMilliseconds(milliseconds);
        _refreshTimer.Interval = interval;
        _scanResultRefreshTimer.Interval = interval;

        if (_isScanRunning)
        {
            return;
        }

        _refreshTimer.Stop();
        _scanResultRefreshTimer.Stop();
        _refreshTimer.Start();
        _scanResultRefreshTimer.Start();
    }

    private void ScanResultRefreshTimer_OnTick(object? sender, EventArgs e)
    {
        RefreshScanResultValuesIncremental();
    }

    private void ScanResultGrid_OnScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        if (!_memoryAccessor.IsAttached)
        {
            return;
        }

        if (Math.Abs(e.VerticalChange) < 0.01 && Math.Abs(e.ViewportHeightChange) < 0.01)
        {
            return;
        }

        RefreshVisibleScanResultRows();
    }

    private void RefreshScanResultValues()
    {
        if (!_memoryAccessor.IsAttached)
        {
            SetScanResultValuesUnavailableIncremental();
            return;
        }

        _scanResultRefreshCursor = 0;
        foreach (var row in _scanResults)
        {
            UpdateScanResultRowValue(row);
        }
    }

    private void RefreshScanResultValuesIncremental()
    {
        if (!_memoryAccessor.IsAttached)
        {
            SetScanResultValuesUnavailableIncremental();
            return;
        }

        var count = _scanResults.Count;
        if (count == 0)
        {
            return;
        }

        var visibleRows = GetVisibleDataGridItems<ScanResultRow>(ScanResultGrid);
        var visibleSet = visibleRows.Count > 0 ? new HashSet<ScanResultRow>(visibleRows) : null;
        foreach (var row in visibleRows)
        {
            UpdateScanResultRowValue(row);
        }

        if (_scanResultRefreshCursor >= count)
        {
            _scanResultRefreshCursor = 0;
        }

        var backgroundBudget = Math.Min(count, ComputeRefreshBatchSize(count, MinScanResultRefreshBatchSize, MaxScanResultRefreshBatchSize));
        var updated = 0;
        var attempts = 0;
        while (updated < backgroundBudget && attempts < count)
        {
            if (_scanResultRefreshCursor >= count)
            {
                _scanResultRefreshCursor = 0;
            }

            var row = _scanResults[_scanResultRefreshCursor];
            _scanResultRefreshCursor++;
            attempts++;

            if (visibleSet is not null && visibleSet.Contains(row))
            {
                continue;
            }

            UpdateScanResultRowValue(row);
            updated++;
        }
    }

    private void WatchGrid_OnPreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        _watchDragStartPoint = e.GetPosition(WatchGrid);
        _watchDragSourceEntry = null;

        var source = e.OriginalSource as DependencyObject;
        if (FindVisualParent<DataGridColumnHeader>(source) is not null)
        {
            return;
        }

        var cell = FindVisualParent<DataGridCell>(source);
        if (cell?.Column is DataGridCheckBoxColumn)
        {
            return;
        }

        var row = FindVisualParent<DataGridRow>(source);
        if (row?.DataContext is WatchEntry entry)
        {
            _watchDragSourceEntry = entry;
        }
    }

    private void WatchGrid_OnMouseMove(object sender, MouseEventArgs e)
    {
        if (e.LeftButton != MouseButtonState.Pressed || _watchDragSourceEntry is null)
        {
            return;
        }

        var position = e.GetPosition(WatchGrid);
        var delta = _watchDragStartPoint - position;
        if (Math.Abs(delta.X) < SystemParameters.MinimumHorizontalDragDistance &&
            Math.Abs(delta.Y) < SystemParameters.MinimumVerticalDragDistance)
        {
            return;
        }

        DragDrop.DoDragDrop(WatchGrid, new DataObject(typeof(WatchEntry), _watchDragSourceEntry), DragDropEffects.Move);
        _watchDragSourceEntry = null;
    }

    private void WatchGrid_OnDragOver(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(typeof(WatchEntry)))
        {
            e.Effects = DragDropEffects.None;
            e.Handled = true;
            return;
        }

        e.Effects = DragDropEffects.Move;
        e.Handled = true;
    }

    private void WatchGrid_OnDrop(object sender, DragEventArgs e)
    {
        try
        {
            if (!e.Data.GetDataPresent(typeof(WatchEntry)))
            {
                return;
            }

            if (e.Data.GetData(typeof(WatchEntry)) is not WatchEntry draggedEntry)
            {
                return;
            }

            var oldIndex = _watchEntries.IndexOf(draggedEntry);
            if (oldIndex < 0)
            {
                return;
            }

            var source = e.OriginalSource as DependencyObject;
            var targetRow = FindVisualParent<DataGridRow>(source);
            var targetEntry = targetRow?.Item as WatchEntry;
            var newIndex = targetEntry is null
                ? _watchEntries.Count - 1
                : _watchEntries.IndexOf(targetEntry);

            if (newIndex < 0 || newIndex == oldIndex)
            {
                return;
            }

            _watchEntries.Move(oldIndex, newIndex);
            WatchGrid.SelectedItem = draggedEntry;
            WatchGrid.ScrollIntoView(draggedEntry);
        }
        finally
        {
            _watchDragSourceEntry = null;
            e.Handled = true;
        }
    }

    private void UpdateScanResultRowValue(ScanResultRow row)
    {
        if (!_memoryAccessor.IsAttached)
        {
            row.ValueText = UnavailableValueText;
            return;
        }

        if (_memoryAccessor.TryReadValue(row.Address, row.DataType, out var value, row.StringByteLength))
        {
            row.ValueText = FormatValue(value);
        }
        else
        {
            row.ValueText = "<invalid>";
        }
    }

    private void ScanComparisonBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateScanComparisonInputUi();
    }

    private void ScanTypeBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateScanComparisonChoices();
    }

    private static IReadOnlyList<ScanComparisonOption> BuildScanComparisonOptions(
        bool includeUnknownInitial,
        bool includeRelativeComparisons,
        bool includeRangeComparisons)
    {
        var list = new List<ScanComparisonOption>();

        if (includeUnknownInitial)
        {
            list.Add(new ScanComparisonOption(ScanComparison.UnknownInitial, FormatScanComparisonLabel(ScanComparison.UnknownInitial)));
        }

        list.Add(new ScanComparisonOption(ScanComparison.Equal, FormatScanComparisonLabel(ScanComparison.Equal)));
        list.Add(new ScanComparisonOption(ScanComparison.NotEqual, FormatScanComparisonLabel(ScanComparison.NotEqual)));

        if (includeRangeComparisons)
        {
            list.Add(new ScanComparisonOption(ScanComparison.Greater, FormatScanComparisonLabel(ScanComparison.Greater)));
            list.Add(new ScanComparisonOption(ScanComparison.Less, FormatScanComparisonLabel(ScanComparison.Less)));
            list.Add(new ScanComparisonOption(ScanComparison.Between, FormatScanComparisonLabel(ScanComparison.Between)));
        }

        if (includeRelativeComparisons)
        {
            list.Add(new ScanComparisonOption(ScanComparison.Increased, FormatScanComparisonLabel(ScanComparison.Increased)));
            list.Add(new ScanComparisonOption(ScanComparison.Decreased, FormatScanComparisonLabel(ScanComparison.Decreased)));
            list.Add(new ScanComparisonOption(ScanComparison.Changed, FormatScanComparisonLabel(ScanComparison.Changed)));
            list.Add(new ScanComparisonOption(ScanComparison.Unchanged, FormatScanComparisonLabel(ScanComparison.Unchanged)));
        }

        return list;
    }

    private static string FormatScanComparisonLabel(ScanComparison comparison)
    {
        return comparison switch
        {
            ScanComparison.UnknownInitial => "Unknown Initial",
            ScanComparison.NotEqual => "Not Equal",
            ScanComparison.Between => "Between (Range)",
            _ => comparison.ToString()
        };
    }

    private void UpdateScanComparisonChoices()
    {
        if (ScanComparisonBox is null)
        {
            return;
        }

        var previous = (ScanComparisonBox.SelectedItem as ScanComparisonOption)?.Value;
        var selectedType = ScanTypeBox?.SelectedItem as MemoryDataType? ?? MemoryDataType.Int32;

        IReadOnlyList<ScanComparisonOption> options = selectedType == MemoryDataType.String
            ? BuildScanComparisonOptions(includeUnknownInitial: false, includeRelativeComparisons: false, includeRangeComparisons: false)
            : (_hasCompletedFirstScan
                ? BuildScanComparisonOptions(includeUnknownInitial: false, includeRelativeComparisons: true, includeRangeComparisons: true)
                : BuildScanComparisonOptions(includeUnknownInitial: true, includeRelativeComparisons: false, includeRangeComparisons: true));

        ScanComparisonBox.ItemsSource = options;

        if (previous.HasValue && !options.Any(x => x.Value == previous.Value))
        {
            previous = null;
        }

        var selected = previous.HasValue
            ? options.FirstOrDefault(x => x.Value == previous.Value)
            : null;

        if (selected is null)
        {
            selected = options.FirstOrDefault(x => x.Value == ScanComparison.Equal)
                ?? options.First();
        }

        ScanComparisonBox.SelectedItem = selected;
        UpdateScanComparisonInputUi();
    }

    private void UpdateScanComparisonInputUi()
    {
        if (ScanComparisonBox.SelectedItem is not ScanComparisonOption option)
        {
            ScanValueLabelText.Text = "Value";
            ScanValueText.IsEnabled = true;
            ScanRangeToPanel.Visibility = Visibility.Collapsed;
            return;
        }

        var comparison = option.Value;
        var selectedType = ScanTypeBox.SelectedItem as MemoryDataType? ?? MemoryDataType.Int32;
        var requiresInput = selectedType == MemoryDataType.String
            ? comparison is ScanComparison.Equal or ScanComparison.NotEqual
            : comparison is ScanComparison.Equal
                or ScanComparison.NotEqual
                or ScanComparison.Greater
                or ScanComparison.Less
                or ScanComparison.Between;

        var showRange = selectedType != MemoryDataType.String && comparison == ScanComparison.Between;

        ScanValueLabelText.Text = showRange ? "Range From" : "Value";
        ScanValueText.IsEnabled = requiresInput;
        ScanRangeToPanel.Visibility = showRange ? Visibility.Visible : Visibility.Collapsed;

        if (!showRange)
        {
            ScanValueToText.Text = string.Empty;
        }
    }
    private async Task RunScanAsync(bool isFirstScan)
    {
        if (_isScanRunning)
        {
            return;
        }

        if (!isFirstScan && !_hasCompletedFirstScan)
        {
            return;
        }

        if (!TryGetScanInput(out var dataType, out var comparison, out var valueText, out var valueTextTo))
        {
            return;
        }

        if (!isFirstScan && comparison == ScanComparison.UnknownInitial)
        {
            MessageBox.Show(this, "Unknown Initial can only be used as first scan.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!_memoryAccessor.IsAttached)
        {
            MessageBox.Show(this, "Select a process first.", "No Process", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        _scanCts?.Cancel();
        _scanCts?.Dispose();
        _scanCts = new CancellationTokenSource();

        long lastUiProgressTicks = 0;
        const long uiProgressMinDeltaTicks = TimeSpan.TicksPerMillisecond * 50;

        var progress = new Progress<ScanProgressInfo>(info =>
        {
            var now = DateTime.UtcNow.Ticks;
            var force = info.Percent >= 100 || info.StatusText.Contains("finished", StringComparison.OrdinalIgnoreCase) || info.StatusText.Contains("canceled", StringComparison.OrdinalIgnoreCase);
            if (!force && now - lastUiProgressTicks < uiProgressMinDeltaTicks)
            {
                return;
            }

            lastUiProgressTicks = now;
            ScanProgressBar.Value = info.Percent;
            ScanProgressText.Text = $"{info.StatusText} {info.Percent:0.0}% ({info.Processed}/{info.Total})";
        });

        SetScanBusyUi();
        try
        {
            var token = _scanCts.Token;
            IReadOnlyList<ScanResult> results = isFirstScan
                ? await Task.Run(() => _scanService.FirstScan(dataType, comparison, valueText, valueTextTo, _scanOptions, progress, token), token)
                : await Task.Run(() => _scanService.NextScan(dataType, comparison, valueText, valueTextTo, _scanOptions, progress, token), token);

            SetScanResults(results);
            if (isFirstScan && !token.IsCancellationRequested)
            {
                _hasCompletedFirstScan = true;
                UpdateScanComparisonChoices();
            }
            ScanProgressBar.Value = 100;
            if (isFirstScan && comparison == ScanComparison.UnknownInitial)
            {
                ScanProgressText.Text = $"Unknown initial baseline captured ({_scanService.CandidateCount} candidates)";
            }
            else
            {
                ScanProgressText.Text = $"Scan finished ({results.Count} results)";
            }
        }
        catch (OperationCanceledException)
        {
            ScanProgressText.Text = "Scan canceled";
        }
        catch (AggregateException ex) when (IsOnlyCancellation(ex))
        {
            ScanProgressText.Text = "Scan canceled";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Scan Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            SetScanIdleUi();
        }
    }

    private void SetScanBusyUi()
    {
        _isScanRunning = true;
        _resumeWatchRefreshAfterScan = _refreshTimer.IsEnabled;
        _resumeScanResultRefreshAfterScan = _scanResultRefreshTimer.IsEnabled;
        _refreshTimer.Stop();
        _scanResultRefreshTimer.Stop();

        UpdateScanActionButtonsState();
        ScanOptionsButton.IsEnabled = false;
        ScanButtonsPanel.Visibility = Visibility.Collapsed;
        CancelScanPanel.Visibility = Visibility.Visible;
        CancelScanButton.IsEnabled = true;
        ScanProgressBar.Value = 0;
        ScanProgressText.Text = "Preparing scan...";
        UpdateTakeSelectedButtonState();
    }

    private void SetScanIdleUi()
    {
        _isScanRunning = false;
        if (_resumeWatchRefreshAfterScan)
        {
            _refreshTimer.Start();
        }

        if (_resumeScanResultRefreshAfterScan)
        {
            _scanResultRefreshTimer.Start();
        }

        UpdateScanActionButtonsState();
        ScanOptionsButton.IsEnabled = true;
        ScanButtonsPanel.Visibility = Visibility.Visible;
        CancelScanPanel.Visibility = Visibility.Collapsed;
        UpdateIdleProgressText();
        UpdateTakeSelectedButtonState();
    }

    private void UpdateScanActionButtonsState()
    {
        FirstScanButton.IsEnabled = !_isScanRunning && !_hasCompletedFirstScan;
        NextScanButton.IsEnabled = !_isScanRunning && _hasCompletedFirstScan;
        ResetScanButton.IsEnabled = !_isScanRunning && _hasCompletedFirstScan;
    }

    private void UpdateWindowTitle()
    {
        var profileSuffix = string.IsNullOrWhiteSpace(_currentWatchListFilePath)
            ? string.Empty
            : $" - {Path.GetFileName(_currentWatchListFilePath)}";

        Title = $"MemoryScanner{profileSuffix}";
    }
    private void UpdateIdleProgressText()
    {
        var updateMsText = UiUpdateRoutineSettings.ValueRefreshIntervalMs;
        ScanProgressText.Text = $"Idle | Update {updateMsText} ms | Results {_allScanResults.Count}";
    }

    private void ScanResultGrid_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateTakeSelectedButtonState();
    }
    private void ScanResultGrid_OnPreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (_isScanRunning)
        {
            return;
        }

        var source = e.OriginalSource as DependencyObject;
        var row = FindVisualParent<DataGridRow>(source);
        if (row?.Item is not ScanResultRow clickedRow)
        {
            _allowScanResultDoubleClickAction = false;
            return;
        }

        var nowUtc = DateTime.UtcNow;
        var deltaMs = (nowUtc - _lastScanResultClickUtc).TotalMilliseconds;
        _allowScanResultDoubleClickAction = ReferenceEquals(_lastScanResultClickedRow, clickedRow)
            && deltaMs >= 0
            && deltaMs <= ScanResultQuickDoubleClickThresholdMs;
        _lastScanResultClickUtc = nowUtc;
        _lastScanResultClickedRow = clickedRow;

        if (e.ClickCount > 1)
        {
            return;
        }

        if ((Keyboard.Modifiers & (ModifierKeys.Control | ModifierKeys.Shift)) != ModifierKeys.None)
        {
            return;
        }

        row.IsSelected = !row.IsSelected;
        e.Handled = true;
    }

    private void ScanResultGrid_OnMouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (!_allowScanResultDoubleClickAction)
        {
            return;
        }

        _allowScanResultDoubleClickAction = false;
        TakeSelectedScanResult_OnClick(sender, e);
        e.Handled = true;
    }

    private void UpdateTakeSelectedButtonState()
    {
        if (TakeSelectedScanResultButton is null)
        {
            return;
        }

        TakeSelectedScanResultButton.IsEnabled = !_isScanRunning && ScanResultGrid.SelectedItems.Count >= 1;
    }
    private void TakeSelectedScanResult_OnClick(object sender, RoutedEventArgs e)
    {
        var selected = ScanResultGrid.SelectedItems.OfType<ScanResultRow>().ToList();
        if (selected.Count == 0)
        {
            return;
        }

        foreach (var row in selected)
        {
            var entry = new WatchEntry
            {
                Name = $"Address_{row.Address:X}",
                Kind = WatchEntryKind.DirectAddress,
                DirectAddress = row.Address,
                DataType = row.DataType
            };
            AddWatchEntry(entry);
        }
    }

    private void TakeAllScanResults_OnClick(object sender, RoutedEventArgs e)
    {
        foreach (var row in _allScanResults)
        {
            var entry = new WatchEntry
            {
                Name = $"Address_{row.Address:X}",
                Kind = WatchEntryKind.DirectAddress,
                DirectAddress = row.Address,
                DataType = row.DataType
            };
            AddWatchEntry(entry);
        }
    }

    private async void PointerScanForSelected_OnClick(object sender, RoutedEventArgs e)
    {
        if (!_memoryAccessor.IsAttached)
        {
            MessageBox.Show(this, "Select a process first.", "No Process", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (WatchGrid.SelectedItem is not WatchEntry selected)
        {
            return;
        }

        if (!_memoryAccessor.TryResolveWatchAddress(selected, out var resolvedAddress, out _))
        {
            MessageBox.Show(this, "Could not resolve selected entry address.", "Resolve Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        OpenPointerScannerWithAddress(resolvedAddress, selected.DataType);
        await Task.CompletedTask;
    }
    private void RepairPointerBaseFromWatch_OnClick(object sender, RoutedEventArgs e)
    {
        if (!_memoryAccessor.IsAttached)
        {
            MessageBox.Show(this, "Select a process first.", "No Process", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (WatchGrid.SelectedItem is not WatchEntry selected)
        {
            return;
        }

        if (!TryCreatePointerRepairSeed(selected, out var currentBaseAddress, out var offsets, out var pointerSizeHint))
        {
            MessageBox.Show(this,
                "Pointer base repair is available for pointer entries (base + optional offsets).",
                "Not Supported",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        var dialog = new PointerBaseRepairWindow(
            _memoryAccessor,
            currentBaseAddress,
            offsets,
            pointerSizeHint,
            selected.DataType,
            selected.LastValueText)
        {
            Owner = this
        };

        if (dialog.ShowDialog() != true || !dialog.SelectedBaseAddress.HasValue)
        {
            return;
        }

        ApplyPointerRepairResult(
            selected,
            dialog.SelectedBaseAddress.Value,
            offsets,
            dialog.SelectedPointerSizeBytes > 0 ? dialog.SelectedPointerSizeBytes : pointerSizeHint,
            dialog.SelectedDataType);
    }

    private bool TryCreatePointerRepairSeed(WatchEntry entry, out ulong baseAddress, out int[] offsets, out int pointerSizeHint)
    {
        baseAddress = 0;
        offsets = Array.Empty<int>();
        pointerSizeHint = 0;

        if (entry.Kind == WatchEntryKind.PointerChain)
        {
            baseAddress = entry.PointerBaseAddress;
            offsets = entry.Offsets?.ToArray() ?? Array.Empty<int>();
            pointerSizeHint = entry.PointerSizeBytes;
            return true;
        }

        if (entry.Kind == WatchEntryKind.DirectAddress &&
            (!string.IsNullOrWhiteSpace(entry.PointerBaseModuleName) || entry.IsProcessBaseDisplay))
        {
            baseAddress = entry.DirectAddress;
            offsets = Array.Empty<int>();
            pointerSizeHint = entry.PointerSizeBytes;
            return true;
        }

        return false;
    }

    private void ApplyPointerRepairResult(
        WatchEntry targetEntry,
        ulong repairedBaseAddress,
        IReadOnlyList<int> offsets,
        int pointerSizeBytes,
        MemoryDataType selectedType)
    {
        targetEntry.Kind = WatchEntryKind.PointerChain;
        targetEntry.PointerBaseAddress = repairedBaseAddress;
        targetEntry.Offsets = new ObservableCollection<int>(offsets);
        targetEntry.DataType = selectedType;

        if (pointerSizeBytes == 4 || pointerSizeBytes == 8)
        {
            targetEntry.PointerSizeBytes = pointerSizeBytes;
        }

        UpdatePointerBaseModuleReference(targetEntry, repairedBaseAddress);

        targetEntry.Status = "Unknown";
        UpdateWatchDisplayForCurrentState(targetEntry);
        WatchGrid.Items.Refresh();
        RefreshWatchValues();
    }

    private void UpdatePointerBaseModuleReference(WatchEntry entry, ulong pointerBaseAddress)
    {
        var module = _memoryAccessor.Modules.FirstOrDefault(m => m.Contains(pointerBaseAddress));
        if (module is null)
        {
            entry.PointerBaseModuleName = string.Empty;
            entry.PointerBaseModuleOffset = 0;
            return;
        }

        entry.PointerBaseModuleName = module.Name;
        entry.PointerBaseModuleOffset = pointerBaseAddress - module.Base;
    }

    private void OpenPointerScanner_OnClick(object sender, RoutedEventArgs e)
    {
        if (!_memoryAccessor.IsAttached)
        {
            MessageBox.Show(this, "Select a process first.", "No Process", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        ulong initialAddress = 0;
        MemoryDataType initialType = MemoryDataType.Int32;

        if (WatchGrid.SelectedItem is WatchEntry selected && _memoryAccessor.TryResolveWatchAddress(selected, out var resolvedAddress, out _))
        {
            initialAddress = resolvedAddress;
            initialType = selected.DataType;
        }
        else
        {
            var firstModule = _memoryAccessor.Modules.FirstOrDefault();
            if (firstModule is not null)
            {
                initialAddress = firstModule.Base;
            }
        }

        OpenPointerScannerWithAddress(initialAddress, initialType);
    }

    private void OpenPointerScannerWithAddress(ulong address, MemoryDataType initialType, PointerScanOptions? initialOptions = null)
    {
        var pointerWindow = new PointerScanWindow(_pointerScanService, _memoryAccessor, address, initialType, initialOptions)
        {
            Owner = this
        };

        pointerWindow.TakeSelectedRequested += (_, paths, selectedType) =>
        {
            TakePointerPathsIntoWatchList(paths, selectedType);
        };

        pointerWindow.Show();
        pointerWindow.Activate();
    }

    private void TakePointerPathsIntoWatchList(IReadOnlyList<PointerPath> paths, MemoryDataType selectedType)
    {
        foreach (var path in paths)
        {
            var dialog = new AddWatchEntryWindow(path, selectedType, processName: GetAttachedProcessName(), modules: GetAttachedModuleSnapshot()) { Owner = this };
            if (dialog.ShowDialog() == true && dialog.CreatedEntry is not null)
            {
                AddWatchEntry(dialog.CreatedEntry);
            }
        }
    }

    private void ShowNearbyAddressesFromWatch_OnClick(object sender, RoutedEventArgs e)
    {
        if (!_memoryAccessor.IsAttached)
        {
            MessageBox.Show(this, "Select a process first.", "No Process", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (WatchGrid.SelectedItem is not WatchEntry selected)
        {
            return;
        }

        if (!_memoryAccessor.TryResolveWatchAddress(selected, out var resolvedAddress, out _))
        {
            MessageBox.Show(this, "Could not resolve selected entry address.", "Resolve Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        BuildNearbyCenterHeaderForWatch(selected, resolvedAddress, out var centerHeaderText, out var centerHeaderAccent);
        var pointerSeed = selected.Kind == WatchEntryKind.PointerChain && HasPointerOffsets(selected)
            ? ClonePointerSeed(selected)
            : null;
        ShowNearbyAddressesWindow(resolvedAddress, selected.DataType, centerHeaderText, centerHeaderAccent, pointerSeed);
    }

    private void ShowNearbyAddressesFromScanResult_OnClick(object sender, RoutedEventArgs e)
    {
        if (!_memoryAccessor.IsAttached)
        {
            MessageBox.Show(this, "Select a process first.", "No Process", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (ScanResultGrid.SelectedItem is not ScanResultRow row)
        {
            return;
        }

        BuildNearbyCenterHeaderForScanResult(row, out var centerHeaderText, out var centerHeaderAccent);
        ShowNearbyAddressesWindow(row.Address, row.DataType, centerHeaderText, centerHeaderAccent, null);
    }

    private void ShowNearbyAddressesWindow(
        ulong centerAddress,
        MemoryDataType dataType,
        string? centerHeaderText = null,
        bool centerHeaderAccent = false,
        WatchEntry? relativePointerSeed = null)
    {
        var viewer = new NearbyAddressesWindow(
            _memoryAccessor,
            centerAddress,
            dataType,
            centerHeaderText,
            centerHeaderAccent,
            relativePointerSeed) { Owner = this };
        viewer.QuickTakeRequested += OnNearbyQuickTakeRequested;
        if (viewer.ShowDialog() != true)
        {
            viewer.QuickTakeRequested -= OnNearbyQuickTakeRequested;
            return;
        }

        foreach (var entry in viewer.SelectedEntries)
        {
            AddWatchEntry(entry);
        }

        viewer.QuickTakeRequested -= OnNearbyQuickTakeRequested;
    }

    private void BuildNearbyCenterHeaderForWatch(WatchEntry entry, ulong resolvedAddress, out string text, out bool accent)
    {
        if (entry.Kind == WatchEntryKind.PointerChain)
        {
            accent = true;
            if (HasPointerOffsets(entry))
            {
                text = $"P-> {_memoryAccessor.FormatAddress(resolvedAddress)}";
                return;
            }

            text = FormatPointerBaseForDisplay(entry);
            return;
        }

        if (entry.IsProcessBaseDisplay)
        {
            accent = true;
            text = string.IsNullOrWhiteSpace(entry.DisplayAddress)
                ? _memoryAccessor.FormatAddress(resolvedAddress)
                : entry.DisplayAddress;
            return;
        }

        accent = false;
        text = _memoryAccessor.FormatAddress(resolvedAddress);
    }

    private void BuildNearbyCenterHeaderForScanResult(ScanResultRow row, out string text, out bool accent)
    {
        text = row.DisplayAddress;
        accent = row.IsProcessBaseDisplay;
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

    private void OnNearbyQuickTakeRequested(WatchEntry entry)
    {
        AddWatchEntry(entry);
    }

    private void OpenMemoryViewerFromWatch_OnClick(object sender, RoutedEventArgs e)
    {
        if (!_memoryAccessor.IsAttached)
        {
            MessageBox.Show(this, "Select a process first.", "No Process", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (WatchGrid.SelectedItem is not WatchEntry selected)
        {
            return;
        }

        if (!_memoryAccessor.TryResolveWatchAddress(selected, out var resolvedAddress, out _))
        {
            MessageBox.Show(this, "Could not resolve selected entry address.", "Resolve Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        OpenMemoryViewerWindow(resolvedAddress);
    }

    private void OpenMemoryViewerFromScanResult_OnClick(object sender, RoutedEventArgs e)
    {
        if (!_memoryAccessor.IsAttached)
        {
            MessageBox.Show(this, "Select a process first.", "No Process", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (ScanResultGrid.SelectedItem is not ScanResultRow row)
        {
            return;
        }

        OpenMemoryViewerWindow(row.Address);
    }

    private void OpenMemoryViewerWindow(ulong startAddress)
    {
        var viewer = new MemoryViewerWindow(_memoryAccessor, startAddress) { Owner = this };
        viewer.ShowDialog();
    }

    private void FindWriteAccessFromWatch_OnClick(object sender, RoutedEventArgs e)
    {
        if (!_memoryAccessor.IsAttached)
        {
            MessageBox.Show(this, "Select a process first.", "No Process", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (WatchGrid.SelectedItem is not WatchEntry selected)
        {
            return;
        }

        if (!_memoryAccessor.TryResolveWatchAddress(selected, out var resolvedAddress, out _))
        {
            MessageBox.Show(this, "Could not resolve selected entry address.", "Resolve Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        OpenWriteAccessTracerWindow(resolvedAddress, selected.DataType);
    }

    private void FindWriteAccessFromScanResult_OnClick(object sender, RoutedEventArgs e)
    {
        if (!_memoryAccessor.IsAttached)
        {
            MessageBox.Show(this, "Select a process first.", "No Process", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (ScanResultGrid.SelectedItem is not ScanResultRow row)
        {
            return;
        }

        OpenWriteAccessTracerWindow(row.Address, row.DataType);
    }

    private void OpenWriteAccessTracerWindow(ulong address, MemoryDataType dataType)
    {
        var tracer = new WriteAccessTracerWindow(
            _memoryAccessor,
            address,
            dataType,
            (baseAddress, selectedType, initialOptions) => OpenPointerScannerWithAddress(baseAddress, selectedType, initialOptions))
        {
            Owner = this
        };

        tracer.ShowDialog();
    }

    private void MenuLoadWatchList_OnClick(object sender, RoutedEventArgs e)
    {
        LoadWatchList_OnClick(sender, e);
    }

    private void MenuSaveWatchList_OnClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_currentWatchListFilePath))
        {
            SaveWatchListAs();
            return;
        }

        SaveWatchListToPath(_currentWatchListFilePath);
    }

    private void MenuSaveWatchListAs_OnClick(object sender, RoutedEventArgs e)
    {
        SaveWatchListAs();
    }

    private void MenuExit_OnClick(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private void MenuAbout_OnClick(object sender, RoutedEventArgs e)
    {
        MessageBox.Show(this,
            "MemoryScanner\nLightweight RAM scanner with address and pointer scan.",
            "About MemoryScanner",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }
    private void SaveWatchList_OnClick(object sender, RoutedEventArgs e)
    {
        SaveWatchListAs();
    }

    private bool SaveWatchListAs()
    {
        var saveDialog = new SaveFileDialog
        {
            Filter = "MemoryScanner Profile (*.json)|*.json|All files (*.*)|*.*",
            DefaultExt = ".json",
            FileName = string.IsNullOrWhiteSpace(_currentWatchListFilePath) ? string.Empty : Path.GetFileName(_currentWatchListFilePath)
        };

        if (saveDialog.ShowDialog(this) != true)
        {
            return false;
        }

        SaveWatchListToPath(saveDialog.FileName);
        return true;
    }

    private void SaveWatchListToPath(string filePath)
    {
        var processName = _memoryAccessor.IsAttached ? _memoryAccessor.Process.ProcessName : string.Empty;

        try
        {
            _profileStorageService.Save(filePath, processName, _watchEntries);
            _currentWatchListFilePath = filePath;
            UpdateWindowTitle();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Save Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void LoadWatchList_OnClick(object sender, RoutedEventArgs e)
    {
        var openDialog = new OpenFileDialog
        {
            Filter = "MemoryScanner Profile (*.json)|*.json|All files (*.*)|*.*"
        };

        if (openDialog.ShowDialog(this) != true)
        {
            return;
        }

        try
        {
            var loaded = _profileStorageService.Load(openDialog.FileName);
            _watchEntries.Clear();
            foreach (var entry in loaded.Entries)
            {
                AddWatchEntry(entry, refreshNow: false);
            }

            _currentWatchListFilePath = openDialog.FileName;
            UpdateWindowTitle();
            RefreshWatchValues();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Load Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void RefreshTimer_OnTick(object? sender, EventArgs e)
    {
        RefreshWatchValuesIncremental();
        ApplyFreezeValues();
    }

    private void WatchGrid_OnScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        if (!_memoryAccessor.IsAttached || _isScanRunning)
        {
            return;
        }

        if (Math.Abs(e.VerticalChange) < 0.01 && Math.Abs(e.ViewportHeightChange) < 0.01)
        {
            return;
        }

        RefreshVisibleWatchEntries();
    }

    private void RefreshWatchValues()
    {
        if (!_memoryAccessor.IsAttached)
        {
            SetWatchEntriesUnavailableIncremental();
            return;
        }

        _watchInvalidStateApplied = false;
        _watchRefreshCursor = 0;
        foreach (var entry in _watchEntries)
        {
            UpdateWatchEntryValue(entry);
        }
    }

    private void RefreshWatchValuesIncremental()
    {
        if (!_memoryAccessor.IsAttached)
        {
            SetWatchEntriesUnavailableIncremental();
            return;
        }

        _watchInvalidStateApplied = false;

        var count = _watchEntries.Count;
        if (count == 0)
        {
            return;
        }

        var visibleEntries = GetVisibleDataGridItems<WatchEntry>(WatchGrid);
        var visibleSet = visibleEntries.Count > 0 ? new HashSet<WatchEntry>(visibleEntries) : null;
        foreach (var entry in visibleEntries)
        {
            UpdateWatchEntryValue(entry);
        }

        if (_watchRefreshCursor >= count)
        {
            _watchRefreshCursor = 0;
        }

        var backgroundBudget = Math.Min(count, ComputeRefreshBatchSize(count, MinWatchRefreshBatchSize, MaxWatchRefreshBatchSize));
        var updated = 0;
        var attempts = 0;
        while (updated < backgroundBudget && attempts < count)
        {
            if (_watchRefreshCursor >= count)
            {
                _watchRefreshCursor = 0;
            }

            var entry = _watchEntries[_watchRefreshCursor];
            _watchRefreshCursor++;
            attempts++;

            if (visibleSet is not null && visibleSet.Contains(entry))
            {
                continue;
            }

            UpdateWatchEntryValue(entry);
            updated++;
        }
    }

    private void RefreshVisibleWatchEntries()
    {
        foreach (var entry in GetVisibleDataGridItems<WatchEntry>(WatchGrid))
        {
            UpdateWatchEntryValue(entry);
        }
    }

    private void RefreshVisibleScanResultRows()
    {
        foreach (var row in GetVisibleDataGridItems<ScanResultRow>(ScanResultGrid))
        {
            UpdateScanResultRowValue(row);
        }
    }

    private void SetWatchEntriesUnavailableIncremental()
    {
        var count = _watchEntries.Count;
        if (count == 0)
        {
            return;
        }

        var visibleEntries = GetVisibleDataGridItems<WatchEntry>(WatchGrid);
        var visibleSet = visibleEntries.Count > 0 ? new HashSet<WatchEntry>(visibleEntries) : null;
        foreach (var entry in visibleEntries)
        {
            entry.LastValueText = UnavailableValueText;
            entry.Status = "Invalid";
        }

        if (_watchRefreshCursor >= count)
        {
            _watchRefreshCursor = 0;
        }

        var backgroundBudget = Math.Min(count, ComputeRefreshBatchSize(count, MinWatchRefreshBatchSize, MaxWatchRefreshBatchSize));
        var updated = 0;
        var attempts = 0;
        while (updated < backgroundBudget && attempts < count)
        {
            if (_watchRefreshCursor >= count)
            {
                _watchRefreshCursor = 0;
            }

            var entry = _watchEntries[_watchRefreshCursor];
            _watchRefreshCursor++;
            attempts++;

            if (visibleSet is not null && visibleSet.Contains(entry))
            {
                continue;
            }

            entry.LastValueText = UnavailableValueText;
            entry.Status = "Invalid";
            updated++;
        }
    }

    private void SetScanResultValuesUnavailableIncremental()
    {
        var count = _scanResults.Count;
        if (count == 0)
        {
            return;
        }

        var visibleRows = GetVisibleDataGridItems<ScanResultRow>(ScanResultGrid);
        var visibleSet = visibleRows.Count > 0 ? new HashSet<ScanResultRow>(visibleRows) : null;
        foreach (var row in visibleRows)
        {
            row.ValueText = UnavailableValueText;
        }

        if (_scanResultRefreshCursor >= count)
        {
            _scanResultRefreshCursor = 0;
        }

        var backgroundBudget = Math.Min(count, ComputeRefreshBatchSize(count, MinScanResultRefreshBatchSize, MaxScanResultRefreshBatchSize));
        var updated = 0;
        var attempts = 0;
        while (updated < backgroundBudget && attempts < count)
        {
            if (_scanResultRefreshCursor >= count)
            {
                _scanResultRefreshCursor = 0;
            }

            var row = _scanResults[_scanResultRefreshCursor];
            _scanResultRefreshCursor++;
            attempts++;

            if (visibleSet is not null && visibleSet.Contains(row))
            {
                continue;
            }

            row.ValueText = UnavailableValueText;
            updated++;
        }
    }

    private void UpdateWatchEntryValue(WatchEntry entry)
    {
        if (!_memoryAccessor.TryResolveWatchAddress(entry, out var address, out var displayAddress))
        {
            if (entry.Kind == WatchEntryKind.PointerChain)
            {
                entry.DisplayAddress = HasPointerOffsets(entry)
                    ? "P-> <unresolved>"
                    : FormatPointerBaseForDisplay(entry);
                entry.IsProcessBaseDisplay = true;
            }

            entry.Status = "Invalid";
            return;
        }

        if (entry.Kind == WatchEntryKind.PointerChain)
        {
            entry.DisplayAddress = HasPointerOffsets(entry)
                ? $"P-> {_memoryAccessor.FormatAddress(address)}"
                : displayAddress;
            entry.IsProcessBaseDisplay = true;
        }
        else
        {
            entry.DisplayAddress = displayAddress;
            entry.IsProcessBaseDisplay = IsProcessBaseAddressText(displayAddress);
        }

        if (_memoryAccessor.TryReadValue(address, entry.DataType, out var value))
        {
            entry.LastValueText = FormatValue(value);
            entry.Status = "Valid";
        }
        else
        {
            entry.Status = "Invalid";
        }
    }

    private void ApplyFreezeValues()
    {
        if (!_memoryAccessor.IsAttached)
        {
            return;
        }

        foreach (var entry in _watchEntries)
        {
            if (!entry.IsFrozen)
            {
                continue;
            }

            if (!_memoryAccessor.TryResolveWatchAddress(entry, out var address, out _))
            {
                entry.Status = "Invalid";
                continue;
            }

            if (!ScanService.TryParseValue(entry.DataType, entry.FreezeValueText, out var valueToWrite))
            {
                continue;
            }

            if (!_memoryAccessor.TryWriteValue(address, entry.DataType, valueToWrite))
            {
                entry.Status = "Invalid";
            }
        }
    }

    private void AddWatchEntry(WatchEntry entry, bool refreshNow = true)
    {
        if (entry.Id == Guid.Empty)
        {
            entry.Id = Guid.NewGuid();
        }

        UpdateWatchDisplayForCurrentState(entry);

        if (string.IsNullOrWhiteSpace(entry.FreezeValueText))
        {
            entry.FreezeValueText = entry.LastValueText;
        }

        entry.Status = "Unknown";
        _watchEntries.Add(entry);
        _watchInvalidStateApplied = false;

        if (refreshNow)
        {
            RefreshWatchValues();
        }
    }

    private void UpdateAllWatchDisplayAddresses()
    {
        foreach (var entry in _watchEntries)
        {
            UpdateWatchDisplayForCurrentState(entry);
        }
    }

    private void CaptureDirectEntryModuleReference(WatchEntry entry)
    {
        if (!_memoryAccessor.IsAttached || entry.Kind != WatchEntryKind.DirectAddress)
        {
            return;
        }

        var module = _memoryAccessor.Modules.FirstOrDefault(m => m.Contains(entry.DirectAddress));
        if (module is null)
        {
            return;
        }

        entry.PointerBaseModuleName = module.Name;
        entry.PointerBaseModuleOffset = entry.DirectAddress - module.Base;
    }

    private void TryRebaseDirectEntryFromModuleReference(WatchEntry entry)
    {
        if (!_memoryAccessor.IsAttached || entry.Kind != WatchEntryKind.DirectAddress)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(entry.PointerBaseModuleName))
        {
            return;
        }

        var moduleByName = _memoryAccessor.Modules.FirstOrDefault(m =>
            string.Equals(m.Name, entry.PointerBaseModuleName, StringComparison.OrdinalIgnoreCase));

        if (moduleByName is null)
        {
            return;
        }

        entry.DirectAddress = moduleByName.Base + entry.PointerBaseModuleOffset;
    }

    private void TryRebasePointerEntryFromModuleReference(WatchEntry entry)
    {
        if (!_memoryAccessor.IsAttached || entry.Kind != WatchEntryKind.PointerChain)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(entry.PointerBaseModuleName))
        {
            return;
        }

        var moduleByName = _memoryAccessor.Modules.FirstOrDefault(m =>
            string.Equals(m.Name, entry.PointerBaseModuleName, StringComparison.OrdinalIgnoreCase));

        if (moduleByName is null)
        {
            return;
        }

        entry.PointerBaseAddress = moduleByName.Base + entry.PointerBaseModuleOffset;
    }

    private bool TryGetScanInput(out MemoryDataType dataType, out ScanComparison comparison, out string valueText, out string valueTextTo)
    {
        dataType = MemoryDataType.Int32;
        comparison = ScanComparison.Equal;
        var rawValueText = ScanValueText.Text;
        var rawValueTextTo = ScanValueToText.Text;
        valueText = rawValueText.Trim();
        valueTextTo = rawValueTextTo.Trim();

        if (ScanTypeBox.SelectedItem is not MemoryDataType selectedType)
        {
            MessageBox.Show(this, "Select data type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        if (ScanComparisonBox.SelectedItem is not ScanComparisonOption selectedComparison)
        {
            MessageBox.Show(this, "Select condition.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        dataType = selectedType;
        comparison = selectedComparison.Value;

        if (dataType == MemoryDataType.String)
        {
            valueText = rawValueText;
            valueTextTo = rawValueTextTo;

            if (comparison is not (ScanComparison.Equal or ScanComparison.NotEqual))
            {
                MessageBox.Show(this, "String scans currently support only Equal and Not Equal.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
        }

        if (comparison == ScanComparison.UnknownInitial)
        {
            return true;
        }

        if (comparison == ScanComparison.Between)
        {
            if (!ScanService.TryParseValue(dataType, valueText, out _) || !ScanService.TryParseValue(dataType, valueTextTo, out _))
            {
                MessageBox.Show(this, "Invalid range values for selected type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            return true;
        }

        var inputRequired = comparison is ScanComparison.Equal or ScanComparison.NotEqual or ScanComparison.Greater or ScanComparison.Less;
        if (inputRequired && !ScanService.TryParseValue(dataType, valueText, out _))
        {
            MessageBox.Show(this, "Invalid value for selected type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        return true;
    }

    private void SetScanResults(IReadOnlyList<ScanResult> results)
    {
        _allScanResults.Clear();
        if (_allScanResults.Capacity < results.Count)
        {
            _allScanResults.Capacity = results.Count;
        }

        var displayContext = new ScanResultDisplayContext(_memoryAccessor);
        foreach (var result in results)
        {
            _allScanResults.Add(new ScanResultRow(result, displayContext));
        }

        _scanResultRefreshCursor = 0;
        _scanResults.ReplaceAll(_allScanResults);
        UpdateTakeSelectedButtonState();
    }

    private static int ComputeRefreshBatchSize(int totalCount, int minBatchSize, int maxBatchSize)
    {
        if (totalCount <= 0)
        {
            return 0;
        }

        var scaled = totalCount / 20;
        return Math.Clamp(scaled, minBatchSize, maxBatchSize);
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

    private static string FormatValue(object value)
    {
        return value switch
        {
            float f => f.ToString("0.######", System.Globalization.CultureInfo.InvariantCulture),
            double d => d.ToString("0.######", System.Globalization.CultureInfo.InvariantCulture),
            _ => Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty
        };
    }

    private string BuildWatchEntryCopyText()
    {
        var builder = new StringBuilder();
        foreach (var entry in _watchEntries)
        {
            var name = string.IsNullOrWhiteSpace(entry.Name) ? "Entry" : entry.Name.Trim();
            var addressPart = BuildWatchEntryAddressForCopy(entry);
            builder.Append(name);
            builder.Append('=');
            builder.Append(addressPart);
            builder.AppendLine();
        }

        return builder.ToString().TrimEnd();
    }

    private static string BuildWatchEntryAddressForCopy(WatchEntry entry)
    {
        var hasModuleBase = !string.IsNullOrWhiteSpace(entry.PointerBaseModuleName);
        var baseValue = entry.Kind == WatchEntryKind.DirectAddress
            ? (hasModuleBase ? entry.PointerBaseModuleOffset : entry.DirectAddress)
            : (hasModuleBase ? entry.PointerBaseModuleOffset : entry.PointerBaseAddress);

        var baseText = baseValue.ToString("X");
        if (entry.Kind != WatchEntryKind.PointerChain || entry.Offsets is not { Count: > 0 })
        {
            return baseText;
        }

        var offsets = entry.Offsets.Select(FormatSignedOffsetHex);
        return $"{baseText},{string.Join(",", offsets)}";
    }

    private static string FormatSignedOffsetHex(int offset)
    {
        if (offset >= 0)
        {
            return offset.ToString("X");
        }

        var abs = Math.Abs((long)offset);
        return $"-{abs:X}";
    }

    private void ShowCopyWatchListDialog(string content)
    {
        var window = new Window
        {
            Title = "Copy Watch Entries",
            Width = 680,
            Height = 460,
            MinWidth = 520,
            MinHeight = 340,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = this
        };

        var root = new Grid { Margin = new Thickness(10) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var text = new TextBlock
        {
            Text = "Format: NAME=BASE[,OFFSET...]. Process name is omitted.",
            Margin = new Thickness(0, 0, 0, 8)
        };
        Grid.SetRow(text, 0);
        root.Children.Add(text);

        var textBox = new TextBox
        {
            Text = content,
            IsReadOnly = true,
            AcceptsReturn = true,
            AcceptsTab = true,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            TextWrapping = TextWrapping.NoWrap
        };
        Grid.SetRow(textBox, 1);
        root.Children.Add(textBox);

        var buttonRow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 10, 0, 0)
        };

        var copyButton = new Button
        {
            Content = "Copy All",
            Width = 100,
            Height = 30,
            Margin = new Thickness(0, 0, 8, 0),
            IsDefault = true
        };

        var closeButton = new Button
        {
            Content = "Close",
            Width = 100,
            Height = 30,
            IsCancel = true
        };

        copyButton.Click += (_, _) =>
        {
            try
            {
                Clipboard.SetText(textBox.Text ?? string.Empty);
                textBox.Focus();
                textBox.SelectAll();
            }
            catch (Exception ex)
            {
                MessageBox.Show(window, ex.Message, "Clipboard Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        };

        closeButton.Click += (_, _) => window.Close();

        buttonRow.Children.Add(copyButton);
        buttonRow.Children.Add(closeButton);

        Grid.SetRow(buttonRow, 2);
        root.Children.Add(buttonRow);

        window.Content = root;
        window.ShowDialog();
    }

    private static bool IsOnlyCancellation(AggregateException ex)
    {
        return ex.Flatten().InnerExceptions.All(inner => inner is OperationCanceledException);
    }

    private static T? FindVisualParent<T>(DependencyObject? current) where T : DependencyObject
    {
        while (current is not null)
        {
            if (current is T typed)
            {
                return typed;
            }

            current = VisualTreeHelper.GetParent(current);
        }

        return null;
    }

    private static IReadOnlyList<T> GetVisibleDataGridItems<T>(DataGrid grid) where T : class
    {
        var indexedItems = new List<(int Index, T Item)>();
        foreach (var row in FindVisualChildren<DataGridRow>(grid))
        {
            if (!row.IsVisible)
            {
                continue;
            }

            var index = row.GetIndex();
            if (index < 0 || index >= grid.Items.Count)
            {
                continue;
            }

            if (grid.Items[index] is T item)
            {
                indexedItems.Add((index, item));
            }
        }

        if (indexedItems.Count <= 1)
        {
            return indexedItems.Select(x => x.Item).ToArray();
        }

        indexedItems.Sort((a, b) => a.Index.CompareTo(b.Index));
        var deduplicated = new List<T>(indexedItems.Count);
        var lastIndex = -1;
        foreach (var entry in indexedItems)
        {
            if (entry.Index == lastIndex)
            {
                continue;
            }

            deduplicated.Add(entry.Item);
            lastIndex = entry.Index;
        }

        return deduplicated;
    }

    private static IEnumerable<T> FindVisualChildren<T>(DependencyObject? parent) where T : DependencyObject
    {
        if (parent is null)
        {
            yield break;
        }

        var childCount = VisualTreeHelper.GetChildrenCount(parent);
        for (var i = 0; i < childCount; i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T typedChild)
            {
                yield return typedChild;
            }

            foreach (var descendant in FindVisualChildren<T>(child))
            {
                yield return descendant;
            }
        }
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

    private MemoryDataType? PromptForDataType(MemoryDataType current)
    {
        var window = new Window
        {
            Title = "Edit Data Type",
            Width = 360,
            Height = 170,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = this,
            ResizeMode = ResizeMode.NoResize
        };

        var root = new Grid { Margin = new Thickness(10) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var text = new TextBlock { Text = "Select data type:", Margin = new Thickness(0, 0, 0, 8) };
        Grid.SetRow(text, 0);
        root.Children.Add(text);

        var combo = new ComboBox { Margin = new Thickness(0, 0, 0, 12), ItemsSource = MemoryDataTypeUiOrder.Ordered };
        combo.SelectedItem = current;
        Grid.SetRow(combo, 1);
        root.Children.Add(combo);

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var ok = new Button { Content = "Apply", Width = 90, Height = 30, Margin = new Thickness(0, 0, 8, 0), IsDefault = true };
        var cancel = new Button { Content = "Cancel", Width = 90, Height = 30, IsCancel = true };

        ok.Click += (_, _) => window.DialogResult = true;
        cancel.Click += (_, _) => window.DialogResult = false;

        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);

        Grid.SetRow(buttons, 2);
        root.Children.Add(buttons);

        window.Content = root;

        return window.ShowDialog() == true && combo.SelectedItem is MemoryDataType selected
            ? selected
            : null;
    }

    protected override void OnClosed(EventArgs e)
    {
        _scanCts?.Cancel();
        _scanCts?.Dispose();
        _scanService.Dispose();
        UiUpdateRoutineSettings.ValueRefreshIntervalChanged -= OnGlobalValueRefreshIntervalChanged;
        _refreshTimer.Stop();
        _scanResultRefreshTimer.Stop();
        _memoryAccessor.Detach();
        base.OnClosed(e);
    }


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

    public sealed class BulkObservableCollection<T> : ObservableCollection<T>
    {
        public void ReplaceAll(IEnumerable<T> items)
        {
            CheckReentrancy();
            Items.Clear();
            foreach (var item in items)
            {
                Items.Add(item);
            }

            OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
            OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
            OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
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























