using MemoryScanner.Core;
using MemoryScanner.Models;
using MemoryScanner.Windows;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace MemoryScanner;

public partial class MainWindow : Window
{
    private const int ShowAllPageSize = -1;
    private const int MinWatchRefreshBatchSize = 24;
    private const int MaxWatchRefreshBatchSize = 256;
    private const int MinScanResultRefreshBatchSize = 32;
    private const int MaxScanResultRefreshBatchSize = 512;
    private readonly ObservableCollection<WatchEntry> _watchEntries = new();
    private readonly ObservableCollection<ScanResultRow> _scanResults = new();
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
    private ScanExecutionOptions _scanOptions = new();
    private int _scanResultPageSize = ShowAllPageSize;
    private int _scanResultPageIndex;
    private bool _resumeWatchRefreshAfterScan;
    private bool _resumeScanResultRefreshAfterScan;
    private string? _currentWatchListFilePath;
    private int _watchRefreshCursor;
    private int _scanResultRefreshCursor;
    private bool _watchInvalidStateApplied;

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

        ScanComparisonBox.ItemsSource = Enum.GetValues<ScanComparison>();
        ScanComparisonBox.SelectedItem = ScanComparison.Equal;
        PageSizeBox.ItemsSource = new[] { "25", "50", "100", "500", "All Entries" };
        PageSizeBox.SelectedIndex = 4;

        _refreshTimer = new DispatcherTimer();
        _refreshTimer.Tick += RefreshTimer_OnTick;

        _scanResultRefreshTimer = new DispatcherTimer();
        _scanResultRefreshTimer.Tick += ScanResultRefreshTimer_OnTick;

        UiUpdateRoutineSettings.ValueRefreshIntervalChanged += OnGlobalValueRefreshIntervalChanged;
        ApplyGlobalValueRefreshInterval(UiUpdateRoutineSettings.ValueRefreshIntervalMs);

        UpdateScanResultPageUi();
        SetScanIdleUi();
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

        var baseLabel = _memoryAccessor.IsAttached
            ? _memoryAccessor.FormatAddress(entry.PointerBaseAddress)
            : (string.IsNullOrWhiteSpace(entry.PointerBaseModuleName)
                ? $"0x{entry.PointerBaseAddress:X}"
                : $"{entry.PointerBaseModuleName}+0x{entry.PointerBaseModuleOffset:X}");

        entry.DisplayAddress = BuildPointerDisplayAddress(baseLabel, entry.Offsets);
        entry.IsProcessBaseDisplay = IsProcessBaseAddressText(entry.DisplayAddress);
    }

    private static string BuildPointerDisplayAddress(string baseLabel, IEnumerable<int> offsets)
    {
        var offsetText = AddressParser.OffsetsToText(offsets);
        if (string.IsNullOrWhiteSpace(offsetText))
        {
            return baseLabel;
        }

        return $"{baseLabel} [{offsetText}]";
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
        _allScanResults.Clear();
        _scanResults.Clear();
        _scanResultRefreshCursor = 0;
        _scanResultPageIndex = 0;
        UpdateScanResultPageUi();
        ScanProgressBar.Value = 0;
        UpdateIdleProgressText();
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

    private void UpdateScanResultRowValue(ScanResultRow row)
    {
        if (_memoryAccessor.TryReadValue(row.Address, row.DataType, out var value))
        {
            row.ValueText = FormatValue(value);
        }
        else
        {
            row.ValueText = "<invalid>";
        }
    }

    private async Task RunScanAsync(bool isFirstScan)
    {
        if (_isScanRunning)
        {
            return;
        }

        if (!TryGetScanInput(out var dataType, out var comparison, out var valueText))
        {
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
                ? await Task.Run(() => _scanService.FirstScan(dataType, comparison, valueText, _scanOptions, progress, token), token)
                : await Task.Run(() => _scanService.NextScan(dataType, comparison, valueText, _scanOptions, progress, token), token);

            SetScanResults(results);
            ScanProgressBar.Value = 100;
            ScanProgressText.Text = $"Scan finished ({results.Count} results)";
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

        FirstScanButton.IsEnabled = false;
        NextScanButton.IsEnabled = false;
        ResetScanButton.IsEnabled = false;
        ScanOptionsButton.IsEnabled = false;
        ScanButtonsPanel.Visibility = Visibility.Collapsed;
        CancelScanPanel.Visibility = Visibility.Visible;
        CancelScanButton.IsEnabled = true;
        ScanProgressBar.Value = 0;
        ScanProgressText.Text = "Preparing scan...";
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

        FirstScanButton.IsEnabled = true;
        NextScanButton.IsEnabled = true;
        ResetScanButton.IsEnabled = true;
        ScanOptionsButton.IsEnabled = true;
        ScanButtonsPanel.Visibility = Visibility.Visible;
        CancelScanPanel.Visibility = Visibility.Collapsed;
        UpdateIdleProgressText();
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
        var limitText = _scanOptions.UseResultLimit ? _scanOptions.ResultLimit.ToString() : "off";
        var updateMsText = UiUpdateRoutineSettings.ValueRefreshIntervalMs;
        ScanProgressText.Text = $"Idle | Options: {_scanOptions.DepthProfile}, Threads {_scanOptions.ThreadCount}, Limit {limitText}, Update {updateMsText} ms";
    }

    private void ScanResultGrid_OnMouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        TakeSelectedScanResult_OnClick(sender, e);
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

    private void OpenPointerScannerWithAddress(ulong address, MemoryDataType initialType)
    {
        var pointerWindow = new PointerScanWindow(_pointerScanService, _memoryAccessor, address, initialType) { Owner = this };
        if (pointerWindow.ShowDialog() != true)
        {
            return;
        }

        var selectedType = pointerWindow.SelectedValueDataType;
        foreach (var path in pointerWindow.SelectedPaths)
        {
            var dialog = new AddWatchEntryWindow(path, selectedType, processName: GetAttachedProcessName(), modules: GetAttachedModuleSnapshot()) { Owner = this };
            if (dialog.ShowDialog() == true && dialog.CreatedEntry is not null)
            {
                AddWatchEntry(dialog.CreatedEntry);
            }
        }
    }

    private void ShowMemoryRegionFromWatch_OnClick(object sender, RoutedEventArgs e)
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

        ShowMemoryRegionWindow(resolvedAddress, selected.DataType);
    }

    private void ShowMemoryRegionFromScanResult_OnClick(object sender, RoutedEventArgs e)
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

        ShowMemoryRegionWindow(row.Address, row.DataType);
    }

    private void ShowMemoryRegionWindow(ulong centerAddress, MemoryDataType dataType)
    {
        var viewer = new MemoryRegionWindow(_memoryAccessor, centerAddress, dataType) { Owner = this };
        if (viewer.ShowDialog() != true)
        {
            return;
        }

        foreach (var entry in viewer.SelectedEntries)
        {
            AddWatchEntry(entry);
        }
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
            SetWatchEntriesInvalidIfNeeded();
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
            SetWatchEntriesInvalidIfNeeded();
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

    private void SetWatchEntriesInvalidIfNeeded()
    {
        if (_watchInvalidStateApplied)
        {
            return;
        }

        foreach (var entry in _watchEntries)
        {
            entry.Status = "Invalid";
        }

        _watchInvalidStateApplied = true;
        _watchRefreshCursor = 0;
    }

    private void UpdateWatchEntryValue(WatchEntry entry)
    {
        if (!_memoryAccessor.TryResolveWatchAddress(entry, out var address, out var displayAddress))
        {
            entry.Status = "Invalid";
            return;
        }

        entry.DisplayAddress = displayAddress;
        entry.IsProcessBaseDisplay = IsProcessBaseAddressText(displayAddress);

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

    private bool TryGetScanInput(out MemoryDataType dataType, out ScanComparison comparison, out string valueText)
    {
        dataType = MemoryDataType.Int32;
        comparison = ScanComparison.Equal;
        valueText = ScanValueText.Text.Trim();

        if (ScanTypeBox.SelectedItem is not MemoryDataType selectedType)
        {
            MessageBox.Show(this, "Select data type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        if (ScanComparisonBox.SelectedItem is not ScanComparison selectedComparison)
        {
            MessageBox.Show(this, "Select condition.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        dataType = selectedType;
        comparison = selectedComparison;

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
        foreach (var result in results)
        {
            var displayAddress = _memoryAccessor.IsAttached
                ? _memoryAccessor.FormatAddress(result.Address)
                : $"0x{result.Address:X}";
            _allScanResults.Add(new ScanResultRow(result, displayAddress, IsProcessBaseAddressText(displayAddress)));
        }

        _scanResultPageIndex = 0;
        ApplyScanResultPagination();
    }

    private void PageSizeBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (PageSizeBox.SelectedItem is not string selected)
        {
            return;
        }

        _scanResultPageSize = selected.Contains("all", StringComparison.OrdinalIgnoreCase)
            ? ShowAllPageSize
            : int.TryParse(selected, out var parsed) ? Math.Max(1, parsed) : 100;

        _scanResultPageIndex = 0;
        ApplyScanResultPagination();
    }

    private void PrevPage_OnClick(object sender, RoutedEventArgs e)
    {
        if (_scanResultPageIndex <= 0)
        {
            return;
        }

        _scanResultPageIndex--;
        ApplyScanResultPagination();
    }

    private void NextPage_OnClick(object sender, RoutedEventArgs e)
    {
        var pageCount = GetScanResultPageCount();
        if (_scanResultPageIndex >= pageCount - 1)
        {
            return;
        }

        _scanResultPageIndex++;
        ApplyScanResultPagination();
    }

    private void ApplyScanResultPagination()
    {
        _scanResultRefreshCursor = 0;
        _scanResults.Clear();

        if (_allScanResults.Count == 0)
        {
            UpdateScanResultPageUi();
            return;
        }

        if (_scanResultPageSize == ShowAllPageSize)
        {
            foreach (var row in _allScanResults)
            {
                _scanResults.Add(row);
            }

            _scanResultPageIndex = 0;
            UpdateScanResultPageUi();
            return;
        }

        var pageCount = GetScanResultPageCount();
        if (_scanResultPageIndex >= pageCount)
        {
            _scanResultPageIndex = Math.Max(0, pageCount - 1);
        }

        var startIndex = _scanResultPageIndex * _scanResultPageSize;
        var count = Math.Min(_scanResultPageSize, _allScanResults.Count - startIndex);
        for (var i = 0; i < count; i++)
        {
            _scanResults.Add(_allScanResults[startIndex + i]);
        }

        UpdateScanResultPageUi();
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

    private int GetScanResultPageCount()
    {
        if (_allScanResults.Count == 0 || _scanResultPageSize == ShowAllPageSize)
        {
            return 1;
        }

        return Math.Max(1, (_allScanResults.Count + _scanResultPageSize - 1) / _scanResultPageSize);
    }

    private void UpdateScanResultPageUi()
    {
        var pageCount = GetScanResultPageCount();
        var current = _allScanResults.Count == 0 ? 0 : _scanResultPageIndex + 1;
        PageInfoText.Text = $"{current}/{pageCount}";
        ShowingInfoText.Text = $"Showing {_scanResults.Count} of {_allScanResults.Count}";

        var pagingActive = _allScanResults.Count > 0 && _scanResultPageSize != ShowAllPageSize;
        PrevPageButton.IsEnabled = pagingActive && _scanResultPageIndex > 0;
        NextPageButton.IsEnabled = pagingActive && _scanResultPageIndex < pageCount - 1;
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
        UiUpdateRoutineSettings.ValueRefreshIntervalChanged -= OnGlobalValueRefreshIntervalChanged;
        _refreshTimer.Stop();
        _scanResultRefreshTimer.Stop();
        _memoryAccessor.Detach();
        base.OnClosed(e);
    }

    public sealed class ScanResultRow : INotifyPropertyChanged
    {
        private string _valueText;

        public ScanResultRow(ScanResult result, string displayAddress, bool isProcessBaseDisplay)
        {
            Address = result.Address;
            DisplayAddress = displayAddress;
            IsProcessBaseDisplay = isProcessBaseDisplay;
            DataType = result.DataType;
            _valueText = result.ValueText;
            AddressHex = $"0x{result.Address:X}";
        }

        public ulong Address { get; }
        public string AddressHex { get; }
        public string DisplayAddress { get; }
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
        public bool IsProcessBaseDisplay { get; }
        public MemoryDataType DataType { get; }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
