using MemoryScanner.Core;
using MemoryScanner.Models;
using MemoryScanner.Windows.Shared;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Runtime;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace MemoryScanner.Windows;

public partial class PointerScanWindow : Window
{
    private const string UnavailableValueText = "???";
    private const int MinPointerRefreshBatchSize = 32;
    private const int MaxPointerRefreshBatchSize = 512;
    private const int SaveWriteChunkSize = 1024 * 1024;
    private const int LoadReadChunkSize = 1024 * 1024;
    private readonly PointerScanService _pointerScanService;
    private readonly IMemoryAccessor _memoryAccessor;
    private readonly PointerDisplayContext _displayContext;
    private MemoryDataType _selectedValueDataType;
    private readonly DispatcherTimer _valueRefreshTimer;

    private ulong _targetAddress;
    private CancellationTokenSource? _scanCts;
    private bool _isScanRunning;
    private bool _isSaveRunning;
    private bool _isLoadRunning;
    private PointerScanOptions _runtimeOptions = new();
    private PointerSessionSaveOptions _saveOptions = new();
    private PointerSaveProgressWindow? _saveProgressWindow;
    private PointerLoadProgressWindow? _loadProgressWindow;
    private string? _currentSessionFilePath;
    private int _pointerRefreshCursor;
    private bool _cancelRequestedByUser;
    private DateTime _mergePhaseStartedUtc = DateTime.MinValue;
    private long _mergePhaseTotal;

    public BulkObservableCollection<PointerPathRow> Rows { get; } = new();

    public List<PointerPath> SelectedPaths { get; private set; } = new();
    public MemoryDataType SelectedValueDataType => _selectedValueDataType;
    public event Action<PointerScanWindow, IReadOnlyList<PointerPath>, MemoryDataType>? TakeSelectedRequested;

    public PointerScanWindow(
        PointerScanService pointerScanService,
        IMemoryAccessor memoryAccessor,
        ulong targetAddress,
        MemoryDataType valueDataType,
        PointerScanOptions? initialOptions = null)
    {
        _pointerScanService = pointerScanService;
        _memoryAccessor = memoryAccessor;
        _displayContext = new PointerDisplayContext(memoryAccessor);
        _targetAddress = targetAddress;
        _selectedValueDataType = valueDataType;
        _runtimeOptions = CloneOptions(initialOptions) ?? new PointerScanOptions();

        InitializeComponent();
        ResultGrid.ItemsSource = Rows;

        TargetAddressText.Text = $"0x{_targetAddress:X}";
        ValueDataTypeBox.ItemsSource = MemoryDataTypeUiOrder.Ordered;
        ValueDataTypeBox.SelectedItem = _selectedValueDataType;


        _valueRefreshTimer = new DispatcherTimer();
        _valueRefreshTimer.Tick += ValueRefreshTimer_OnTick;
        UiUpdateRoutineSettings.ValueRefreshIntervalChanged += OnGlobalValueRefreshIntervalChanged;
        ApplyGlobalValueRefreshInterval(UiUpdateRoutineSettings.ValueRefreshIntervalMs);

        UpdateOptionsText();
        SetIdleUi();
        UpdateWindowTitle();
    }


    private static PointerScanOptions? CloneOptions(PointerScanOptions? source)
    {
        if (source is null)
        {
            return null;
        }

        return new PointerScanOptions
        {
            MaxDepth = source.MaxDepth,
            MaxOffset = source.MaxOffset,
            MaxResults = source.MaxResults,
            UseResultLimit = source.UseResultLimit,
            ThreadCount = source.ThreadCount,
            Alignment = source.Alignment,
            IncludePrivate = source.IncludePrivate,
            IncludeMapped = source.IncludeMapped,
            IncludeModuleImage = source.IncludeModuleImage,
            RequireStaticRoot = source.RequireStaticRoot,
            ExcludeReadOnlyNodes = source.ExcludeReadOnlyNodes,
            NoLoopingPointers = source.NoLoopingPointers,
            StopTraversingAfterStaticRoot = source.StopTraversingAfterStaticRoot,
            AggressiveNodeDeduplication = source.AggressiveNodeDeduplication,
            AllowNegativeOffsets = source.AllowNegativeOffsets,
            PointerWidthMode = source.PointerWidthMode,
            UseAddressRange = source.UseAddressRange,
            ClampSearchToAddressRange = source.ClampSearchToAddressRange,
            AddressRangeFrom = source.AddressRangeFrom,
            AddressRangeTo = source.AddressRangeTo,
            RequireRootInAddressRange = source.RequireRootInAddressRange,
            RequireAllNodesInAddressRange = source.RequireAllNodesInAddressRange,
            TrimMemoryAfterCancel = source.TrimMemoryAfterCancel,
            EnableDiskSpillToTemp = source.EnableDiskSpillToTemp,
            MaxTempStorageGigabytes = source.MaxTempStorageGigabytes
        };
    }

    private async void MenuLoadResults_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning || _isSaveRunning || _isLoadRunning)
        {
            return;
        }

        await LoadResultsFromDialogAsync();
    }

    private async void MenuSaveResults_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning || _isSaveRunning || _isLoadRunning)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(_currentSessionFilePath))
        {
            await SaveResultsAsAsync();
            return;
        }

        await SaveResultsToPathAsync(_currentSessionFilePath);
    }

    private async void MenuSaveResultsAs_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning || _isSaveRunning || _isLoadRunning)
        {
            return;
        }

        await SaveResultsAsAsync();
    }

    private async void StartScan_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning || _isSaveRunning || _isLoadRunning)
        {
            return;
        }

        if (!TryBuildOptions(out var options, out var targetAddress))
        {
            MessageBox.Show(this, "Invalid pointer scan options.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _targetAddress = targetAddress;
        _scanCts?.Cancel();
        _scanCts?.Dispose();
        _scanCts = new CancellationTokenSource();
        _cancelRequestedByUser = false;
        Rows.ReplaceAll(Array.Empty<PointerPathRow>());
        _pointerRefreshCursor = 0;

        var progress = new Progress<ScanProgressInfo>(info =>
        {
            UpdateProgressUi(info);
        });

        SetBusyUi();

        try
        {
            var results = await Task.Run(() => _pointerScanService.Scan(_targetAddress, options, progress, _scanCts.Token));
            var rows = new List<PointerPathRow>(results.Count);
            foreach (var result in results)
            {
                rows.Add(CreatePointerPathRow(result));
            }

            var canceled = _scanCts?.IsCancellationRequested == true;
            Rows.ReplaceAll(rows);
            RefreshValuesAfterBulkLoad();
            if (canceled)
            {
                PointerProgressText.Text = $"Scan canceled ({results.Count} partial results)";
            }
            else
            {
                ResetMergePhaseEstimate();
                PointerPhaseText.Text = "Scanning";
                PointerProgressBar.Visibility = Visibility.Visible;
                PointerMergeProgressBar.Visibility = Visibility.Collapsed;
                PointerProgressBar.Value = 100;
                PointerProgressText.Text = $"Scan finished ({results.Count} results)";
            }
        }
        catch (OperationCanceledException)
        {
            PointerProgressText.Text = "Scan canceled";
        }
        catch (AggregateException ex) when (IsOnlyCancellation(ex))
        {
            PointerProgressText.Text = "Scan canceled";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Pointer Scan Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            var shouldTrim = _cancelRequestedByUser && _runtimeOptions.TrimMemoryAfterCancel;
            _scanCts?.Dispose();
            _scanCts = null;
            SetIdleUi();
            _cancelRequestedByUser = false;
            if (shouldTrim)
            {
                _ = TrimMemoryAfterCancelAsync();
            }
        }
    }

    private async void Rescan_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning || _isSaveRunning || _isLoadRunning)
        {
            return;
        }

        if (!_memoryAccessor.IsAttached)
        {
            MessageBox.Show(this, "Attach to a process first.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var sourcePaths = Rows.Select(r => r.Path).ToList();
        if (sourcePaths.Count == 0)
        {
            MessageBox.Show(this, "No pointer results available to rescan.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dialogAddress = _targetAddress;
        if (TryParseAddress(TargetAddressText.Text, out var parsedTargetAddress))
        {
            dialogAddress = parsedTargetAddress;
        }

        var dialog = new PointerRescanWindow(dialogAddress, _selectedValueDataType) { Owner = this };
        if (dialog.ShowDialog() != true || dialog.Request is null)
        {
            return;
        }

        var request = dialog.Request;
        if (request.Mode == PointerRescanMode.Address)
        {
            _targetAddress = request.Address;
            TargetAddressText.Text = $"0x{_targetAddress:X}";
        }

        _scanCts?.Cancel();
        _scanCts?.Dispose();
        _scanCts = new CancellationTokenSource();
        _cancelRequestedByUser = false;

        var progress = new Progress<ScanProgressInfo>(info =>
        {
            UpdateProgressUi(info);
        });

        SetBusyUi("Preparing rescan...");

        try
        {
            var rescanned = await Task.Run(() => RescanPointerPaths(sourcePaths, request, progress, _scanCts.Token));
            var rows = new List<PointerPathRow>(rescanned.Count);
            foreach (var path in rescanned)
            {
                rows.Add(CreatePointerPathRow(path));
            }

            var canceled = _scanCts?.IsCancellationRequested == true;
            Rows.ReplaceAll(rows);
            _pointerRefreshCursor = 0;
            RefreshValuesAfterBulkLoad();
            if (canceled)
            {
                PointerProgressText.Text = $"Rescan canceled ({rescanned.Count} partial results)";
            }
            else
            {
                ResetMergePhaseEstimate();
                PointerPhaseText.Text = "Scanning";
                PointerProgressBar.Visibility = Visibility.Visible;
                PointerMergeProgressBar.Visibility = Visibility.Collapsed;
                PointerProgressBar.Value = 100;
                PointerProgressText.Text = $"Rescan finished ({rescanned.Count} results)";
            }
        }
        catch (OperationCanceledException)
        {
            PointerProgressText.Text = "Rescan canceled";
        }
        catch (AggregateException ex) when (IsOnlyCancellation(ex))
        {
            PointerProgressText.Text = "Rescan canceled";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Pointer Rescan Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            var shouldTrim = _cancelRequestedByUser && _runtimeOptions.TrimMemoryAfterCancel;
            _scanCts?.Dispose();
            _scanCts = null;
            SetIdleUi();
            _cancelRequestedByUser = false;
            if (shouldTrim)
            {
                _ = TrimMemoryAfterCancelAsync();
            }
        }
    }

    private void PointerOptions_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning || _isSaveRunning || _isLoadRunning)
        {
            return;
        }

        var dialog = new PointerScanOptionsWindow(_runtimeOptions) { Owner = this };
        if (dialog.ShowDialog() != true || dialog.SelectedOptions is null)
        {
            return;
        }

        _runtimeOptions = dialog.SelectedOptions;
        UpdateOptionsText();
    }


    private void SaveOptions_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning || _isSaveRunning || _isLoadRunning)
        {
            return;
        }

        var dialog = new PointerSaveOptionsWindow(_saveOptions) { Owner = this };
        if (dialog.ShowDialog() != true || dialog.SelectedOptions is null)
        {
            return;
        }

        _saveOptions = dialog.SelectedOptions;
    }

    private void ValueDataTypeBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ValueDataTypeBox.SelectedItem is not MemoryDataType selectedType)
        {
            return;
        }

        if (_selectedValueDataType == selectedType)
        {
            return;
        }

        _selectedValueDataType = selectedType;

        // Avoid full synchronous refresh on large lists: update visible rows immediately,
        // then let the regular incremental routine refresh the rest.
        _pointerRefreshCursor = 0;
        if (Rows.Count <= 2000)
        {
            RefreshPointerValues();
        }
        else
        {
            RefreshVisiblePointerRows();
            var warmupBatch = ComputeRefreshBatchSize(Rows.Count, MinPointerRefreshBatchSize, MaxPointerRefreshBatchSize);
            RefreshPointerValuesCore(Math.Min(Rows.Count, warmupBatch));
        }
        UpdateOptionsText();
    }

    private static bool TryCompareValuesByType(MemoryDataType dataType, object left, object right, out int result)
    {
        result = 0;

        switch (dataType)
        {
            case MemoryDataType.Byte:
                if (!TryCoerce(left, out byte leftByte) || !TryCoerce(right, out byte rightByte))
                {
                    return false;
                }

                result = leftByte.CompareTo(rightByte);
                return true;

            case MemoryDataType.Int16:
                if (!TryCoerce(left, out short leftShort) || !TryCoerce(right, out short rightShort))
                {
                    return false;
                }

                result = leftShort.CompareTo(rightShort);
                return true;

            case MemoryDataType.Int32:
                if (!TryCoerce(left, out int leftInt) || !TryCoerce(right, out int rightInt))
                {
                    return false;
                }

                result = leftInt.CompareTo(rightInt);
                return true;

            case MemoryDataType.Int64:
                if (!TryCoerce(left, out long leftLong) || !TryCoerce(right, out long rightLong))
                {
                    return false;
                }

                result = leftLong.CompareTo(rightLong);
                return true;

            case MemoryDataType.Float:
                if (!TryCoerce(left, out float leftFloat) || !TryCoerce(right, out float rightFloat))
                {
                    return false;
                }

                result = leftFloat.CompareTo(rightFloat);
                return true;

            case MemoryDataType.Double:
                if (!TryCoerce(left, out double leftDouble) || !TryCoerce(right, out double rightDouble))
                {
                    return false;
                }

                result = leftDouble.CompareTo(rightDouble);
                return true;

            case MemoryDataType.String:
                result = string.CompareOrdinal(
                    Convert.ToString(left, CultureInfo.InvariantCulture) ?? string.Empty,
                    Convert.ToString(right, CultureInfo.InvariantCulture) ?? string.Empty);
                return true;

            default:
                return false;
        }
    }

    private static bool TryCoerce(object value, out byte result)
    {
        result = 0;
        return value switch
        {
            byte b => AssignTry(b, out result),
            sbyte sb when sb >= byte.MinValue => AssignTry((byte)sb, out result),
            short s when s >= byte.MinValue && s <= byte.MaxValue => AssignTry((byte)s, out result),
            ushort us when us <= byte.MaxValue => AssignTry((byte)us, out result),
            int i when i >= byte.MinValue && i <= byte.MaxValue => AssignTry((byte)i, out result),
            uint ui when ui <= byte.MaxValue => AssignTry((byte)ui, out result),
            long l when l >= byte.MinValue && l <= byte.MaxValue => AssignTry((byte)l, out result),
            ulong ul when ul <= byte.MaxValue => AssignTry((byte)ul, out result),
            float f when f >= byte.MinValue && f <= byte.MaxValue && f % 1 == 0 => AssignTry((byte)f, out result),
            double d when d >= byte.MinValue && d <= byte.MaxValue && d % 1 == 0 => AssignTry((byte)d, out result),
            _ => false
        };
    }

    private static bool TryCoerce(object value, out short result)
    {
        result = 0;
        return value switch
        {
            short s => AssignTry(s, out result),
            byte b => AssignTry((short)b, out result),
            sbyte sb => AssignTry((short)sb, out result),
            int i when i >= short.MinValue && i <= short.MaxValue => AssignTry((short)i, out result),
            long l when l >= short.MinValue && l <= short.MaxValue => AssignTry((short)l, out result),
            ushort us when us <= (ushort)short.MaxValue => AssignTry((short)us, out result),
            uint ui when ui <= (uint)short.MaxValue => AssignTry((short)ui, out result),
            ulong ul when ul <= (ulong)short.MaxValue => AssignTry((short)ul, out result),
            float f when f >= short.MinValue && f <= short.MaxValue && f % 1 == 0 => AssignTry((short)f, out result),
            double d when d >= short.MinValue && d <= short.MaxValue && d % 1 == 0 => AssignTry((short)d, out result),
            _ => false
        };
    }

    private static bool TryCoerce(object value, out int result)
    {
        result = 0;
        return value switch
        {
            int i => AssignTry(i, out result),
            byte b => AssignTry(b, out result),
            sbyte sb => AssignTry(sb, out result),
            short s => AssignTry(s, out result),
            ushort us => AssignTry(us, out result),
            long l when l >= int.MinValue && l <= int.MaxValue => AssignTry((int)l, out result),
            uint ui when ui <= int.MaxValue => AssignTry((int)ui, out result),
            ulong ul when ul <= int.MaxValue => AssignTry((int)ul, out result),
            float f when f >= int.MinValue && f <= int.MaxValue && f % 1 == 0 => AssignTry((int)f, out result),
            double d when d >= int.MinValue && d <= int.MaxValue && d % 1 == 0 => AssignTry((int)d, out result),
            _ => false
        };
    }

    private static bool TryCoerce(object value, out long result)
    {
        result = 0;
        return value switch
        {
            long l => AssignTry(l, out result),
            int i => AssignTry(i, out result),
            byte b => AssignTry(b, out result),
            sbyte sb => AssignTry(sb, out result),
            short s => AssignTry(s, out result),
            ushort us => AssignTry(us, out result),
            uint ui => AssignTry(ui, out result),
            ulong ul when ul <= long.MaxValue => AssignTry((long)ul, out result),
            float f when f >= long.MinValue && f <= long.MaxValue && f % 1 == 0 => AssignTry((long)f, out result),
            double d when d >= long.MinValue && d <= long.MaxValue && d % 1 == 0 => AssignTry((long)d, out result),
            _ => false
        };
    }

    private static bool TryCoerce(object value, out float result)
    {
        result = 0;
        return value switch
        {
            float f => AssignTry(f, out result),
            double d when d >= -float.MaxValue && d <= float.MaxValue => AssignTry((float)d, out result),
            int i => AssignTry(i, out result),
            long l => AssignTry(l, out result),
            byte b => AssignTry(b, out result),
            sbyte sb => AssignTry(sb, out result),
            short s => AssignTry(s, out result),
            ushort us => AssignTry(us, out result),
            uint ui => AssignTry(ui, out result),
            ulong ul => AssignTry(ul, out result),
            _ => false
        };
    }

    private static bool TryCoerce(object value, out double result)
    {
        result = 0;
        return value switch
        {
            double d => AssignTry(d, out result),
            float f => AssignTry(f, out result),
            int i => AssignTry(i, out result),
            long l => AssignTry(l, out result),
            byte b => AssignTry(b, out result),
            sbyte sb => AssignTry(sb, out result),
            short s => AssignTry(s, out result),
            ushort us => AssignTry(us, out result),
            uint ui => AssignTry(ui, out result),
            ulong ul => AssignTry(ul, out result),
            _ => false
        };
    }

    private static bool AssignTry<T>(T value, out T result)
    {
        result = value;
        return true;
    }
    private void ValueRefreshTimer_OnTick(object? sender, EventArgs e)
    {
        RefreshPointerValuesIncremental();
    }

    private void ResultGrid_OnScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        if (!_memoryAccessor.IsAttached || _isScanRunning)
        {
            return;
        }

        if (Math.Abs(e.VerticalChange) < 0.01 && Math.Abs(e.ViewportHeightChange) < 0.01)
        {
            return;
        }

        RefreshVisiblePointerRows();
    }

    private void ResultGrid_OnMouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (_isScanRunning || e.ChangedButton != MouseButton.Left)
        {
            return;
        }

        var source = e.OriginalSource as DependencyObject;
        var row = DataGridVisualUtilities.FindAncestor<DataGridRow>(source);
        if (row?.Item is not PointerPathRow pointerRow)
        {
            return;
        }

        var path = ClonePath(pointerRow.Path);
        SelectedPaths = new List<PointerPath> { path };
        TakeSelectedRequested?.Invoke(this, SelectedPaths, _selectedValueDataType);
    }
    private void OnGlobalValueRefreshIntervalChanged(object? sender, int milliseconds)
    {
        Dispatcher.Invoke(() =>
        {
            ApplyGlobalValueRefreshInterval(milliseconds);
            UpdateOptionsText();
        });
    }

    private void ApplyGlobalValueRefreshInterval(int milliseconds)
    {
        _valueRefreshTimer.Interval = TimeSpan.FromMilliseconds(milliseconds);
        if (_isScanRunning)
        {
            return;
        }

        _valueRefreshTimer.Stop();
        _valueRefreshTimer.Start();
    }

    private async Task<bool> SaveResultsAsAsync()
    {
        var dialog = new SaveFileDialog
        {
            Filter = "Compressed Pointer Scan Session (*.json.gz)|*.json.gz|Pointer Scan Session (*.json)|*.json|All files (*.*)|*.*",
            DefaultExt = _saveOptions.EnableGZipCompression ? ".json.gz" : ".json",
            AddExtension = true,
            FileName = string.IsNullOrWhiteSpace(_currentSessionFilePath) ? string.Empty : Path.GetFileName(_currentSessionFilePath)
        };

        if (dialog.ShowDialog(this) != true)
        {
            return false;
        }

        return await SaveResultsToPathAsync(dialog.FileName);
    }

    private async Task<bool> SaveResultsToPathAsync(string path)
    {
        if (_isSaveRunning || _isLoadRunning)
        {
            return false;
        }

        if (!TryBuildOptions(out var options, out var targetAddress))
        {
            MessageBox.Show(this, "Cannot save: invalid options/address.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        var saveOptionsSnapshot = _saveOptions.Clone();
        path = NormalizeSavePath(path, saveOptionsSnapshot);
        var processName = _memoryAccessor.IsAttached ? _memoryAccessor.Process.ProcessName : string.Empty;
        var sourcePaths = Rows.Select(r => r.Path).ToArray();
        var moduleSnapshot = _memoryAccessor.IsAttached
            ? _memoryAccessor.Modules.Select(m => new ModuleRange { Name = m.Name, Base = m.Base, End = m.End }).ToArray()
            : Array.Empty<ModuleRange>();

        SetSaveUiState(true);
        ShowSaveProgressWindow(path);

        var saveProgress = new Progress<PointerSaveProgressInfo>(UpdateSaveProgressUi);

        try
        {
            await Task.Run(() =>
                SaveSessionToPathCore(
                    path,
                    processName,
                    targetAddress,
                    _selectedValueDataType,
                    options,
                    sourcePaths,
                    moduleSnapshot,
                    saveOptionsSnapshot,
                    saveProgress));

            _currentSessionFilePath = path;
            UpdateWindowTitle();
            PointerProgressText.Text = $"Saved ({sourcePaths.Length} results)";
            return true;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Save Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return false;
        }
        finally
        {
            SetSaveUiState(false);
            CloseSaveProgressWindow();
        }
    }

    private static void SaveSessionToPathCore(
        string path,
        string processName,
        ulong targetAddress,
        MemoryDataType valueDataType,
        PointerScanOptions options,
        IReadOnlyList<PointerPath> sourcePaths,
        IReadOnlyList<ModuleRange> modules,
        PointerSessionSaveOptions saveOptions,
        IProgress<PointerSaveProgressInfo>? progress)
    {
        progress?.Report(new PointerSaveProgressInfo(0, "Preparing data...", $"Collecting {sourcePaths.Count} pointer results"));

        var preparedPaths = new List<PointerPath>(sourcePaths.Count);
        for (var i = 0; i < sourcePaths.Count; i++)
        {
            preparedPaths.Add(PreparePathForSave(sourcePaths[i], modules));

            if (sourcePaths.Count == 0)
            {
                continue;
            }

            if (((i + 1) % 256 == 0) || i == sourcePaths.Count - 1)
            {
                var ratio = (i + 1) / (double)sourcePaths.Count;
                progress?.Report(new PointerSaveProgressInfo(
                    55 * ratio,
                    "Preparing data...",
                    $"Prepared {i + 1}/{sourcePaths.Count}"));
            }
        }

        var session = new PointerScanSession
        {
            ProcessName = processName,
            SavedAtUtc = DateTime.UtcNow,
            TargetAddress = targetAddress,
            ValueDataType = valueDataType,
            Options = options,
            Results = preparedPaths
        };

        progress?.Report(new PointerSaveProgressInfo(58, "Serializing...", "Building JSON payload"));
        var payload = SerializeSessionPayload(session, saveOptions);
        progress?.Report(new PointerSaveProgressInfo(72, "Writing file...", $"{FormatBytes(payload.Length)} payload"));

        if (saveOptions.EnableGZipCompression)
        {
            WriteCompressedPayload(path, payload, progress);
        }
        else
        {
            WriteUncompressedPayload(path, payload, progress);
        }

        progress?.Report(new PointerSaveProgressInfo(100, "Save finished", $"Saved {preparedPaths.Count} pointers"));
    }

    private static void WriteCompressedPayload(
        string path,
        byte[] payload,
        IProgress<PointerSaveProgressInfo>? progress)
    {
        using var file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1024 * 64, FileOptions.SequentialScan);
        using var gzip = new GZipStream(file, CompressionLevel.Optimal, leaveOpen: false);

        var processed = 0;
        while (processed < payload.Length)
        {
            var chunkSize = Math.Min(SaveWriteChunkSize, payload.Length - processed);
            gzip.Write(payload, processed, chunkSize);
            processed += chunkSize;

            var ratio = payload.Length == 0 ? 1d : processed / (double)payload.Length;
            var percent = 72 + (ratio * 28);
            progress?.Report(new PointerSaveProgressInfo(
                percent,
                "Compressing and writing...",
                $"{FormatBytes(processed)} / {FormatBytes(payload.Length)}"));
        }
    }

    private static void WriteUncompressedPayload(
        string path,
        byte[] payload,
        IProgress<PointerSaveProgressInfo>? progress)
    {
        using var file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1024 * 64, FileOptions.SequentialScan);

        var processed = 0;
        while (processed < payload.Length)
        {
            var chunkSize = Math.Min(SaveWriteChunkSize, payload.Length - processed);
            file.Write(payload, processed, chunkSize);
            processed += chunkSize;

            var ratio = payload.Length == 0 ? 1d : processed / (double)payload.Length;
            var percent = 72 + (ratio * 28);
            progress?.Report(new PointerSaveProgressInfo(
                percent,
                "Writing file...",
                $"{FormatBytes(processed)} / {FormatBytes(payload.Length)}"));
        }
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024)
        {
            return $"{bytes} B";
        }

        var kib = bytes / 1024d;
        if (kib < 1024)
        {
            return $"{kib:0.0} KiB";
        }

        var mib = kib / 1024d;
        if (mib < 1024)
        {
            return $"{mib:0.0} MiB";
        }

        var gib = mib / 1024d;
        return $"{gib:0.00} GiB";
    }

    private static string NormalizeSavePath(string path, PointerSessionSaveOptions saveOptions)
    {
        if (saveOptions.EnableGZipCompression && !path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
        {
            return path + ".gz";
        }

        return path;
    }

    private static byte[] SerializeSessionPayload(PointerScanSession session, PointerSessionSaveOptions saveOptions)
    {
        var serializerOptions = new JsonSerializerOptions
        {
            WriteIndented = !saveOptions.CompactJson
        };

        if (saveOptions.UseCompactSchema)
        {
            var compact = BuildCompactSession(session);
            return JsonSerializer.SerializeToUtf8Bytes(compact, serializerOptions);
        }

        return JsonSerializer.SerializeToUtf8Bytes(session, serializerOptions);
    }

    private static PointerScanCompactSession BuildCompactSession(PointerScanSession session)
    {
        return new PointerScanCompactSession
        {
            Version = 1,
            ProcessName = session.ProcessName,
            SavedAtUtc = session.SavedAtUtc,
            TargetAddress = session.TargetAddress,
            ValueDataType = session.ValueDataType,
            Options = session.Options,
            Results = session.Results.Select(CreateCompactPath).ToList()
        };
    }

    private static PointerPathCompact CreateCompactPath(PointerPath path)
    {
        return new PointerPathCompact
        {
            BaseAddress = path.BaseAddress,
            PointerSizeBytes = path.PointerSizeBytes,
            BaseModuleName = path.BaseModuleName,
            BaseModuleOffset = path.BaseModuleOffset,
            Offsets = path.Offsets.ToList()
        };
    }

    private async Task LoadResultsFromDialogAsync()
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Pointer Scan Session (*.json;*.json.gz;*.gz)|*.json;*.json.gz;*.gz|All files (*.*)|*.*"
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        await LoadResultsFromPathAsync(dialog.FileName);
    }

    private async Task LoadResultsFromPathAsync(string path)
    {
        if (_isLoadRunning)
        {
            return;
        }

        _isLoadRunning = true;
        SetFileMenuEnabled(false);
        if (!_isScanRunning)
        {
            StartScanButton.IsEnabled = false;
            RescanButton.IsEnabled = false;
            PointerOptionsButton.IsEnabled = false;
            TargetAddressText.IsEnabled = false;
            ValueDataTypeBox.IsEnabled = false;
        }

        ShowLoadProgressWindow(path);
        IProgress<PointerLoadProgressInfo> loadProgress = new Progress<PointerLoadProgressInfo>(UpdateLoadProgressUi);

        try
        {
            var loadResult = await Task.Run(() => LoadSessionCore(path, loadProgress));
            if (!TryDeserializeSession(loadResult.Payload, out var session) || session is null || session.Options is null)
            {
                MessageBox.Show(this, "Invalid file format.", "Load Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _targetAddress = session.TargetAddress;
            TargetAddressText.Text = $"0x{_targetAddress:X}";

            _runtimeOptions = session.Options;
            _selectedValueDataType = session.ValueDataType;
            ValueDataTypeBox.SelectedItem = _selectedValueDataType;


            Rows.ReplaceAll(Array.Empty<PointerPathRow>());
            _pointerRefreshCursor = 0;
            var rows = new List<PointerPathRow>(session.Results.Count);
            for (var i = 0; i < session.Results.Count; i++)
            {
                rows.Add(CreatePointerPathRow(NormalizeLoadedPathForRuntime(session.Results[i])));
                if (((i + 1) % 512 == 0) || i == session.Results.Count - 1)
                {
                    var ratio = session.Results.Count == 0 ? 1d : (i + 1) / (double)session.Results.Count;
                    loadProgress.Report(new PointerLoadProgressInfo(
                        92 + (ratio * 8),
                        "Applying results...",
                        $"Prepared {i + 1}/{session.Results.Count} rows"));
                }
            }

            Rows.ReplaceAll(rows);
            RefreshValuesAfterBulkLoad();
            UpdateOptionsText();
            PointerProgressBar.Value = 0;
            var sourceProcessText = string.IsNullOrWhiteSpace(session.ProcessName) ? string.Empty : $" | source {session.ProcessName}";
            PointerProgressText.Text = $"Loaded ({Rows.Count} results){sourceProcessText}";

            _currentSessionFilePath = path;
            UpdateWindowTitle();
            loadProgress.Report(new PointerLoadProgressInfo(100, "Load finished", $"Loaded {Rows.Count} pointer results"));
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Load Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _isLoadRunning = false;
            if (_isScanRunning)
            {
                SetFileMenuEnabled(false);
            }
            else
            {
                var uiBusy = _isSaveRunning || _isLoadRunning;
                SetFileMenuEnabled(!uiBusy);
                StartScanButton.IsEnabled = !uiBusy;
                RescanButton.IsEnabled = !uiBusy;
                PointerOptionsButton.IsEnabled = !uiBusy;
                TargetAddressText.IsEnabled = !uiBusy;
                ValueDataTypeBox.IsEnabled = !uiBusy;
            }

            CloseLoadProgressWindow();
        }
    }

    private static PointerLoadResult LoadSessionCore(string path, IProgress<PointerLoadProgressInfo>? progress)
    {
        progress?.Report(new PointerLoadProgressInfo(0, "Reading file...", $"Opening {Path.GetFileName(path)}"));
        var payload = ReadAllBytesWithProgress(path, progress, 0, 40);

        if (IsGZipData(payload))
        {
            progress?.Report(new PointerLoadProgressInfo(42, "Decompressing...", "Detected GZip payload"));
            payload = DecompressGZipWithProgress(payload, progress, 42, 78);
        }

        progress?.Report(new PointerLoadProgressInfo(82, "Deserializing...", "Parsing JSON"));
        return new PointerLoadResult(payload);
    }

    private static bool TryDeserializeSession(byte[] payload, out PointerScanSession? session)
    {
        session = null;

        var serializerOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };

        var regular = JsonSerializer.Deserialize<PointerScanSession>(payload, serializerOptions);
        if (regular is not null && regular.Options is not null && regular.Results is not null)
        {
            session = regular;
            return true;
        }

        var compact = JsonSerializer.Deserialize<PointerScanCompactSession>(payload, serializerOptions);
        if (compact is null || compact.Options is null || compact.Results is null)
        {
            return false;
        }

        session = ConvertCompactSession(compact);
        return true;
    }

    private static PointerScanSession ConvertCompactSession(PointerScanCompactSession compact)
    {
        return new PointerScanSession
        {
            ProcessName = compact.ProcessName,
            SavedAtUtc = compact.SavedAtUtc,
            TargetAddress = compact.TargetAddress,
            ValueDataType = compact.ValueDataType,
            Options = compact.Options,
            Results = compact.Results.Select(x => new PointerPath
            {
                BaseAddress = x.BaseAddress,
                PointerSizeBytes = x.PointerSizeBytes,
                BaseModuleName = x.BaseModuleName,
                BaseModuleOffset = x.BaseModuleOffset,
                Offsets = x.Offsets?.ToList() ?? new List<int>(),
                DisplayExpression = string.Empty,
                FinalAddressPreview = compact.TargetAddress
            }).ToList()
        };
    }

    private static bool IsGZipData(byte[] payload)
    {
        return payload.Length >= 2 && payload[0] == 0x1F && payload[1] == 0x8B;
    }

    private static byte[] ReadAllBytesWithProgress(
        string path,
        IProgress<PointerLoadProgressInfo>? progress,
        double startPercent,
        double endPercent)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 64, FileOptions.SequentialScan);
        var totalLength = Math.Max(1L, file.Length);
        using var target = new MemoryStream(totalLength > int.MaxValue ? int.MaxValue : (int)totalLength);

        var buffer = new byte[LoadReadChunkSize];
        long totalRead = 0;
        int read;
        while ((read = file.Read(buffer, 0, buffer.Length)) > 0)
        {
            target.Write(buffer, 0, read);
            totalRead += read;
            var ratio = totalRead / (double)totalLength;
            var percent = startPercent + (ratio * (endPercent - startPercent));
            progress?.Report(new PointerLoadProgressInfo(
                percent,
                "Reading file...",
                $"{FormatBytes(totalRead)} / {FormatBytes(totalLength)}"));
        }

        return target.ToArray();
    }

    private static byte[] DecompressGZipWithProgress(
        byte[] payload,
        IProgress<PointerLoadProgressInfo>? progress,
        double startPercent,
        double endPercent)
    {
        using var sourceStream = new MemoryStream(payload);
        using var countingSource = new ProgressStream(sourceStream);
        using var gzip = new GZipStream(countingSource, CompressionMode.Decompress);
        using var target = new MemoryStream();
        var buffer = new byte[LoadReadChunkSize];
        int read;
        while ((read = gzip.Read(buffer, 0, buffer.Length)) > 0)
        {
            target.Write(buffer, 0, read);
            var consumed = countingSource.BytesRead;
            var ratio = payload.Length == 0 ? 1d : Math.Min(1d, consumed / (double)payload.Length);
            var percent = startPercent + (ratio * (endPercent - startPercent));
            progress?.Report(new PointerLoadProgressInfo(
                percent,
                "Decompressing...",
                $"{FormatBytes(consumed)} / {FormatBytes(payload.Length)} compressed"));
        }

        return target.ToArray();
    }

    private sealed class ProgressStream : Stream
    {
        private readonly Stream _inner;

        public ProgressStream(Stream inner)
        {
            _inner = inner;
        }

        public long BytesRead { get; private set; }

        public override bool CanRead => _inner.CanRead;
        public override bool CanSeek => _inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;
        public override long Position
        {
            get => _inner.Position;
            set => _inner.Position = value;
        }

        public override void Flush() => _inner.Flush();
        public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
        public override void SetLength(long value) => _inner.SetLength(value);

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = _inner.Read(buffer, offset, count);
            if (read > 0)
            {
                BytesRead += read;
            }

            return read;
        }

        public override int Read(Span<byte> buffer)
        {
            var read = _inner.Read(buffer);
            if (read > 0)
            {
                BytesRead += read;
            }

            return read;
        }

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private readonly struct PointerLoadResult
    {
        public PointerLoadResult(byte[] payload)
        {
            Payload = payload;
        }

        public byte[] Payload { get; }
    }

    private readonly struct PointerLoadProgressInfo
    {
        public PointerLoadProgressInfo(double percent, string stage, string detail)
        {
            Percent = percent;
            Stage = stage;
            Detail = detail;
        }

        public double Percent { get; }
        public string Stage { get; }
        public string Detail { get; }
    }

    private void ShowLoadProgressWindow(string path)
    {
        if (_loadProgressWindow is null || !_loadProgressWindow.IsLoaded)
        {
            _loadProgressWindow = new PointerLoadProgressWindow
            {
                Owner = this
            };
            _loadProgressWindow.Show();
        }
        else
        {
            _loadProgressWindow.Show();
        }

        _loadProgressWindow.UpdateProgress(0, "Reading file...", $"Loading {Path.GetFileName(path)}");
    }

    private void UpdateLoadProgressUi(PointerLoadProgressInfo info)
    {
        if (_loadProgressWindow is null || !_loadProgressWindow.IsLoaded)
        {
            return;
        }

        _loadProgressWindow.UpdateProgress(info.Percent, info.Stage, info.Detail);
    }

    private void CloseLoadProgressWindow()
    {
        if (_loadProgressWindow is null)
        {
            return;
        }

        if (_loadProgressWindow.IsLoaded)
        {
            _loadProgressWindow.CloseSafely();
        }

        _loadProgressWindow = null;
    }

    private static byte[] DecompressGZip(byte[] payload)
    {
        using var source = new MemoryStream(payload);
        using var gzip = new GZipStream(source, CompressionMode.Decompress);
        using var target = new MemoryStream();
        gzip.CopyTo(target);
        return target.ToArray();
    }

    private void CancelScan_OnClick(object sender, RoutedEventArgs e)
    {
        _cancelRequestedByUser = true;
        _scanCts?.Cancel();
    }

    private void TakeSelected_OnClick(object sender, RoutedEventArgs e)
    {
        var paths = ResultGrid.SelectedItems.OfType<PointerPathRow>().Select(x => ClonePath(x.Path)).ToList();
        if (paths.Count == 0)
        {
            MessageBox.Show(this, "No pointer selected.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        SelectedPaths = paths;
        TakeSelectedRequested?.Invoke(this, paths, _selectedValueDataType);
    }

    private bool TryBuildOptions(out PointerScanOptions options, out ulong targetAddress)
    {
        options = new PointerScanOptions();
        targetAddress = 0;

        if (!TryParseAddress(TargetAddressText.Text, out targetAddress))
        {
            return false;
        }

        options.MaxDepth = _runtimeOptions.MaxDepth;
        options.MaxOffset = _runtimeOptions.MaxOffset;
        options.Alignment = _runtimeOptions.Alignment;
        options.ThreadCount = _runtimeOptions.ThreadCount;
        options.UseResultLimit = _runtimeOptions.UseResultLimit;
        options.MaxResults = _runtimeOptions.MaxResults;
        options.IncludePrivate = _runtimeOptions.IncludePrivate;
        options.IncludeMapped = _runtimeOptions.IncludeMapped;
        options.IncludeModuleImage = _runtimeOptions.IncludeModuleImage;
        options.RequireStaticRoot = _runtimeOptions.RequireStaticRoot;
        options.ExcludeReadOnlyNodes = _runtimeOptions.ExcludeReadOnlyNodes;
        options.NoLoopingPointers = _runtimeOptions.NoLoopingPointers;
        options.StopTraversingAfterStaticRoot = _runtimeOptions.StopTraversingAfterStaticRoot;
        options.AggressiveNodeDeduplication = _runtimeOptions.AggressiveNodeDeduplication;
        options.AllowNegativeOffsets = _runtimeOptions.AllowNegativeOffsets;
        options.PointerWidthMode = _runtimeOptions.PointerWidthMode;
        options.UseAddressRange = _runtimeOptions.UseAddressRange;
        options.ClampSearchToAddressRange = _runtimeOptions.ClampSearchToAddressRange;
        options.AddressRangeFrom = _runtimeOptions.AddressRangeFrom;
        options.AddressRangeTo = _runtimeOptions.AddressRangeTo;
        options.RequireRootInAddressRange = _runtimeOptions.RequireRootInAddressRange;
        options.RequireAllNodesInAddressRange = _runtimeOptions.RequireAllNodesInAddressRange;
        options.TrimMemoryAfterCancel = _runtimeOptions.TrimMemoryAfterCancel;
        options.EnableDiskSpillToTemp = _runtimeOptions.EnableDiskSpillToTemp;
        options.MaxTempStorageGigabytes = _runtimeOptions.MaxTempStorageGigabytes;

        return true;
    }

    private static bool TryParseAddress(string? text, out ulong address)
    {
        address = 0;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var t = text.Trim();
        if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            t = t[2..];
        }

        return ulong.TryParse(t, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out address)
            || ulong.TryParse(t, NumberStyles.Integer, CultureInfo.InvariantCulture, out address);
    }

    private static PointerPath PreparePathForSave(PointerPath source, IReadOnlyList<ModuleRange> modules)
    {
        var path = ClonePath(source);

        if (modules.Count > 0)
        {
            if (!string.IsNullOrWhiteSpace(path.BaseModuleName))
            {
                var moduleByName = modules.FirstOrDefault(m =>
                    string.Equals(m.Name, path.BaseModuleName, StringComparison.OrdinalIgnoreCase));
                if (moduleByName is not null)
                {
                    path.BaseAddress = moduleByName.Base + path.BaseModuleOffset;
                }
            }
            else
            {
                var module = modules.FirstOrDefault(m => m.Contains(path.BaseAddress));
                if (module is not null)
                {
                    path.BaseModuleName = module.Name;
                    path.BaseModuleOffset = path.BaseAddress - module.Base;
                }
            }
        }

        path.DisplayExpression = BuildPointerExpressionForSave(path);
        return path;
    }

    private PointerPath NormalizeLoadedPathForRuntime(PointerPath source)
    {
        var path = ClonePath(source);

        if (_memoryAccessor.IsAttached && !string.IsNullOrWhiteSpace(path.BaseModuleName))
        {
            var moduleByName = _memoryAccessor.Modules.FirstOrDefault(m =>
                string.Equals(m.Name, path.BaseModuleName, StringComparison.OrdinalIgnoreCase));
            if (moduleByName is not null)
            {
                path.BaseAddress = moduleByName.Base + path.BaseModuleOffset;
            }
        }

        return path;
    }

    private static PointerPath ClonePath(PointerPath source)
    {
        return new PointerPath
        {
            BaseAddress = source.BaseAddress,
            BaseModuleName = source.BaseModuleName,
            BaseModuleOffset = source.BaseModuleOffset,
            Offsets = source.Offsets.ToList(),
            DisplayExpression = source.DisplayExpression,
            FinalAddressPreview = source.FinalAddressPreview,
            PointerSizeBytes = source.PointerSizeBytes
        };
    }

    private PointerPathRow CreatePointerPathRow(PointerPath path)
    {
        return new PointerPathRow(path, BuildPointerExpression);
    }

    private static string FormatOffset(int offset)
    {
        return offset < 0 ? "-0x" + Math.Abs(offset).ToString("X") : "0x" + offset.ToString("X");
    }

    private string BuildPointerExpression(PointerPath path)
    {
        string baseText;
        if (_displayContext.IsAttached)
        {
            baseText = _displayContext.FormatAddress(path.BaseAddress);
        }
        else if (!string.IsNullOrWhiteSpace(path.BaseModuleName))
        {
            baseText = $"{path.BaseModuleName}+0x{path.BaseModuleOffset:X}";
        }
        else
        {
            baseText = $"0x{path.BaseAddress:X}";
        }

        var offsetText = string.Join(", ", path.Offsets.Select(FormatOffset));
        return $"{baseText} -> [{offsetText}]";
    }

    private static string BuildPointerExpressionForSave(PointerPath path)
    {
        var baseText = !string.IsNullOrWhiteSpace(path.BaseModuleName)
            ? $"{path.BaseModuleName}+0x{path.BaseModuleOffset:X}"
            : $"0x{path.BaseAddress:X}";

        var offsetText = string.Join(", ", path.Offsets.Select(FormatOffset));
        return $"{baseText} -> [{offsetText}]";
    }

    private void RefreshPointerValues()
    {
        if (!_memoryAccessor.IsAttached)
        {
            SetPointerValuesUnavailableIncremental();
            return;
        }

        _pointerRefreshCursor = 0;
        RefreshPointerValuesCore(Rows.Count);
    }

    private void RefreshPointerValuesIncremental()
    {
        if (!_memoryAccessor.IsAttached)
        {
            SetPointerValuesUnavailableIncremental();
            return;
        }

        var count = Rows.Count;
        if (count == 0)
        {
            return;
        }

        var visibleRows = DataGridVisualUtilities.GetVisibleDataGridItems<PointerPathRow>(ResultGrid);
        var visibleSet = visibleRows.Count > 0 ? new HashSet<PointerPathRow>(visibleRows) : null;
        foreach (var row in visibleRows)
        {
            UpdatePointerRowValue(row);
        }

        if (_pointerRefreshCursor >= count)
        {
            _pointerRefreshCursor = 0;
        }

        var backgroundBudget = Math.Min(count, ComputeRefreshBatchSize(count, MinPointerRefreshBatchSize, MaxPointerRefreshBatchSize));
        var updated = 0;
        var attempts = 0;
        while (updated < backgroundBudget && attempts < count)
        {
            if (_pointerRefreshCursor >= count)
            {
                _pointerRefreshCursor = 0;
            }

            var row = Rows[_pointerRefreshCursor];
            _pointerRefreshCursor++;
            attempts++;

            if (visibleSet is not null && visibleSet.Contains(row))
            {
                continue;
            }

            UpdatePointerRowValue(row);
            updated++;
        }

    }

    private void RefreshPointerValuesCore(int maxUpdates)
    {
        var total = Rows.Count;
        if (total == 0 || maxUpdates <= 0)
        {
            return;
        }

        var updates = Math.Min(total, maxUpdates);
        for (var i = 0; i < updates; i++)
        {
            if (_pointerRefreshCursor >= total)
            {
                _pointerRefreshCursor = 0;
            }

            var row = Rows[_pointerRefreshCursor];
            _pointerRefreshCursor++;
            UpdatePointerRowValue(row);
        }

    }

    private void RefreshValuesAfterBulkLoad()
    {
        if (!_memoryAccessor.IsAttached)
        {
            SetPointerValuesUnavailableIncremental();
            return;
        }

        _pointerRefreshCursor = 0;
        const int fullRefreshThreshold = 5000;
        if (Rows.Count <= fullRefreshThreshold)
        {
            RefreshPointerValues();
            return;
        }

        RefreshVisiblePointerRows();
    }

    private void UpdatePointerRowValue(PointerPathRow row)
    {
        if (!_memoryAccessor.IsAttached)
        {
            row.ValueText = UnavailableValueText;
            row.ClearResolvedValue();
            return;
        }

        if (TryResolvePointerValue(row.Path, out var rawValue, out var valueText, out var currentAddressText))
        {
            row.ValueText = valueText;
            row.CurrentAddressText = currentAddressText;
            row.SetResolvedValue(rawValue);
        }
        else
        {
            row.ValueText = "<invalid>";
            row.CurrentAddressText = "<unresolved>";
            row.ClearResolvedValue();
        }
    }

    private static int ComputeRefreshBatchSize(int totalCount, int minBatchSize, int maxBatchSize)
    {
        return RefreshBatchSizer.Compute(totalCount, minBatchSize, maxBatchSize);
    }
    private void RefreshVisiblePointerRows()
    {
        foreach (var row in DataGridVisualUtilities.GetVisibleDataGridItems<PointerPathRow>(ResultGrid))
        {
            UpdatePointerRowValue(row);
        }

    }

    private void SetPointerValuesUnavailableIncremental()
    {
        var count = Rows.Count;
        if (count == 0)
        {
            return;
        }

        var visibleRows = DataGridVisualUtilities.GetVisibleDataGridItems<PointerPathRow>(ResultGrid);
        var visibleSet = visibleRows.Count > 0 ? new HashSet<PointerPathRow>(visibleRows) : null;
        foreach (var row in visibleRows)
        {
            row.ValueText = UnavailableValueText;
            row.ClearResolvedValue();
        }

        if (_pointerRefreshCursor >= count)
        {
            _pointerRefreshCursor = 0;
        }

        var backgroundBudget = Math.Min(count, ComputeRefreshBatchSize(count, MinPointerRefreshBatchSize, MaxPointerRefreshBatchSize));
        var updated = 0;
        var attempts = 0;
        while (updated < backgroundBudget && attempts < count)
        {
            if (_pointerRefreshCursor >= count)
            {
                _pointerRefreshCursor = 0;
            }

            var row = Rows[_pointerRefreshCursor];
            _pointerRefreshCursor++;
            attempts++;

            if (visibleSet is not null && visibleSet.Contains(row))
            {
                continue;
            }

            row.ValueText = UnavailableValueText;
            row.ClearResolvedValue();
            updated++;
        }
    }

    private List<PointerPath> RescanPointerPaths(
        IReadOnlyList<PointerPath> sourcePaths,
        PointerRescanRequest request,
        IProgress<ScanProgressInfo>? progress,
        CancellationToken cancellationToken)
    {
        var kept = new List<PointerPath>(sourcePaths.Count);
        var total = Math.Max(1, sourcePaths.Count);
        var modeText = request.Mode == PointerRescanMode.Address ? "address" : "value";
        progress?.Report(new ScanProgressInfo { Processed = 0, Total = total, StatusText = $"Rescanning pointers ({modeText})" });

        for (var i = 0; i < sourcePaths.Count; i++)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                break;
            }

            var path = sourcePaths[i];
            var keep = false;

            if (request.Mode == PointerRescanMode.Address)
            {
                keep = TryResolvePointerFinalAddress(path, out var resolvedAddress) && resolvedAddress == request.Address;
            }
            else if (request.Value is not null
                && TryResolvePointerValue(path, request.ValueDataType, out var rawValue, out _, out _)
                && ValuesMatchForRescan(request, rawValue))
            {
                keep = true;
            }

            if (keep)
            {
                kept.Add(ClonePath(path));
            }

            if ((i & 255) == 0)
            {
                progress?.Report(new ScanProgressInfo
                {
                    Processed = i + 1,
                    Total = total,
                    StatusText = $"Rescanning pointers ({modeText})"
                });
            }
        }

        progress?.Report(new ScanProgressInfo
        {
            Processed = total,
            Total = total,
            StatusText = cancellationToken.IsCancellationRequested ? "Rescan canceled" : "Rescan finished"
        });

        return kept;
    }

    private static bool ValuesMatchForRescan(PointerRescanRequest request, object currentValue)
    {
        if (request.Value is null)
        {
            return false;
        }

        return request.ValueDataType switch
        {
            MemoryDataType.Float => TryMatchFloatForRescan(currentValue, request.Value, request.ValueTextRaw),
            MemoryDataType.Double => TryMatchDoubleForRescan(currentValue, request.Value, request.ValueTextRaw),
            _ => TryCompareValuesByType(request.ValueDataType, currentValue, request.Value, out var comparison) && comparison == 0
        };
    }

    private static bool TryMatchFloatForRescan(object currentValue, object expectedValue, string? rawInput)
    {
        if (!TryCoerce(currentValue, out float currentFloat) || !TryCoerce(expectedValue, out float expectedFloat))
        {
            return false;
        }

        var currentDisplay = ValueTextFormatter.Format(currentFloat);
        var expectedDisplay = ValueTextFormatter.Format(expectedFloat);
        if (string.Equals(currentDisplay, expectedDisplay, StringComparison.Ordinal))
        {
            return true;
        }

        var tolerance = ComputeFloatingTolerance(rawInput, defaultTolerance: 0.000001f, maxDisplayPrecision: 6);
        return Math.Abs(currentFloat - expectedFloat) <= tolerance;
    }

    private static bool TryMatchDoubleForRescan(object currentValue, object expectedValue, string? rawInput)
    {
        if (!TryCoerce(currentValue, out double currentDouble) || !TryCoerce(expectedValue, out double expectedDouble))
        {
            return false;
        }

        var currentDisplay = ValueTextFormatter.Format(currentDouble);
        var expectedDisplay = ValueTextFormatter.Format(expectedDouble);
        if (string.Equals(currentDisplay, expectedDisplay, StringComparison.Ordinal))
        {
            return true;
        }

        var tolerance = ComputeFloatingTolerance(rawInput, defaultTolerance: 0.000000000001d, maxDisplayPrecision: 6);
        return Math.Abs(currentDouble - expectedDouble) <= tolerance;
    }

    private static double ComputeFloatingTolerance(string? rawInput, double defaultTolerance, int maxDisplayPrecision)
    {
        var fractionalDigits = CountFractionalDigits(rawInput);
        if (fractionalDigits <= 0)
        {
            return defaultTolerance;
        }

        var normalizedDigits = Math.Min(fractionalDigits, maxDisplayPrecision);
        return Math.Max(defaultTolerance, 0.5d * Math.Pow(10, -normalizedDigits));
    }

    private static int CountFractionalDigits(string? rawInput)
    {
        if (string.IsNullOrWhiteSpace(rawInput))
        {
            return 0;
        }

        var trimmed = rawInput.Trim();
        var exponentIndex = trimmed.IndexOfAny(new[] { 'e', 'E' });
        if (exponentIndex >= 0)
        {
            trimmed = trimmed[..exponentIndex];
        }

        var separatorIndex = Math.Max(trimmed.LastIndexOf('.'), trimmed.LastIndexOf(','));
        if (separatorIndex < 0 || separatorIndex >= trimmed.Length - 1)
        {
            return 0;
        }

        var digits = 0;
        for (var i = separatorIndex + 1; i < trimmed.Length; i++)
        {
            if (!char.IsDigit(trimmed[i]))
            {
                break;
            }

            digits++;
        }

        return digits;
    }

    private bool TryResolvePointerFinalAddress(PointerPath path, out ulong finalAddress)
    {
        finalAddress = 0;
        var entry = new WatchEntry
        {
            Kind = WatchEntryKind.PointerChain,
            PointerBaseAddress = path.BaseAddress,
            PointerBaseModuleName = path.BaseModuleName,
            PointerBaseModuleOffset = path.BaseModuleOffset,
            DataType = _selectedValueDataType,
            Offsets = new ObservableCollection<int>(path.Offsets),
            PointerSizeBytes = path.PointerSizeBytes
        };

        return _memoryAccessor.TryResolveWatchAddress(entry, out finalAddress, out _);
    }
    private bool TryResolvePointerValue(PointerPath path, out object rawValue, out string valueText, out string currentAddressText)
    {
        return TryResolvePointerValue(path, _selectedValueDataType, out rawValue, out valueText, out currentAddressText);
    }

    private bool TryResolvePointerValue(PointerPath path, MemoryDataType dataType, out object rawValue, out string valueText, out string currentAddressText)
    {
        rawValue = 0;
        valueText = "<invalid>";
        currentAddressText = "<unresolved>";

        var entry = new WatchEntry
        {
            Kind = WatchEntryKind.PointerChain,
            PointerBaseAddress = path.BaseAddress,
            PointerBaseModuleName = path.BaseModuleName,
            PointerBaseModuleOffset = path.BaseModuleOffset,
            DataType = dataType,
            Offsets = new ObservableCollection<int>(path.Offsets),
            PointerSizeBytes = path.PointerSizeBytes
        };

        if (!_memoryAccessor.TryResolveWatchAddress(entry, out var finalAddress, out _))
        {
            return false;
        }

        currentAddressText = _displayContext.FormatAddress(finalAddress);

        if (!_memoryAccessor.TryReadValue(finalAddress, dataType, out var value))
        {
            return false;
        }

        rawValue = value;
        valueText = value switch
        {
            float f => f.ToString("0.######", CultureInfo.InvariantCulture),
            double d => d.ToString("0.######", CultureInfo.InvariantCulture),
            _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty
        };

        return true;
    }

    private void UpdateProgressUi(ScanProgressInfo info)
    {
        var isMerge = info.Phase == ScanProgressPhase.Merging;
        var hasPhaseTotals = info.PhaseTotal > 0;
        var phaseProcessed = hasPhaseTotals ? info.PhaseProcessed : info.Processed;
        var phaseTotal = hasPhaseTotals ? info.PhaseTotal : info.Total;
        var phasePercent = hasPhaseTotals ? info.PhasePercent : info.Percent;
        var safePhaseTotal = Math.Max(1, phaseTotal);

        PointerPhaseText.Text = isMerge ? "Merging" : "Scanning";
        PointerProgressBar.Visibility = isMerge ? Visibility.Collapsed : Visibility.Visible;
        PointerMergeProgressBar.Visibility = isMerge ? Visibility.Visible : Visibility.Collapsed;

        if (isMerge)
        {
            PointerMergeProgressBar.Value = phasePercent;

            if (!hasPhaseTotals)
            {
                ResetMergePhaseEstimate();
                PointerProgressText.Text = $"{info.StatusText} {phasePercent:0.0}% ({phaseProcessed}/{safePhaseTotal}) | Overall {info.Percent:0.0}%";
                return;
            }

            if (_mergePhaseTotal != phaseTotal || _mergePhaseStartedUtc == DateTime.MinValue || phaseProcessed <= 1)
            {
                _mergePhaseTotal = phaseTotal;
                _mergePhaseStartedUtc = DateTime.UtcNow;
            }

            var etaText = string.Empty;
            if (phaseProcessed > 0 && phaseProcessed < phaseTotal && _mergePhaseStartedUtc != DateTime.MinValue)
            {
                var elapsed = DateTime.UtcNow - _mergePhaseStartedUtc;
                if (elapsed.TotalMilliseconds >= 300)
                {
                    var ratePerSecond = phaseProcessed / Math.Max(elapsed.TotalSeconds, 0.001);
                    if (ratePerSecond > 0.01)
                    {
                        var remainingSeconds = (phaseTotal - phaseProcessed) / ratePerSecond;
                        if (!double.IsNaN(remainingSeconds) && !double.IsInfinity(remainingSeconds) && remainingSeconds >= 0)
                        {
                            etaText = $" | ETA {FormatEta(TimeSpan.FromSeconds(remainingSeconds))}";
                        }
                    }
                }
            }

            PointerProgressText.Text = $"{info.StatusText} {phasePercent:0.0}% ({phaseProcessed}/{safePhaseTotal}){etaText} | Overall {info.Percent:0.0}%";
        }
        else
        {
            ResetMergePhaseEstimate();
            PointerProgressBar.Value = phasePercent;
            PointerProgressText.Text = $"{info.StatusText} {phasePercent:0.0}% ({phaseProcessed}/{safePhaseTotal})";
        }
    }

    private void SetBusyUi(string statusText = "Preparing scan...")
    {
        _isScanRunning = true;
        _valueRefreshTimer.Stop();
        StartScanButton.IsEnabled = false;
        RescanButton.IsEnabled = false;
        PointerOptionsButton.IsEnabled = false;
        CancelScanButton.IsEnabled = true;
        TargetAddressText.IsEnabled = false;
        ValueDataTypeBox.IsEnabled = false;
        SetFileMenuEnabled(false);

        ResetMergePhaseEstimate();
        PointerPhaseText.Text = "Scanning";
        PointerProgressBar.Visibility = Visibility.Visible;
        PointerMergeProgressBar.Visibility = Visibility.Collapsed;
        PointerProgressBar.Value = 0;
        PointerMergeProgressBar.Value = 0;
        PointerProgressText.Text = statusText;
    }

    private void SetIdleUi()
    {
        _isScanRunning = false;
        ApplyGlobalValueRefreshInterval(UiUpdateRoutineSettings.ValueRefreshIntervalMs);
        var uiBusy = _isSaveRunning || _isLoadRunning;
        StartScanButton.IsEnabled = !uiBusy;
        RescanButton.IsEnabled = !uiBusy;
        PointerOptionsButton.IsEnabled = !uiBusy;
        CancelScanButton.IsEnabled = false;
        TargetAddressText.IsEnabled = !uiBusy;
        ValueDataTypeBox.IsEnabled = !uiBusy;
        SetFileMenuEnabled(!uiBusy);

        ResetMergePhaseEstimate();
        PointerPhaseText.Text = "Idle";
        PointerProgressBar.Visibility = Visibility.Visible;
        PointerMergeProgressBar.Visibility = Visibility.Collapsed;

        if (PointerProgressText.Text == "Preparing scan..." || PointerProgressText.Text == "Preparing rescan..." || PointerProgressText.Text == "Idle")
        {
            PointerProgressText.Text = "Idle";
        }
    }

    private void SetSaveUiState(bool isSaving)
    {
        _isSaveRunning = isSaving;
        SetFileMenuEnabled(!isSaving && !_isScanRunning && !_isLoadRunning);

        if (_isScanRunning || _isLoadRunning)
        {
            return;
        }

        StartScanButton.IsEnabled = !isSaving;
        RescanButton.IsEnabled = !isSaving;
        PointerOptionsButton.IsEnabled = !isSaving;
        TargetAddressText.IsEnabled = !isSaving;
        ValueDataTypeBox.IsEnabled = !isSaving;
    }

    private void SetFileMenuEnabled(bool isEnabled)
    {
        if (LoadResultsMenuItem is not null)
        {
            LoadResultsMenuItem.IsEnabled = isEnabled;
        }

        if (SaveResultsMenuItem is not null)
        {
            SaveResultsMenuItem.IsEnabled = isEnabled;
        }

        if (SaveResultsAsMenuItem is not null)
        {
            SaveResultsAsMenuItem.IsEnabled = isEnabled;
        }

        if (SaveOptionsMenuItem is not null)
        {
            SaveOptionsMenuItem.IsEnabled = isEnabled;
        }
    }

    private void ShowSaveProgressWindow(string path)
    {
        if (_saveProgressWindow is null || !_saveProgressWindow.IsLoaded)
        {
            _saveProgressWindow = new PointerSaveProgressWindow
            {
                Owner = this
            };
            _saveProgressWindow.Show();
        }
        else
        {
            _saveProgressWindow.Show();
        }

        _saveProgressWindow.UpdateProgress(0, "Preparing data...", $"Saving to {Path.GetFileName(path)}");
    }

    private void UpdateSaveProgressUi(PointerSaveProgressInfo info)
    {
        if (_saveProgressWindow is null || !_saveProgressWindow.IsLoaded)
        {
            return;
        }

        _saveProgressWindow.UpdateProgress(info.Percent, info.Stage, info.Detail);
    }

    private void CloseSaveProgressWindow()
    {
        if (_saveProgressWindow is null)
        {
            return;
        }

        if (_saveProgressWindow.IsLoaded)
        {
            _saveProgressWindow.CloseSafely();
        }

        _saveProgressWindow = null;
    }

    private void ResetMergePhaseEstimate()
    {
        _mergePhaseStartedUtc = DateTime.MinValue;
        _mergePhaseTotal = 0;
    }

    private static string FormatEta(TimeSpan remaining)
    {
        if (remaining.TotalHours >= 1)
        {
            return remaining.ToString(@"hh\:mm\:ss", CultureInfo.InvariantCulture);
        }

        return remaining.ToString(@"mm\:ss", CultureInfo.InvariantCulture);
    }
    private void UpdateOptionsText()
    {
        var updateMs = UiUpdateRoutineSettings.ValueRefreshIntervalMs;
        PointerOptionsText.Text = $"Update {updateMs} ms";
    }

    private void UpdateWindowTitle()
    {
        var suffix = string.IsNullOrWhiteSpace(_currentSessionFilePath)
            ? string.Empty
            : $" - {Path.GetFileName(_currentSessionFilePath)}";

        Title = $"Pointer Scan{suffix}";
    }

    private static bool IsOnlyCancellation(AggregateException ex)
    {
        return ExceptionUtilities.IsOnlyCancellation(ex);
    }
    private async Task TrimMemoryAfterCancelAsync()
    {
        var previousText = PointerProgressText.Text;
        PointerProgressText.Text = "Scan canceled - trimming memory...";

        await Task.Run(() =>
        {
            try
            {
                GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
                GC.Collect(2, GCCollectionMode.Forced, true, true);
                GC.WaitForPendingFinalizers();
                GC.Collect(2, GCCollectionMode.Forced, true, true);
            }
            catch
            {
                // Keep cancel path robust.
            }

            try
            {
                EmptyWorkingSet(GetCurrentProcess());
            }
            catch
            {
                // Best-effort working set trim.
            }
        });

        if (PointerProgressText.Text.StartsWith("Scan canceled", StringComparison.OrdinalIgnoreCase)
            || PointerProgressText.Text.StartsWith("Rescan canceled", StringComparison.OrdinalIgnoreCase)
            || PointerProgressText.Text.Contains("trimming memory", StringComparison.OrdinalIgnoreCase))
        {
            PointerProgressText.Text = string.IsNullOrWhiteSpace(previousText)
                ? "Scan canceled - memory trimmed"
                : previousText + " | memory trimmed";
        }
    }

    [DllImport("psapi.dll")]
    private static extern bool EmptyWorkingSet(IntPtr hProcess);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    protected override void OnClosing(CancelEventArgs e)
    {
        if (_isSaveRunning || _isLoadRunning)
        {
            MessageBox.Show(this, "File operation is still running. Please wait until it finishes.", "Working", MessageBoxButton.OK, MessageBoxImage.Information);
            e.Cancel = true;
            return;
        }

        base.OnClosing(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        _scanCts?.Cancel();
        _scanCts?.Dispose();
        CloseSaveProgressWindow();
        CloseLoadProgressWindow();
        UiUpdateRoutineSettings.ValueRefreshIntervalChanged -= OnGlobalValueRefreshIntervalChanged;
        _valueRefreshTimer.Stop();
        base.OnClosed(e);
    }

}
































































