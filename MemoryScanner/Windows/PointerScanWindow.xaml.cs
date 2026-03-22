using MemoryScanner.Core;
using MemoryScanner.Models;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;

namespace MemoryScanner.Windows;

public partial class PointerScanWindow : Window
{
    private const int MinPointerRefreshBatchSize = 32;
    private const int MaxPointerRefreshBatchSize = 512;

    private enum ValueFilterCondition
    {
        Equal,
        NotEqual,
        Greater,
        Less,
        Between
    }
    private readonly PointerScanService _pointerScanService;
    private readonly IMemoryAccessor _memoryAccessor;
    private MemoryDataType _selectedValueDataType;
    private readonly DispatcherTimer _valueRefreshTimer;

    private ulong _targetAddress;
    private CancellationTokenSource? _scanCts;
    private bool _isScanRunning;
    private PointerScanOptions _runtimeOptions = new();
    private string? _currentSessionFilePath;
    private readonly ICollectionView _rowsView;
    private bool _isValueFilterActive;
    private ValueFilterCondition _valueFilterCondition = ValueFilterCondition.Equal;
    private object? _valueFilterPrimary;
    private object? _valueFilterSecondary;
    private int _pointerRefreshCursor;

    public BulkObservableCollection<PointerPathRow> Rows { get; } = new();

    public List<PointerPath> SelectedPaths { get; private set; } = new();
    public MemoryDataType SelectedValueDataType => _selectedValueDataType;

    public PointerScanWindow(
        PointerScanService pointerScanService,
        IMemoryAccessor memoryAccessor,
        ulong targetAddress,
        MemoryDataType valueDataType,
        PointerScanOptions? initialOptions = null)
    {
        _pointerScanService = pointerScanService;
        _memoryAccessor = memoryAccessor;
        _targetAddress = targetAddress;
        _selectedValueDataType = valueDataType;
        _runtimeOptions = CloneOptions(initialOptions) ?? new PointerScanOptions();

        InitializeComponent();
        _rowsView = CollectionViewSource.GetDefaultView(Rows);
        _rowsView.Filter = FilterPointerRow;
        ResultGrid.ItemsSource = _rowsView;

        TargetAddressText.Text = $"0x{_targetAddress:X}";
        ValueDataTypeBox.ItemsSource = MemoryDataTypeUiOrder.Ordered;
        ValueDataTypeBox.SelectedItem = _selectedValueDataType;

        ValueFilterConditionBox.ItemsSource = Enum.GetValues<ValueFilterCondition>();
        ValueFilterConditionBox.SelectedItem = ValueFilterCondition.Equal;
        UpdateValueFilterInputVisibility();

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
            AddressRangeFrom = source.AddressRangeFrom,
            AddressRangeTo = source.AddressRangeTo,
            RequireRootInAddressRange = source.RequireRootInAddressRange,
            RequireAllNodesInAddressRange = source.RequireAllNodesInAddressRange
        };
    }

    private void MenuLoadResults_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning)
        {
            return;
        }

        LoadResultsFromDialog();
    }

    private void MenuSaveResults_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(_currentSessionFilePath))
        {
            SaveResultsAs();
            return;
        }

        SaveResultsToPath(_currentSessionFilePath);
    }

    private void MenuSaveResultsAs_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning)
        {
            return;
        }

        SaveResultsAs();
    }

    private async void StartScan_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning)
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
        Rows.ReplaceAll(Array.Empty<PointerPathRow>());
        _pointerRefreshCursor = 0;

        var progress = new Progress<ScanProgressInfo>(info =>
        {
            PointerProgressBar.Value = info.Percent;
            PointerProgressText.Text = $"{info.StatusText} {info.Percent:0.0}% ({info.Processed}/{info.Total})";
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

            Rows.ReplaceAll(rows);
            RefreshValuesAfterBulkLoad();
            PointerProgressBar.Value = 100;
            PointerProgressText.Text = $"Scan finished ({results.Count} results)";
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
            SetIdleUi();
        }
    }

    private async void Rescan_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning)
        {
            return;
        }

        if (!_memoryAccessor.IsAttached)
        {
            MessageBox.Show(this, "Attach to a process first.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (!TryParseAddress(TargetAddressText.Text, out var newTargetAddress))
        {
            MessageBox.Show(this, "Invalid target address.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var sourcePaths = Rows.Select(r => r.Path).ToList();
        if (sourcePaths.Count == 0)
        {
            MessageBox.Show(this, "No pointer results available to rescan.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        _targetAddress = newTargetAddress;
        _scanCts?.Cancel();
        _scanCts?.Dispose();
        _scanCts = new CancellationTokenSource();

        var progress = new Progress<ScanProgressInfo>(info =>
        {
            PointerProgressBar.Value = info.Percent;
            PointerProgressText.Text = $"{info.StatusText} {info.Percent:0.0}% ({info.Processed}/{info.Total})";
        });

        SetBusyUi("Preparing rescan...");

        try
        {
            var rescanned = await Task.Run(() => RescanPointerPaths(sourcePaths, newTargetAddress, progress, _scanCts.Token));
            var rows = new List<PointerPathRow>(rescanned.Count);
            foreach (var path in rescanned)
            {
                rows.Add(CreatePointerPathRow(path));
            }

            Rows.ReplaceAll(rows);
            _pointerRefreshCursor = 0;
            RefreshValuesAfterBulkLoad();
            PointerProgressBar.Value = 100;
            PointerProgressText.Text = $"Rescan finished ({rescanned.Count} results)";
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
            SetIdleUi();
        }
    }
    private void PointerOptions_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning)
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

        if (_isValueFilterActive)
        {
            if (!TryApplyValueFilter(showInputError: false))
            {
                _isValueFilterActive = false;
                _valueFilterPrimary = null;
                _valueFilterSecondary = null;
            }

            _rowsView.Refresh();
        }

        UpdateOptionsText();
    }
    private void ValueFilterConditionBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ValueFilterConditionBox.SelectedItem is ValueFilterCondition condition)
        {
            _valueFilterCondition = condition;
        }

        UpdateValueFilterInputVisibility();
    }

    private void ApplyValueFilter_OnClick(object sender, RoutedEventArgs e)
    {
        if (!TryApplyValueFilter(showInputError: true))
        {
            return;
        }

        _rowsView.Refresh();
    }

    private void ClearValueFilter_OnClick(object sender, RoutedEventArgs e)
    {
        _isValueFilterActive = false;
        _valueFilterPrimary = null;
        _valueFilterSecondary = null;
        ValueFilterInputText.Text = string.Empty;
        ValueFilterInputToText.Text = string.Empty;
        _rowsView.Refresh();
    }

    private bool TryApplyValueFilter(bool showInputError)
    {
        if (!TryParseFilterInput(ValueFilterInputText.Text, out var primaryValue))
        {
            if (showInputError)
            {
                MessageBox.Show(this, "Invalid filter value for current data type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            return false;
        }

        _valueFilterPrimary = primaryValue;
        _valueFilterSecondary = null;

        if (_valueFilterCondition == ValueFilterCondition.Between)
        {
            if (!TryParseFilterInput(ValueFilterInputToText.Text, out var secondaryValue))
            {
                if (showInputError)
                {
                    MessageBox.Show(this, "Invalid range end value for current data type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                }

                return false;
            }

            _valueFilterSecondary = secondaryValue;
        }

        _isValueFilterActive = true;
        return true;
    }

    private bool TryParseFilterInput(string? input, out object value)
    {
        value = 0;
        var text = input?.Trim() ?? string.Empty;
        return ScanService.TryParseValue(_selectedValueDataType, text, out value);
    }

    private void UpdateValueFilterInputVisibility()
    {
        var isBetween = _valueFilterCondition == ValueFilterCondition.Between;
        ValueFilterToLabel.Visibility = isBetween ? Visibility.Visible : Visibility.Collapsed;
        ValueFilterInputToText.Visibility = isBetween ? Visibility.Visible : Visibility.Collapsed;
    }

    private bool FilterPointerRow(object item)
    {
        if (!_isValueFilterActive)
        {
            return true;
        }

        if (item is not PointerPathRow row || !row.TryGetResolvedValue(out var currentValue))
        {
            return false;
        }

        var primary = _valueFilterPrimary;
        if (primary is null)
        {
            return true;
        }

        return _valueFilterCondition switch
        {
            ValueFilterCondition.Equal => TryCompareValuesByType(currentValue, primary, out var eqCmp) && eqCmp == 0,
            ValueFilterCondition.NotEqual => TryCompareValuesByType(currentValue, primary, out var neCmp) && neCmp != 0,
            ValueFilterCondition.Greater => TryCompareValuesByType(currentValue, primary, out var gtCmp) && gtCmp > 0,
            ValueFilterCondition.Less => TryCompareValuesByType(currentValue, primary, out var ltCmp) && ltCmp < 0,
            ValueFilterCondition.Between => IsBetween(currentValue, primary, _valueFilterSecondary),
            _ => true
        };
    }

    private bool IsBetween(object currentValue, object boundaryA, object? boundaryB)
    {
        if (boundaryB is null)
        {
            return false;
        }

        if (!TryCompareValuesByType(boundaryA, boundaryB, out var order))
        {
            return false;
        }

        object low = order <= 0 ? boundaryA : boundaryB;
        object high = order <= 0 ? boundaryB : boundaryA;

        return TryCompareValuesByType(currentValue, low, out var lowCmp)
            && TryCompareValuesByType(currentValue, high, out var highCmp)
            && lowCmp >= 0
            && highCmp <= 0;
    }

    private bool TryCompareValuesByType(object left, object right, out int result)
    {
        result = 0;

        switch (_selectedValueDataType)
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

    private bool SaveResultsAs()
    {
        var dialog = new SaveFileDialog
        {
            Filter = "Pointer Scan Session (*.json)|*.json|All files (*.*)|*.*",
            DefaultExt = ".json",
            FileName = string.IsNullOrWhiteSpace(_currentSessionFilePath) ? string.Empty : Path.GetFileName(_currentSessionFilePath)
        };

        if (dialog.ShowDialog(this) != true)
        {
            return false;
        }

        return SaveResultsToPath(dialog.FileName);
    }

    private bool SaveResultsToPath(string path)
    {
        if (!TryBuildOptions(out var options, out var targetAddress))
        {
            MessageBox.Show(this, "Cannot save: invalid options/address.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        try
        {
            var session = new PointerScanSession
            {
                ProcessName = _memoryAccessor.IsAttached ? _memoryAccessor.Process.ProcessName : string.Empty,
                SavedAtUtc = DateTime.UtcNow,
                TargetAddress = targetAddress,
                ValueDataType = _selectedValueDataType,
                Options = options,
                Results = Rows.Select(r => PreparePathForSave(r.Path)).ToList()
            };

            var json = JsonSerializer.Serialize(session, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, json);
            _currentSessionFilePath = path;
            UpdateWindowTitle();
            return true;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Save Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return false;
        }
    }

    private void LoadResultsFromDialog()
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Pointer Scan Session (*.json)|*.json|All files (*.*)|*.*"
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        LoadResultsFromPath(dialog.FileName);
    }

    private void LoadResultsFromPath(string path)
    {
        try
        {
            var json = File.ReadAllText(path);
            var session = JsonSerializer.Deserialize<PointerScanSession>(json);
            if (session is null || session.Options is null)
            {
                MessageBox.Show(this, "Invalid file format.", "Load Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _targetAddress = session.TargetAddress;
            TargetAddressText.Text = $"0x{_targetAddress:X}";

            _runtimeOptions = session.Options;
            _selectedValueDataType = session.ValueDataType;
            ValueDataTypeBox.SelectedItem = _selectedValueDataType;

            ValueFilterConditionBox.ItemsSource = Enum.GetValues<ValueFilterCondition>();
            ValueFilterConditionBox.SelectedItem = ValueFilterCondition.Equal;
            UpdateValueFilterInputVisibility();

            Rows.ReplaceAll(Array.Empty<PointerPathRow>());
            _pointerRefreshCursor = 0;
            var rows = new List<PointerPathRow>(session.Results.Count);
            foreach (var pathEntry in session.Results)
            {
                rows.Add(CreatePointerPathRow(NormalizeLoadedPathForRuntime(pathEntry)));
            }

            Rows.ReplaceAll(rows);
            RefreshValuesAfterBulkLoad();
            UpdateOptionsText();
            PointerProgressBar.Value = 0;
            var sourceProcessText = string.IsNullOrWhiteSpace(session.ProcessName) ? string.Empty : $" | source {session.ProcessName}";
            PointerProgressText.Text = $"Loaded ({Rows.Count} results){sourceProcessText}";

            _currentSessionFilePath = path;
            UpdateWindowTitle();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Load Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void CancelScan_OnClick(object sender, RoutedEventArgs e)
    {
        _scanCts?.Cancel();
    }

    private void TakeSelected_OnClick(object sender, RoutedEventArgs e)
    {
        var paths = ResultGrid.SelectedItems.OfType<PointerPathRow>().Select(x => x.Path).ToList();
        if (paths.Count == 0)
        {
            MessageBox.Show(this, "No pointer selected.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        SelectedPaths = paths;
        DialogResult = true;
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
        options.AddressRangeFrom = _runtimeOptions.AddressRangeFrom;
        options.AddressRangeTo = _runtimeOptions.AddressRangeTo;
        options.RequireRootInAddressRange = _runtimeOptions.RequireRootInAddressRange;
        options.RequireAllNodesInAddressRange = _runtimeOptions.RequireAllNodesInAddressRange;

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

    private PointerPath PreparePathForSave(PointerPath source)
    {
        var path = ClonePath(source);

        if (_memoryAccessor.IsAttached)
        {
            if (!string.IsNullOrWhiteSpace(path.BaseModuleName))
            {
                var moduleByName = _memoryAccessor.Modules.FirstOrDefault(m =>
                    string.Equals(m.Name, path.BaseModuleName, StringComparison.OrdinalIgnoreCase));
                if (moduleByName is not null)
                {
                    path.BaseAddress = moduleByName.Base + path.BaseModuleOffset;
                }
            }
            else
            {
                var module = _memoryAccessor.Modules.FirstOrDefault(m => m.Contains(path.BaseAddress));
                if (module is not null)
                {
                    path.BaseModuleName = module.Name;
                    path.BaseModuleOffset = path.BaseAddress - module.Base;
                }
            }
        }

        path.DisplayExpression = BuildPointerExpression(path);
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
        return new PointerPathRow(path)
        {
            PointerExpressionText = BuildPointerExpression(path)
        };
    }

    private static string FormatOffset(int offset)
    {
        return offset < 0 ? "-0x" + Math.Abs(offset).ToString("X") : "0x" + offset.ToString("X");
    }

    private string BuildPointerExpression(PointerPath path)
    {
        string baseText;
        if (_memoryAccessor.IsAttached)
        {
            baseText = _memoryAccessor.FormatAddress(path.BaseAddress);
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

    private void RefreshPointerValues()
    {
        _pointerRefreshCursor = 0;
        RefreshPointerValuesCore(Rows.Count);
    }

    private void RefreshPointerValuesIncremental()
    {
        var count = Rows.Count;
        if (count == 0)
        {
            return;
        }

        var visibleRows = GetVisibleDataGridItems<PointerPathRow>(ResultGrid);
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

        if (_isValueFilterActive)
        {
            _rowsView.Refresh();
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

        if (_isValueFilterActive)
        {
            _rowsView.Refresh();
        }
    }

    private void RefreshValuesAfterBulkLoad()
    {
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
        row.PointerExpressionText = BuildPointerExpression(row.Path);

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
        if (totalCount <= 0)
        {
            return 0;
        }

        var scaled = totalCount / 20;
        return Math.Clamp(scaled, minBatchSize, maxBatchSize);
    }
    private void RefreshVisiblePointerRows()
    {
        foreach (var row in GetVisibleDataGridItems<PointerPathRow>(ResultGrid))
        {
            UpdatePointerRowValue(row);
        }

        if (_isValueFilterActive)
        {
            _rowsView.Refresh();
        }
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
    private List<PointerPath> RescanPointerPaths(
        IReadOnlyList<PointerPath> sourcePaths,
        ulong newTargetAddress,
        IProgress<ScanProgressInfo>? progress,
        CancellationToken cancellationToken)
    {
        var kept = new List<PointerPath>(sourcePaths.Count);
        var total = Math.Max(1, sourcePaths.Count);
        progress?.Report(new ScanProgressInfo { Processed = 0, Total = total, StatusText = "Rescanning pointers" });

        for (var i = 0; i < sourcePaths.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var path = sourcePaths[i];
            if (TryResolvePointerFinalAddress(path, out var resolvedAddress) && resolvedAddress == newTargetAddress)
            {
                kept.Add(ClonePath(path));
            }

            if ((i & 255) == 0)
            {
                progress?.Report(new ScanProgressInfo
                {
                    Processed = i + 1,
                    Total = total,
                    StatusText = "Rescanning pointers"
                });
            }
        }

        progress?.Report(new ScanProgressInfo
        {
            Processed = total,
            Total = total,
            StatusText = "Rescan finished"
        });

        return kept;
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
        rawValue = 0;
        valueText = "<invalid>";
        currentAddressText = "<unresolved>";

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

        if (!_memoryAccessor.TryResolveWatchAddress(entry, out var finalAddress, out _))
        {
            return false;
        }

        currentAddressText = _memoryAccessor.FormatAddress(finalAddress);

        if (!_memoryAccessor.TryReadValue(finalAddress, _selectedValueDataType, out var value))
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

    private void SetBusyUi(string statusText = "Preparing scan...")
    {
        _isScanRunning = true;
        _valueRefreshTimer.Stop();
        StartScanButton.IsEnabled = false;
        RescanButton.IsEnabled = false;
        PointerOptionsButton.IsEnabled = false;
        CancelScanButton.IsEnabled = true;
        PointerProgressBar.Value = 0;
        PointerProgressText.Text = statusText;
    }

    private void SetIdleUi()
    {
        _isScanRunning = false;
        ApplyGlobalValueRefreshInterval(UiUpdateRoutineSettings.ValueRefreshIntervalMs);
        StartScanButton.IsEnabled = true;
        RescanButton.IsEnabled = true;
        PointerOptionsButton.IsEnabled = true;
        CancelScanButton.IsEnabled = false;
        if (PointerProgressText.Text == "Preparing scan..." || PointerProgressText.Text == "Preparing rescan..." || PointerProgressText.Text == "Idle")
        {
            PointerProgressText.Text = "Idle";
        }
    }
    private void UpdateOptionsText()
    {
        var updateMs = UiUpdateRoutineSettings.ValueRefreshIntervalMs;
        var limitText = _runtimeOptions.UseResultLimit ? _runtimeOptions.MaxResults.ToString(CultureInfo.InvariantCulture) : "off";
        var processBaseOnlyText = _runtimeOptions.RequireStaticRoot ? "on" : "off";
        var readOnlyText = _runtimeOptions.ExcludeReadOnlyNodes ? "on" : "off";
        var loopText = _runtimeOptions.NoLoopingPointers ? "on" : "off";
        var stopStaticText = _runtimeOptions.StopTraversingAfterStaticRoot ? "on" : "off";
        var dedupeText = _runtimeOptions.AggressiveNodeDeduplication ? "on" : "off";
        var negativeOffsetsText = _runtimeOptions.AllowNegativeOffsets ? "on" : "off";
        var widthText = _runtimeOptions.PointerWidthMode switch
        {
            PointerValueWidthMode.Force32Bit => "32-bit",
            PointerValueWidthMode.Force64Bit => "64-bit",
            _ => "auto"
        };

        var rangeText = _runtimeOptions.UseAddressRange
            ? $"0x{_runtimeOptions.AddressRangeFrom:X}-0x{_runtimeOptions.AddressRangeTo:X}"
            : "off";
        var rootInRangeText = _runtimeOptions.RequireRootInAddressRange ? "on" : "off";
        var allNodesInRangeText = _runtimeOptions.RequireAllNodesInAddressRange ? "on" : "off";
        PointerOptionsText.Text = $"Options: Type {_selectedValueDataType}, Threads {_runtimeOptions.ThreadCount}, Limit {limitText}, Width {widthText}, Range {rangeText}, RootInRange {rootInRangeText}, AllNodesInRange {allNodesInRangeText}, Process+Base only {processBaseOnlyText}, RO nodes off {readOnlyText}, No loops {loopText}, Stop@static {stopStaticText}, Dedupe {dedupeText}, NegOff {negativeOffsetsText}, Preset d{_runtimeOptions.MaxDepth}/off{_runtimeOptions.MaxOffset}/a{_runtimeOptions.Alignment}, Update {updateMs} ms";
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
        return ex.Flatten().InnerExceptions.All(inner => inner is OperationCanceledException);
    }

    protected override void OnClosed(EventArgs e)
    {
        _scanCts?.Cancel();
        _scanCts?.Dispose();
        UiUpdateRoutineSettings.ValueRefreshIntervalChanged -= OnGlobalValueRefreshIntervalChanged;
        _valueRefreshTimer.Stop();
        base.OnClosed(e);
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

    public sealed class PointerPathRow : INotifyPropertyChanged
    {
        private string _pointerExpressionText = string.Empty;
        private string _valueText = string.Empty;
        private string _currentAddressText = "<unresolved>";
        private object? _resolvedValue;
        private bool _hasResolvedValue;

        public PointerPathRow(PointerPath path)
        {
            Path = path;
            OffsetsDisplay = string.Join(", ", path.Offsets.Select(PointerScanWindow.FormatOffset));
        }

        public PointerPath Path { get; }
        public string BaseAddress => $"0x{Path.BaseAddress:X}";
        public string OffsetsDisplay { get; }

        public string PointerExpressionText
        {
            get => _pointerExpressionText;
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





















