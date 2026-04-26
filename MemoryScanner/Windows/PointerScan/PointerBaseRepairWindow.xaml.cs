using MemoryScanner.Core;
using MemoryScanner.Models;
using MemoryScanner.Windows.Shared;
using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace MemoryScanner.Windows;

public partial class PointerBaseRepairWindow : Window
{
    private const int UiProgressThrottleMs = 50;
    private const string UnavailableValueText = "???";
    private const int MinRepairRefreshBatchSize = 16;
    private const int MaxRepairRefreshBatchSize = 256;

    private readonly IMemoryAccessor _memoryAccessor;
    private readonly int[] _offsets;
    private readonly int _pointerSizeBytesHint;
    private readonly ObservableCollection<RepairCandidateRow> _results = new();
    private readonly DispatcherTimer _valueRefreshTimer;

    private CancellationTokenSource? _scanCts;
    private bool _isScanning;
    private int _resultRefreshCursor;
    private MemoryDataType _currentResultDataType;

    public ulong CurrentBaseAddress { get; }
    public ulong? SelectedBaseAddress { get; private set; }
    public MemoryDataType SelectedDataType { get; private set; }
    public int SelectedPointerSizeBytes { get; private set; }

    public PointerBaseRepairWindow(
        IMemoryAccessor memoryAccessor,
        ulong currentBaseAddress,
        IReadOnlyList<int> offsets,
        int pointerSizeBytesHint,
        MemoryDataType initialDataType,
        string? initialExpectedValue)
    {
        InitializeComponent();

        _memoryAccessor = memoryAccessor;
        CurrentBaseAddress = currentBaseAddress;
        _offsets = offsets.ToArray();
        _pointerSizeBytesHint = pointerSizeBytesHint;
        _currentResultDataType = initialDataType;

        ResultsGrid.ItemsSource = _results;

        DataTypeBox.ItemsSource = MemoryDataTypeUiOrder.Ordered;
        DataTypeBox.SelectedItem = initialDataType;
        ExpectedValueText.Text = string.IsNullOrWhiteSpace(initialExpectedValue) ? string.Empty : initialExpectedValue.Trim();

        CurrentBaseText.Text = $"Current base: {_memoryAccessor.FormatAddress(currentBaseAddress)} (0x{currentBaseAddress:X})";
        OffsetsText.Text = _offsets.Length == 0
            ? "(no offsets)"
            : string.Join(", ", _offsets.Select(FormatOffset));

        _valueRefreshTimer = new DispatcherTimer();
        _valueRefreshTimer.Tick += ValueRefreshTimer_OnTick;
        UiUpdateRoutineSettings.ValueRefreshIntervalChanged += OnGlobalValueRefreshIntervalChanged;
        ApplyGlobalValueRefreshInterval(UiUpdateRoutineSettings.ValueRefreshIntervalMs);

        StatusText.Text = "Idle";
    }

    private async void StartScan_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanning)
        {
            return;
        }

        if (!_memoryAccessor.IsAttached)
        {
            MessageBox.Show(this, "Select/attach process first.", "No Process", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (DataTypeBox.SelectedItem is not MemoryDataType dataType)
        {
            MessageBox.Show(this, "Select a data type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!ScanService.TryParseValue(dataType, ExpectedValueText.Text, out var expectedValue))
        {
            MessageBox.Show(this, "Expected value is invalid for selected data type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!TryParseUlongInput(RangeText.Text, out var rangeBytes))
        {
            MessageBox.Show(this, "Range must be a non-negative number (decimal or hex with 0x).", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!int.TryParse(StepText.Text.Trim(), out var stepBytes) || stepBytes <= 0)
        {
            MessageBox.Show(this, "Step must be a positive integer.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!int.TryParse(MaxResultsText.Text.Trim(), out var maxResults) || maxResults <= 0)
        {
            MessageBox.Show(this, "Max Results must be a positive integer.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _scanCts?.Cancel();
        _scanCts?.Dispose();
        _scanCts = new CancellationTokenSource();

        _results.Clear();
        _resultRefreshCursor = 0;
        ScanProgressBar.Value = 0;
        SelectedBaseAddress = null;
        SelectedDataType = dataType;
        SelectedPointerSizeBytes = 0;
        _currentResultDataType = dataType;

        SetScanUiState(isBusy: true);

        try
        {
            var token = _scanCts.Token;
            var progress = new Progress<RepairScanProgress>(info =>
            {
                ScanProgressBar.Value = info.Percent;
                StatusText.Text = info.Status;
            });

            var result = await Task.Run(() => ExecuteRepairScan(dataType, expectedValue, rangeBytes, stepBytes, maxResults, progress, token), token);

            foreach (var row in result.Rows)
            {
                _results.Add(row);
            }

            RefreshRepairValuesAfterScan();

            SelectedPointerSizeBytes = result.PointerSizeBytes;
            ScanProgressBar.Value = 100;
            StatusText.Text = token.IsCancellationRequested
                ? $"Canceled | Matches {_results.Count}"
                : $"Done | Matches {_results.Count}";
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = $"Canceled | Matches {_results.Count}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Repair Scan Error", MessageBoxButton.OK, MessageBoxImage.Error);
            StatusText.Text = "Error";
        }
        finally
        {
            SetScanUiState(isBusy: false);
        }
    }

    private void CancelScan_OnClick(object sender, RoutedEventArgs e)
    {
        _scanCts?.Cancel();
    }

    private void DataTypeBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (DataTypeBox.SelectedItem is not MemoryDataType selectedType)
        {
            return;
        }

        _currentResultDataType = selectedType;
        _resultRefreshCursor = 0;
        if (_isScanning)
        {
            return;
        }

        RefreshRepairValuesAfterScan();
    }

    private void ValueRefreshTimer_OnTick(object? sender, EventArgs e)
    {
        if (_isScanning)
        {
            return;
        }

        RefreshRepairValuesIncremental();
    }

    private void ResultsGrid_OnScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        if (_isScanning)
        {
            return;
        }

        if (Math.Abs(e.VerticalChange) < 0.01 && Math.Abs(e.ViewportHeightChange) < 0.01)
        {
            return;
        }

        RefreshVisibleRepairRows();
    }

    private void OnGlobalValueRefreshIntervalChanged(object? sender, int milliseconds)
    {
        Dispatcher.Invoke(() =>
        {
            ApplyGlobalValueRefreshInterval(milliseconds);
        });
    }

    private void ApplyGlobalValueRefreshInterval(int milliseconds)
    {
        _valueRefreshTimer.Interval = TimeSpan.FromMilliseconds(milliseconds);
        _valueRefreshTimer.Stop();
        _valueRefreshTimer.Start();
    }

    private void ResultsGrid_OnPreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        var source = e.OriginalSource as DependencyObject;
        var row = DataGridVisualUtilities.FindAncestor<DataGridRow>(source);
        if (row?.Item is RepairCandidateRow candidate)
        {
            ResultsGrid.SelectedItem = candidate;
        }
    }

    private void CopyDifferenceDecimal_OnClick(object sender, RoutedEventArgs e)
    {
        CopyDifferenceToClipboard(asHex: false);
    }

    private void CopyDifferenceHex_OnClick(object sender, RoutedEventArgs e)
    {
        CopyDifferenceToClipboard(asHex: true);
    }

    private void CopyDifferenceToClipboard(bool asHex)
    {
        if (ResultsGrid.SelectedItem is not RepairCandidateRow row)
        {
            return;
        }

        var difference = row.BaseAddress >= CurrentBaseAddress
            ? row.BaseAddress - CurrentBaseAddress
            : CurrentBaseAddress - row.BaseAddress;

        var text = asHex
            ? $"0x{difference:X}"
            : difference.ToString(CultureInfo.InvariantCulture);

        try
        {
            Clipboard.SetText(text);
            StatusText.Text = $"Copied difference {text}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Clipboard Error", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void ApplySelected_OnClick(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not RepairCandidateRow row)
        {
            MessageBox.Show(this, "Select a candidate row first.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (DataTypeBox.SelectedItem is not MemoryDataType dataType)
        {
            MessageBox.Show(this, "Select a data type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        SelectedBaseAddress = row.BaseAddress;
        SelectedDataType = dataType;
        SelectedPointerSizeBytes = row.PointerSizeBytes;
        DialogResult = true;
    }

    private void Close_OnClick(object sender, RoutedEventArgs e)
    {
        _scanCts?.Cancel();
        DialogResult = false;
    }

    private void SetScanUiState(bool isBusy)
    {
        _isScanning = isBusy;
        StartScanButton.IsEnabled = !isBusy;
        CancelScanButton.IsEnabled = isBusy;
        DataTypeBox.IsEnabled = !isBusy;
        ExpectedValueText.IsEnabled = !isBusy;
        RangeText.IsEnabled = !isBusy;
        StepText.IsEnabled = !isBusy;
        MaxResultsText.IsEnabled = !isBusy;

        if (isBusy)
        {
            _valueRefreshTimer.Stop();
        }
        else
        {
            _valueRefreshTimer.Stop();
            _valueRefreshTimer.Start();
        }
    }

    private void RefreshRepairValuesAfterScan()
    {
        if (_results.Count == 0)
        {
            return;
        }

        _resultRefreshCursor = 0;
        const int fullRefreshThreshold = 2000;
        if (_results.Count <= fullRefreshThreshold)
        {
            RefreshRepairValues();
            return;
        }

        RefreshVisibleRepairRows();
        var warmupBatch = ComputeRefreshBatchSize(_results.Count, MinRepairRefreshBatchSize, MaxRepairRefreshBatchSize);
        RefreshRepairValuesCore(Math.Min(_results.Count, warmupBatch));
    }

    private void RefreshRepairValues()
    {
        if (!_memoryAccessor.IsAttached)
        {
            SetRepairValuesUnavailableIncremental();
            return;
        }

        _resultRefreshCursor = 0;
        foreach (var row in _results)
        {
            UpdateRepairRowValue(row);
        }
    }

    private void RefreshRepairValuesIncremental()
    {
        if (!_memoryAccessor.IsAttached)
        {
            SetRepairValuesUnavailableIncremental();
            return;
        }

        var count = _results.Count;
        if (count == 0)
        {
            return;
        }

        var visibleRows = DataGridVisualUtilities.GetVisibleDataGridItems<RepairCandidateRow>(ResultsGrid);
        var visibleSet = visibleRows.Count > 0 ? new HashSet<RepairCandidateRow>(visibleRows) : null;
        foreach (var row in visibleRows)
        {
            UpdateRepairRowValue(row);
        }

        if (_resultRefreshCursor >= count)
        {
            _resultRefreshCursor = 0;
        }

        var backgroundBudget = Math.Min(count, ComputeRefreshBatchSize(count, MinRepairRefreshBatchSize, MaxRepairRefreshBatchSize));
        var updated = 0;
        var attempts = 0;
        while (updated < backgroundBudget && attempts < count)
        {
            if (_resultRefreshCursor >= count)
            {
                _resultRefreshCursor = 0;
            }

            var row = _results[_resultRefreshCursor];
            _resultRefreshCursor++;
            attempts++;

            if (visibleSet is not null && visibleSet.Contains(row))
            {
                continue;
            }

            UpdateRepairRowValue(row);
            updated++;
        }
    }

    private void RefreshRepairValuesCore(int maxUpdates)
    {
        var total = _results.Count;
        if (total == 0 || maxUpdates <= 0)
        {
            return;
        }

        var updates = Math.Min(total, maxUpdates);
        for (var i = 0; i < updates; i++)
        {
            if (_resultRefreshCursor >= total)
            {
                _resultRefreshCursor = 0;
            }

            var row = _results[_resultRefreshCursor];
            _resultRefreshCursor++;
            UpdateRepairRowValue(row);
        }
    }

    private void RefreshVisibleRepairRows()
    {
        foreach (var row in DataGridVisualUtilities.GetVisibleDataGridItems<RepairCandidateRow>(ResultsGrid))
        {
            UpdateRepairRowValue(row);
        }
    }

    private void SetRepairValuesUnavailableIncremental()
    {
        var count = _results.Count;
        if (count == 0)
        {
            return;
        }

        var visibleRows = DataGridVisualUtilities.GetVisibleDataGridItems<RepairCandidateRow>(ResultsGrid);
        var visibleSet = visibleRows.Count > 0 ? new HashSet<RepairCandidateRow>(visibleRows) : null;
        foreach (var row in visibleRows)
        {
            row.ValueText = UnavailableValueText;
        }

        if (_resultRefreshCursor >= count)
        {
            _resultRefreshCursor = 0;
        }

        var backgroundBudget = Math.Min(count, ComputeRefreshBatchSize(count, MinRepairRefreshBatchSize, MaxRepairRefreshBatchSize));
        var updated = 0;
        var attempts = 0;
        while (updated < backgroundBudget && attempts < count)
        {
            if (_resultRefreshCursor >= count)
            {
                _resultRefreshCursor = 0;
            }

            var row = _results[_resultRefreshCursor];
            _resultRefreshCursor++;
            attempts++;

            if (visibleSet is not null && visibleSet.Contains(row))
            {
                continue;
            }

            row.ValueText = UnavailableValueText;
            updated++;
        }
    }

    private void UpdateRepairRowValue(RepairCandidateRow row)
    {
        var dataType = DataTypeBox.SelectedItem is MemoryDataType selected
            ? selected
            : _currentResultDataType;

        var pointerSizeBytes = row.PointerSizeBytes == 4 || row.PointerSizeBytes == 8
            ? row.PointerSizeBytes
            : ResolvePointerSizeBytes(_pointerSizeBytesHint);

        if (!TryResolveFromBase(row.BaseAddress, _offsets, pointerSizeBytes, out var resolvedAddress))
        {
            row.ResolvedAddress = 0;
            row.ResolvedAddressText = "<unresolved>";
            row.ValueText = "<invalid>";
            return;
        }

        row.ResolvedAddress = resolvedAddress;
        row.ResolvedAddressText = _memoryAccessor.FormatAddress(resolvedAddress);

        if (_memoryAccessor.TryReadValue(resolvedAddress, dataType, out var value))
        {
            row.ValueText = FormatValue(value);
        }
        else
        {
            row.ValueText = UnavailableValueText;
        }
    }

    private RepairScanRunResult ExecuteRepairScan(
        MemoryDataType dataType,
        object expectedValue,
        ulong rangeBytes,
        int stepBytes,
        int maxResults,
        IProgress<RepairScanProgress>? progress,
        CancellationToken cancellationToken)
    {
        int pointerSizeBytes = ResolvePointerSizeBytes(_pointerSizeBytesHint);
        var rows = new List<RepairCandidateRow>();

        var candidates = EnumerateCandidateBases(CurrentBaseAddress, rangeBytes, stepBytes).ToArray();
        var total = Math.Max(1, candidates.Length);

        long processed = 0;
        long lastReportTicks = 0;

        for (int i = 0; i < candidates.Length; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var baseCandidate = candidates[i];
            if (!TryResolveFromBase(baseCandidate, _offsets, pointerSizeBytes, out var resolvedAddress))
            {
                processed++;
                TryReportRepairProgress(progress, ref lastReportTicks, processed, total, rows.Count);
                continue;
            }

            if (!_memoryAccessor.TryReadValue(resolvedAddress, dataType, out var currentValue))
            {
                processed++;
                TryReportRepairProgress(progress, ref lastReportTicks, processed, total, rows.Count);
                continue;
            }

            if (ValuesMatch(dataType, currentValue, expectedValue))
            {
                rows.Add(new RepairCandidateRow
                {
                    BaseAddress = baseCandidate,
                    BaseAddressText = _memoryAccessor.FormatAddress(baseCandidate),
                    BaseHex = $"0x{baseCandidate:X}",
                    ResolvedAddress = resolvedAddress,
                    ResolvedAddressText = _memoryAccessor.FormatAddress(resolvedAddress),
                    ValueText = FormatValue(currentValue),
                    PointerSizeBytes = _offsets.Length == 0 ? 0 : pointerSizeBytes
                });

                if (rows.Count >= maxResults)
                {
                    processed = i + 1;
                    break;
                }
            }

            processed++;
            TryReportRepairProgress(progress, ref lastReportTicks, processed, total, rows.Count);
        }

        progress?.Report(new RepairScanProgress
        {
            Percent = 100,
            Status = $"Processed {processed}/{total} | Matches {rows.Count}"
        });

        return new RepairScanRunResult(rows, pointerSizeBytes);
    }

    private void TryReportRepairProgress(
        IProgress<RepairScanProgress>? progress,
        ref long lastReportTicks,
        long processed,
        long total,
        int matches)
    {
        if (progress is null)
        {
            return;
        }

        var nowTicks = Stopwatch.GetTimestamp();
        var minDelta = Stopwatch.Frequency / (1000 / UiProgressThrottleMs);
        if (lastReportTicks != 0 && nowTicks - lastReportTicks < minDelta)
        {
            return;
        }

        lastReportTicks = nowTicks;
        var percent = total <= 0 ? 0 : Math.Clamp((processed * 100.0) / total, 0, 100);
        progress.Report(new RepairScanProgress
        {
            Percent = percent,
            Status = $"Scanning {processed}/{total} | Matches {matches}"
        });
    }

    private bool TryResolveFromBase(ulong baseAddress, IReadOnlyList<int> offsets, int pointerSizeBytes, out ulong resolvedAddress)
    {
        resolvedAddress = baseAddress;

        if (offsets.Count == 0)
        {
            return true;
        }

        var current = baseAddress;
        foreach (var offset in offsets)
        {
            if (!_memoryAccessor.TryReadBytes(current, pointerSizeBytes, out var raw) || raw.Length < pointerSizeBytes)
            {
                return false;
            }

            if (pointerSizeBytes == 4)
            {
                uint ptr32 = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(0, 4));
                long next = (long)ptr32 + offset;
                if (next < 0 || next > uint.MaxValue)
                {
                    return false;
                }

                current = unchecked((uint)next);
            }
            else
            {
                ulong ptr64 = BinaryPrimitives.ReadUInt64LittleEndian(raw.AsSpan(0, 8));
                current = unchecked((ulong)((long)ptr64 + offset));
            }
        }

        resolvedAddress = current;
        return true;
    }

    private int ResolvePointerSizeBytes(int pointerSizeBytesHint)
    {
        if (pointerSizeBytesHint == 4 || pointerSizeBytesHint == 8)
        {
            return pointerSizeBytesHint;
        }

        return IsWow64Process(_memoryAccessor.Process.Handle, out var wow64) && wow64 ? 4 : 8;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr processHandle, out bool wow64Process);

    private static IEnumerable<ulong> EnumerateCandidateBases(ulong baseAddress, ulong rangeBytes, int stepBytes)
    {
        yield return baseAddress;

        var step = (ulong)stepBytes;
        for (ulong delta = step; delta <= rangeBytes; delta += step)
        {
            if (baseAddress >= delta)
            {
                yield return baseAddress - delta;
            }

            if (baseAddress <= ulong.MaxValue - delta)
            {
                yield return baseAddress + delta;
            }

            if (delta > ulong.MaxValue - step)
            {
                break;
            }
        }
    }

    private static bool ValuesMatch(MemoryDataType dataType, object currentValue, object expectedValue)
    {
        return dataType switch
        {
            MemoryDataType.Byte => Convert.ToByte(currentValue) == Convert.ToByte(expectedValue),
            MemoryDataType.Int16 => Convert.ToInt16(currentValue) == Convert.ToInt16(expectedValue),
            MemoryDataType.Int32 => Convert.ToInt32(currentValue) == Convert.ToInt32(expectedValue),
            MemoryDataType.Int64 => Convert.ToInt64(currentValue) == Convert.ToInt64(expectedValue),
            MemoryDataType.Float => Math.Abs(Convert.ToSingle(currentValue) - Convert.ToSingle(expectedValue)) <= 0.0001f,
            MemoryDataType.Double => Math.Abs(Convert.ToDouble(currentValue) - Convert.ToDouble(expectedValue)) <= 0.0000001d,
            MemoryDataType.String => string.Equals(
                Convert.ToString(currentValue, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
                Convert.ToString(expectedValue, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
                StringComparison.Ordinal),
            _ => Equals(currentValue, expectedValue)
        };
    }

    private static bool TryParseUlongInput(string? text, out ulong value)
    {
        value = 0;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var trimmed = text.Trim();
        if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return ulong.TryParse(trimmed[2..], System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out value);
        }

        return ulong.TryParse(trimmed, out value);
    }

    private static string FormatOffset(int offset)
    {
        return offset < 0 ? $"-0x{Math.Abs(offset):X}" : $"0x{offset:X}";
    }

    private static int ComputeRefreshBatchSize(int totalCount, int minBatchSize, int maxBatchSize)
    {
        return RefreshBatchSizer.Compute(totalCount, minBatchSize, maxBatchSize);
    }

    private static string FormatValue(object value)
    {
        return ValueTextFormatter.Format(value);
    }

    protected override void OnClosed(EventArgs e)
    {
        _scanCts?.Cancel();
        _scanCts?.Dispose();
        _valueRefreshTimer.Stop();
        UiUpdateRoutineSettings.ValueRefreshIntervalChanged -= OnGlobalValueRefreshIntervalChanged;
        base.OnClosed(e);
    }

    private sealed class RepairScanProgress
    {
        public double Percent { get; init; }
        public string Status { get; init; } = string.Empty;
    }

    private sealed record RepairScanRunResult(IReadOnlyList<RepairCandidateRow> Rows, int PointerSizeBytes);

    private sealed class RepairCandidateRow : INotifyPropertyChanged
    {
        private string _baseAddressText = string.Empty;
        private string _resolvedAddressText = string.Empty;
        private string _valueText = string.Empty;

        public ulong BaseAddress { get; set; }
        public ulong ResolvedAddress { get; set; }
        public string BaseHex { get; set; } = string.Empty;
        public int PointerSizeBytes { get; set; }

        public string BaseAddressText
        {
            get => _baseAddressText;
            set
            {
                if (_baseAddressText == value) return;
                _baseAddressText = value;
                OnPropertyChanged();
            }
        }

        public string ResolvedAddressText
        {
            get => _resolvedAddressText;
            set
            {
                if (_resolvedAddressText == value) return;
                _resolvedAddressText = value;
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

        public string PointerSizeLabel => PointerSizeBytes <= 0 ? "-" : $"{PointerSizeBytes * 8}-bit";

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}



