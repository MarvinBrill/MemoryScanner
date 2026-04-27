using MemoryScanner.Core;
using MemoryScanner.Models;
using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Windows;

namespace MemoryScanner.Windows;

public partial class PointerRepairWindow : Window
{
    private readonly IMemoryAccessor _memoryAccessor;
    private readonly WatchEntry _entry;
    private readonly PointerRepairMetadata _metadata;
    private readonly int[] _offsets;
    private readonly int _pointerSizeBytesHint;
    private readonly ObservableCollection<PointerRepairCandidateRow> _results = new();

    private CancellationTokenSource? _scanCts;
    private bool _isScanning;

    public ulong CurrentBaseAddress { get; }
    public ulong? SelectedBaseAddress { get; private set; }
    public int SelectedPointerSizeBytes { get; private set; }
    public MemoryDataType SelectedDataType { get; private set; }

    public PointerRepairWindow(
        IMemoryAccessor memoryAccessor,
        WatchEntry entry,
        PointerRepairMetadata metadata,
        ulong currentBaseAddress,
        IReadOnlyList<int> offsets,
        int pointerSizeBytesHint,
        ulong currentResolvedAddress)
    {
        InitializeComponent();

        _memoryAccessor = memoryAccessor;
        _entry = entry;
        _metadata = metadata;
        _offsets = offsets.ToArray();
        _pointerSizeBytesHint = pointerSizeBytesHint;
        CurrentBaseAddress = currentBaseAddress;
        SelectedDataType = entry.DataType;
        SelectedPointerSizeBytes = pointerSizeBytesHint;

        ResultsGrid.ItemsSource = _results;
        DataTypeBox.ItemsSource = MemoryDataTypeUiOrder.Ordered;
        DataTypeBox.SelectedItem = entry.DataType;

        EntryNameText.Text = string.IsNullOrWhiteSpace(entry.Name) ? "Entry" : entry.Name;
        CurrentBaseText.Text = $"{_memoryAccessor.FormatAddress(currentBaseAddress)} (0x{currentBaseAddress:X})";
        CapturedSourceText.Text = string.IsNullOrWhiteSpace(metadata.SourceExpression) ? "-" : metadata.SourceExpression;
        CapturedFinalAddressText.Text = $"0x{metadata.CapturedFinalAddress:X}";
        TargetAddressText.Text = currentResolvedAddress != 0 ? $"0x{currentResolvedAddress:X}" : $"0x{metadata.CapturedFinalAddress:X}";
        ExpectedValueText.Text = string.IsNullOrWhiteSpace(metadata.CapturedFinalValueText) ? entry.LastValueText : metadata.CapturedFinalValueText;
        OffsetsText.Text = _offsets.Length == 0 ? "(no offsets)" : string.Join(", ", _offsets.Select(FormatOffset));
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

        ulong? targetAddress = null;
        var targetAddressText = TargetAddressText.Text.Trim();
        if (!string.IsNullOrWhiteSpace(targetAddressText))
        {
            if (!TryParseUlongInput(targetAddressText, out var parsedTarget))
            {
                MessageBox.Show(this, "Target address must be decimal or hex (0x...).", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            targetAddress = parsedTarget;
        }

        object? expectedValue = null;
        var expectedValueText = ExpectedValueText.Text;
        if (!string.IsNullOrWhiteSpace(expectedValueText))
        {
            if (!ScanService.TryParseValue(dataType, expectedValueText, out var parsedExpected))
            {
                MessageBox.Show(this, "Expected value is invalid for the selected data type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            expectedValue = parsedExpected;
        }

        _scanCts?.Cancel();
        _scanCts?.Dispose();
        _scanCts = new CancellationTokenSource();

        SelectedBaseAddress = null;
        SelectedDataType = dataType;
        _results.Clear();
        ScanProgressBar.Value = 0;
        SetScanUiState(isBusy: true);

        try
        {
            var token = _scanCts.Token;
            var progress = new Progress<PointerRepairProgress>(info =>
            {
                ScanProgressBar.Value = info.Percent;
                StatusText.Text = info.Status;
            });

            var runResult = await Task.Run(
                () => ExecuteRepairScan(dataType, targetAddress, expectedValue, rangeBytes, stepBytes, maxResults, progress, token),
                token);

            foreach (var row in runResult.Rows)
            {
                _results.Add(row);
            }

            SelectedPointerSizeBytes = runResult.PointerSizeBytes;
            ScanProgressBar.Value = 100;
            StatusText.Text = runResult.WasCanceled
                ? $"Canceled | Matches {_results.Count}"
                : $"Done | Matches {_results.Count}";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            MessageBox.Show(this, ex.Message, "Repair Pointer Error", MessageBoxButton.OK, MessageBoxImage.Error);
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

    private void ApplySelected_OnClick(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not PointerRepairCandidateRow selected)
        {
            MessageBox.Show(this, "Select a candidate row first.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (DataTypeBox.SelectedItem is not MemoryDataType dataType)
        {
            return;
        }

        SelectedBaseAddress = selected.BaseAddress;
        SelectedPointerSizeBytes = selected.PointerSizeBytes;
        SelectedDataType = dataType;
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
        RangeText.IsEnabled = !isBusy;
        StepText.IsEnabled = !isBusy;
        MaxResultsText.IsEnabled = !isBusy;
        TargetAddressText.IsEnabled = !isBusy;
        ExpectedValueText.IsEnabled = !isBusy;
    }

    private PointerRepairScanResult ExecuteRepairScan(
        MemoryDataType dataType,
        ulong? targetAddress,
        object? expectedValue,
        ulong rangeBytes,
        int stepBytes,
        int maxResults,
        IProgress<PointerRepairProgress>? progress,
        CancellationToken cancellationToken)
    {
        var pointerSizeBytes = ResolvePointerSizeBytes(_pointerSizeBytesHint);
        var candidateRows = new List<PointerRepairCandidateRow>();
        var candidateBases = EnumerateCandidateBases(CurrentBaseAddress, rangeBytes, stepBytes).ToArray();
        var total = Math.Max(1, candidateBases.Length);
        var processed = 0;

        foreach (var candidateBase in candidateBases)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                break;
            }

            processed++;
            if (!TryResolvePointerStages(candidateBase, pointerSizeBytes, out var liveStages, out var finalAddress))
            {
                progress?.Report(new PointerRepairProgress(processed, total, candidateRows.Count));
                continue;
            }

            string valueText = "???";
            object? currentValue = null;
            if (_memoryAccessor.TryReadValue(finalAddress, dataType, out var value))
            {
                currentValue = value;
                valueText = ValueTextFormatter.Format(value);
            }

            var score = ScoreCandidate(liveStages, finalAddress, currentValue, dataType, targetAddress, expectedValue, out var notes, out var stageMatches);
            if (score > 0)
            {
                candidateRows.Add(new PointerRepairCandidateRow
                {
                    BaseAddress = candidateBase,
                    BaseAddressText = _memoryAccessor.FormatAddress(candidateBase),
                    ResolvedAddress = finalAddress,
                    ResolvedAddressText = _memoryAccessor.FormatAddress(finalAddress),
                    ValueText = valueText,
                    Score = score,
                    StageMatchSummary = $"{stageMatches}/{_metadata.Stages.Count}",
                    Notes = notes,
                    PointerSizeBytes = pointerSizeBytes
                });

                if (candidateRows.Count >= maxResults)
                {
                    break;
                }
            }

            progress?.Report(new PointerRepairProgress(processed, total, candidateRows.Count));
        }

        var ordered = candidateRows
            .OrderByDescending(row => row.Score)
            .ThenBy(row => AbsoluteDifference(row.ResolvedAddress, targetAddress ?? _metadata.CapturedFinalAddress))
            .ToList();

        progress?.Report(new PointerRepairProgress(processed, total, ordered.Count, true));
        return new PointerRepairScanResult(ordered, pointerSizeBytes, cancellationToken.IsCancellationRequested);
    }

    private int ScoreCandidate(
        IReadOnlyList<PointerRepairStageSnapshot> liveStages,
        ulong finalAddress,
        object? currentValue,
        MemoryDataType dataType,
        ulong? targetAddress,
        object? expectedValue,
        out string notes,
        out int stageMatches)
    {
        var score = 0;
        var noteParts = new List<string>();
        stageMatches = 0;

        if (targetAddress.HasValue)
        {
            var diff = AbsoluteDifference(finalAddress, targetAddress.Value);
            if (diff == 0)
            {
                score += 5000;
                noteParts.Add("target match");
            }
            else if (diff <= 0x1000)
            {
                score += 2000 - (int)Math.Min(1800, diff / 4);
            }
        }

        var capturedFinalDiff = AbsoluteDifference(finalAddress, _metadata.CapturedFinalAddress);
        if (capturedFinalDiff == 0)
        {
            score += 2500;
            noteParts.Add("same final address");
        }
        else if (capturedFinalDiff <= 0x4000)
        {
            score += 1200 - (int)Math.Min(1000, capturedFinalDiff / 16);
        }

        if (expectedValue is not null && currentValue is not null && ValuesMatch(dataType, currentValue, expectedValue))
        {
            score += 3200;
            noteParts.Add("value match");
        }

        var comparableStageCount = Math.Min(liveStages.Count, _metadata.Stages.Count);
        for (var i = 0; i < comparableStageCount; i++)
        {
            var liveStage = liveStages[i];
            var savedStage = _metadata.Stages[i];

            if (liveStage.Offset == savedStage.Offset)
            {
                score += 150;
            }

            if (liveStage.PointerValue == savedStage.PointerValue)
            {
                score += 600;
                stageMatches++;
                continue;
            }

            if (liveStage.ResolvedAddress == savedStage.ResolvedAddress)
            {
                score += 900;
                stageMatches++;
                continue;
            }

            var resolvedDiff = AbsoluteDifference(liveStage.ResolvedAddress, savedStage.ResolvedAddress);
            if (resolvedDiff <= 0x1000)
            {
                score += 450 - (int)Math.Min(350, resolvedDiff / 8);
            }
        }

        if (stageMatches > 0)
        {
            noteParts.Add($"stage matches {stageMatches}/{_metadata.Stages.Count}");
        }

        notes = noteParts.Count == 0 ? "heuristic match" : string.Join(" | ", noteParts);
        return Math.Max(score, 0);
    }

    private bool TryResolvePointerStages(
        ulong baseAddress,
        int pointerSizeBytes,
        out IReadOnlyList<PointerRepairStageSnapshot> stages,
        out ulong finalAddress)
    {
        var rows = new List<PointerRepairStageSnapshot>(_offsets.Length);
        finalAddress = baseAddress;
        var currentAddress = baseAddress;

        for (var depthIndex = 0; depthIndex < _offsets.Length; depthIndex++)
        {
            if (!_memoryAccessor.TryReadBytes(currentAddress, pointerSizeBytes, out var raw) || raw.Length < pointerSizeBytes)
            {
                stages = Array.Empty<PointerRepairStageSnapshot>();
                return false;
            }

            if (!TryResolvePointerStep(raw, pointerSizeBytes, _offsets[depthIndex], out var pointerValue, out var resolvedAddress))
            {
                stages = Array.Empty<PointerRepairStageSnapshot>();
                return false;
            }

            rows.Add(new PointerRepairStageSnapshot
            {
                DepthIndex = depthIndex + 1,
                ReadAddress = currentAddress,
                PointerValue = pointerValue,
                Offset = _offsets[depthIndex],
                ResolvedAddress = resolvedAddress
            });

            currentAddress = resolvedAddress;
        }

        finalAddress = currentAddress;
        stages = rows;
        return true;
    }

    private bool TryResolvePointerStep(byte[] rawPointerBytes, int pointerSizeBytes, int offset, out ulong pointerValue, out ulong resolvedAddress)
    {
        pointerValue = 0;
        resolvedAddress = 0;

        if (pointerSizeBytes == 4)
        {
            var pointer32 = BinaryPrimitives.ReadUInt32LittleEndian(rawPointerBytes.AsSpan(0, 4));
            var next = (long)pointer32 + offset;
            if (next < 0 || next > uint.MaxValue)
            {
                return false;
            }

            pointerValue = pointer32;
            resolvedAddress = unchecked((uint)next);
            return true;
        }

        pointerValue = BinaryPrimitives.ReadUInt64LittleEndian(rawPointerBytes.AsSpan(0, 8));
        resolvedAddress = unchecked((ulong)((long)pointerValue + offset));
        return true;
    }

    private int ResolvePointerSizeBytes(int pointerSizeBytesHint)
    {
        if (pointerSizeBytesHint == 4 || pointerSizeBytesHint == 8)
        {
            return pointerSizeBytesHint;
        }

        return IsWow64Process(_memoryAccessor.Process.Handle, out var wow64Process) && wow64Process ? 4 : 8;
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
            return ulong.TryParse(trimmed[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
        }

        return ulong.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private static bool ValuesMatch(MemoryDataType dataType, object currentValue, object expectedValue)
    {
        return dataType switch
        {
            MemoryDataType.Byte => Convert.ToByte(currentValue, CultureInfo.InvariantCulture) == Convert.ToByte(expectedValue, CultureInfo.InvariantCulture),
            MemoryDataType.Int16 => Convert.ToInt16(currentValue, CultureInfo.InvariantCulture) == Convert.ToInt16(expectedValue, CultureInfo.InvariantCulture),
            MemoryDataType.Int32 => Convert.ToInt32(currentValue, CultureInfo.InvariantCulture) == Convert.ToInt32(expectedValue, CultureInfo.InvariantCulture),
            MemoryDataType.Int64 => Convert.ToInt64(currentValue, CultureInfo.InvariantCulture) == Convert.ToInt64(expectedValue, CultureInfo.InvariantCulture),
            MemoryDataType.Float => Math.Abs(Convert.ToSingle(currentValue, CultureInfo.InvariantCulture) - Convert.ToSingle(expectedValue, CultureInfo.InvariantCulture)) <= 0.0001f,
            MemoryDataType.Double => Math.Abs(Convert.ToDouble(currentValue, CultureInfo.InvariantCulture) - Convert.ToDouble(expectedValue, CultureInfo.InvariantCulture)) <= 0.0000001d,
            MemoryDataType.String => string.Equals(
                Convert.ToString(currentValue, CultureInfo.InvariantCulture) ?? string.Empty,
                Convert.ToString(expectedValue, CultureInfo.InvariantCulture) ?? string.Empty,
                StringComparison.Ordinal),
            _ => Equals(currentValue, expectedValue)
        };
    }

    private static ulong AbsoluteDifference(ulong left, ulong right)
    {
        return left >= right ? left - right : right - left;
    }

    private static string FormatOffset(int offset)
    {
        return offset < 0 ? $"-0x{Math.Abs(offset):X}" : $"0x{offset:X}";
    }

    protected override void OnClosed(EventArgs e)
    {
        _scanCts?.Cancel();
        _scanCts?.Dispose();
        base.OnClosed(e);
    }

    private readonly record struct PointerRepairProgress(int Processed, int Total, int Matches, bool IsFinal = false)
    {
        public double Percent => Total <= 0 ? 0 : Math.Clamp((Processed * 100.0) / Total, 0, 100);
        public string Status => IsFinal
            ? $"Processed {Processed}/{Total} | Matches {Matches}"
            : $"Scanning {Processed}/{Total} | Matches {Matches}";
    }

    private sealed record PointerRepairScanResult(IReadOnlyList<PointerRepairCandidateRow> Rows, int PointerSizeBytes, bool WasCanceled);

    private sealed class PointerRepairCandidateRow : INotifyPropertyChanged
    {
        private string _baseAddressText = string.Empty;
        private string _resolvedAddressText = string.Empty;
        private string _valueText = string.Empty;
        private string _notes = string.Empty;
        private string _stageMatchSummary = string.Empty;
        private int _score;

        public ulong BaseAddress { get; set; }
        public ulong ResolvedAddress { get; set; }
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

        public int Score
        {
            get => _score;
            set
            {
                if (_score == value) return;
                _score = value;
                OnPropertyChanged();
            }
        }

        public string StageMatchSummary
        {
            get => _stageMatchSummary;
            set
            {
                if (_stageMatchSummary == value) return;
                _stageMatchSummary = value;
                OnPropertyChanged();
            }
        }

        public string Notes
        {
            get => _notes;
            set
            {
                if (_notes == value) return;
                _notes = value;
                OnPropertyChanged();
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
