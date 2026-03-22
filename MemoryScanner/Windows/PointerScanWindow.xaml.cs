using MemoryScanner.Core;
using MemoryScanner.Models;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Windows;

namespace MemoryScanner.Windows;

public partial class PointerScanWindow : Window
{
    private readonly PointerScanService _pointerScanService;
    private readonly IMemoryAccessor _memoryAccessor;
    private readonly MemoryDataType _valueDataType;
    private ulong _targetAddress;
    private CancellationTokenSource? _scanCts;
    private bool _isScanRunning;
    private PointerScanOptions _runtimeOptions = new();

    public ObservableCollection<PointerPathRow> Rows { get; } = new();

    public List<PointerPath> SelectedPaths { get; private set; } = new();

    public PointerScanWindow(PointerScanService pointerScanService, IMemoryAccessor memoryAccessor, ulong targetAddress, MemoryDataType valueDataType)
    {
        _pointerScanService = pointerScanService;
        _memoryAccessor = memoryAccessor;
        _targetAddress = targetAddress;
        _valueDataType = valueDataType;

        InitializeComponent();
        ResultGrid.ItemsSource = Rows;

        TargetAddressText.Text = $"0x{_targetAddress:X}";
        IncludePrivateBox.IsChecked = _runtimeOptions.IncludePrivate;
        IncludeMappedBox.IsChecked = _runtimeOptions.IncludeMapped;
        IncludeImageBox.IsChecked = _runtimeOptions.IncludeModuleImage;
        RequireStaticRootBox.IsChecked = _runtimeOptions.RequireStaticRoot;

        UpdateOptionsText();
        SetIdleUi();
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
        Rows.Clear();

        var progress = new Progress<ScanProgressInfo>(info =>
        {
            PointerProgressBar.Value = info.Percent;
            PointerProgressText.Text = $"{info.StatusText} {info.Percent:0.0}% ({info.Processed}/{info.Total})";
        });

        SetBusyUi();

        try
        {
            var results = await Task.Run(() => _pointerScanService.Scan(_targetAddress, options, progress, _scanCts.Token));
            foreach (var result in results)
            {
                Rows.Add(new PointerPathRow(result));
            }

            RefreshPointerValues();
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

    private void PointerOptions_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning)
        {
            return;
        }

        var dialog = new PointerScanOptionsWindow(_runtimeOptions) { Owner = this };
        if (dialog.ShowDialog() == true && dialog.SelectedOptions is not null)
        {
            _runtimeOptions.ThreadCount = dialog.SelectedOptions.ThreadCount;
            _runtimeOptions.MaxResults = dialog.SelectedOptions.MaxResults;
            UpdateOptionsText();
        }
    }

    private void PointerPreset_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning)
        {
            return;
        }

        var dialog = new PointerScanPresetWindow(_runtimeOptions.MaxDepth, _runtimeOptions.MaxOffset, _runtimeOptions.Alignment)
        {
            Owner = this
        };

        if (dialog.ShowDialog() == true)
        {
            _runtimeOptions.MaxDepth = dialog.MaxDepth;
            _runtimeOptions.MaxOffset = dialog.MaxOffset;
            _runtimeOptions.Alignment = dialog.Alignment;
            UpdateOptionsText();
        }
    }

    private void RefreshValues_OnClick(object sender, RoutedEventArgs e)
    {
        RefreshPointerValues();
    }

    private void SaveResults_OnClick(object sender, RoutedEventArgs e)
    {
        if (!TryBuildOptions(out var options, out var targetAddress))
        {
            MessageBox.Show(this, "Cannot save: invalid options/address.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var dialog = new SaveFileDialog
        {
            Filter = "Pointer Scan Session (*.json)|*.json|All files (*.*)|*.*",
            DefaultExt = ".json"
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        var session = new PointerScanSession
        {
            TargetAddress = targetAddress,
            ValueDataType = _valueDataType,
            Options = options,
            Results = Rows.Select(r => r.Path).ToList()
        };

        var json = JsonSerializer.Serialize(session, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(dialog.FileName, json);
    }

    private void LoadResults_OnClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Pointer Scan Session (*.json)|*.json|All files (*.*)|*.*"
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        try
        {
            var json = File.ReadAllText(dialog.FileName);
            var session = JsonSerializer.Deserialize<PointerScanSession>(json);
            if (session is null || session.Options is null)
            {
                MessageBox.Show(this, "Invalid file format.", "Load Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _targetAddress = session.TargetAddress;
            TargetAddressText.Text = $"0x{_targetAddress:X}";

            _runtimeOptions.MaxDepth = session.Options.MaxDepth;
            _runtimeOptions.MaxOffset = session.Options.MaxOffset;
            _runtimeOptions.Alignment = session.Options.Alignment;
            _runtimeOptions.ThreadCount = session.Options.ThreadCount;
            _runtimeOptions.MaxResults = session.Options.MaxResults;
            _runtimeOptions.IncludePrivate = session.Options.IncludePrivate;
            _runtimeOptions.IncludeMapped = session.Options.IncludeMapped;
            _runtimeOptions.IncludeModuleImage = session.Options.IncludeModuleImage;
            _runtimeOptions.RequireStaticRoot = session.Options.RequireStaticRoot;

            IncludePrivateBox.IsChecked = _runtimeOptions.IncludePrivate;
            IncludeMappedBox.IsChecked = _runtimeOptions.IncludeMapped;
            IncludeImageBox.IsChecked = _runtimeOptions.IncludeModuleImage;
            RequireStaticRootBox.IsChecked = _runtimeOptions.RequireStaticRoot;

            Rows.Clear();
            foreach (var path in session.Results)
            {
                Rows.Add(new PointerPathRow(path));
            }

            RefreshPointerValues();
            UpdateOptionsText();
            PointerProgressBar.Value = 0;
            PointerProgressText.Text = $"Loaded ({Rows.Count} results)";
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

        if (!TryParseAddress(TargetAddressText.Text, out targetAddress)) return false;

        options.MaxDepth = _runtimeOptions.MaxDepth;
        options.MaxOffset = _runtimeOptions.MaxOffset;
        options.Alignment = _runtimeOptions.Alignment;
        options.ThreadCount = _runtimeOptions.ThreadCount;
        options.MaxResults = _runtimeOptions.MaxResults;
        options.IncludePrivate = IncludePrivateBox.IsChecked == true;
        options.IncludeMapped = IncludeMappedBox.IsChecked == true;
        options.IncludeModuleImage = IncludeImageBox.IsChecked == true;
        options.RequireStaticRoot = RequireStaticRootBox.IsChecked == true;

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

    private void RefreshPointerValues()
    {
        foreach (var row in Rows)
        {
            row.ValueText = ReadPointerValue(row.Path);
        }
    }

    private string ReadPointerValue(PointerPath path)
    {
        var entry = new WatchEntry
        {
            Kind = WatchEntryKind.PointerChain,
            PointerBaseAddress = path.BaseAddress,
            PointerBaseModuleName = path.BaseModuleName,
            PointerBaseModuleOffset = path.BaseModuleOffset,
            DataType = _valueDataType,
            Offsets = new ObservableCollection<int>(path.Offsets)
        };

        if (!_memoryAccessor.TryResolveWatchAddress(entry, out var finalAddress, out _))
        {
            return "<invalid>";
        }

        if (_memoryAccessor.TryReadValue(finalAddress, _valueDataType, out var value))
        {
            return value switch
            {
                float f => f.ToString("0.######", CultureInfo.InvariantCulture),
                double d => d.ToString("0.######", CultureInfo.InvariantCulture),
                _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty
            };
        }

        return "<invalid>";
    }

    private void SetBusyUi()
    {
        _isScanRunning = true;
        StartScanButton.IsEnabled = false;
        PointerOptionsButton.IsEnabled = false;
        PointerPresetButton.IsEnabled = false;
        RefreshValuesButton.IsEnabled = false;
        SaveResultsButton.IsEnabled = false;
        LoadResultsButton.IsEnabled = false;
        CancelScanButton.IsEnabled = true;
        PointerProgressBar.Value = 0;
        PointerProgressText.Text = "Preparing scan...";
    }

    private void SetIdleUi()
    {
        _isScanRunning = false;
        StartScanButton.IsEnabled = true;
        PointerOptionsButton.IsEnabled = true;
        PointerPresetButton.IsEnabled = true;
        RefreshValuesButton.IsEnabled = true;
        SaveResultsButton.IsEnabled = true;
        LoadResultsButton.IsEnabled = true;
        CancelScanButton.IsEnabled = false;
        if (PointerProgressText.Text == "Preparing scan..." || PointerProgressText.Text == "Idle")
        {
            PointerProgressText.Text = "Idle";
        }
    }

    private void UpdateOptionsText()
    {
        PointerOptionsText.Text = $"Options: Threads {_runtimeOptions.ThreadCount}, Limit {_runtimeOptions.MaxResults}, Preset d{_runtimeOptions.MaxDepth}/off{_runtimeOptions.MaxOffset}/a{_runtimeOptions.Alignment}";
    }

    private static bool IsOnlyCancellation(AggregateException ex)
    {
        return ex.Flatten().InnerExceptions.All(inner => inner is OperationCanceledException);
    }

    protected override void OnClosed(EventArgs e)
    {
        _scanCts?.Cancel();
        _scanCts?.Dispose();
        base.OnClosed(e);
    }

    public sealed class PointerPathRow : INotifyPropertyChanged
    {
        private string _valueText = string.Empty;

        public PointerPathRow(PointerPath path)
        {
            Path = path;
            OffsetsDisplay = string.Join(", ", path.Offsets.Select(x => $"0x{x:X}"));
            FinalAddressDisplay = $"0x{path.FinalAddressPreview:X}";
        }

        public PointerPath Path { get; }
        public string DisplayExpression => Path.DisplayExpression;
        public string BaseAddress => $"0x{Path.BaseAddress:X}";
        public string OffsetsDisplay { get; }
        public string FinalAddressDisplay { get; }

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

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    private sealed class PointerScanSession
    {
        public ulong TargetAddress { get; set; }
        public MemoryDataType ValueDataType { get; set; } = MemoryDataType.Int32;
        public PointerScanOptions Options { get; set; } = new();
        public List<PointerPath> Results { get; set; } = new();
    }
}
