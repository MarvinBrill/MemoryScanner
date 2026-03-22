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
using System.Windows.Threading;

namespace MemoryScanner.Windows;

public partial class PointerScanWindow : Window
{
    private readonly PointerScanService _pointerScanService;
    private readonly IMemoryAccessor _memoryAccessor;
    private readonly MemoryDataType _valueDataType;
    private readonly DispatcherTimer _valueRefreshTimer;

    private ulong _targetAddress;
    private CancellationTokenSource? _scanCts;
    private bool _isScanRunning;
    private PointerScanOptions _runtimeOptions = new();
    private string? _currentSessionFilePath;

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

        _valueRefreshTimer = new DispatcherTimer();
        _valueRefreshTimer.Tick += ValueRefreshTimer_OnTick;
        UiUpdateRoutineSettings.ValueRefreshIntervalChanged += OnGlobalValueRefreshIntervalChanged;
        ApplyGlobalValueRefreshInterval(UiUpdateRoutineSettings.ValueRefreshIntervalMs);

        UpdateOptionsText();
        SetIdleUi();
        UpdateWindowTitle();
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
                Rows.Add(CreatePointerPathRow(result));
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
        if (dialog.ShowDialog() != true || dialog.SelectedOptions is null)
        {
            return;
        }

        _runtimeOptions = dialog.SelectedOptions;
        UpdateOptionsText();
    }

    private void ValueRefreshTimer_OnTick(object? sender, EventArgs e)
    {
        RefreshPointerValues();
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
                ValueDataType = _valueDataType,
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

            Rows.Clear();
            foreach (var pathEntry in session.Results)
            {
                Rows.Add(CreatePointerPathRow(NormalizeLoadedPathForRuntime(pathEntry)));
            }

            RefreshPointerValues();
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
            FinalAddressPreview = source.FinalAddressPreview
        };
    }

    private PointerPathRow CreatePointerPathRow(PointerPath path)
    {
        return new PointerPathRow(path)
        {
            PointerExpressionText = BuildPointerExpression(path)
        };
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

        var offsetText = string.Join(", ", path.Offsets.Select(x => $"0x{x:X}"));
        return $"{baseText} -> [{offsetText}]";
    }

    private void RefreshPointerValues()
    {
        foreach (var row in Rows)
        {
            row.PointerExpressionText = BuildPointerExpression(row.Path);

            if (TryResolvePointerValue(row.Path, out var valueText, out var currentAddressText))
            {
                row.ValueText = valueText;
                row.CurrentAddressText = currentAddressText;
            }
            else
            {
                row.ValueText = "<invalid>";
                row.CurrentAddressText = "<unresolved>";
            }
        }
    }

    private bool TryResolvePointerValue(PointerPath path, out string valueText, out string currentAddressText)
    {
        valueText = "<invalid>";
        currentAddressText = "<unresolved>";

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
            return false;
        }

        currentAddressText = _memoryAccessor.FormatAddress(finalAddress);

        if (!_memoryAccessor.TryReadValue(finalAddress, _valueDataType, out var value))
        {
            return false;
        }

        valueText = value switch
        {
            float f => f.ToString("0.######", CultureInfo.InvariantCulture),
            double d => d.ToString("0.######", CultureInfo.InvariantCulture),
            _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty
        };

        return true;
    }

    private void SetBusyUi()
    {
        _isScanRunning = true;
        _valueRefreshTimer.Stop();
        StartScanButton.IsEnabled = false;
        PointerOptionsButton.IsEnabled = false;
        CancelScanButton.IsEnabled = true;
        PointerProgressBar.Value = 0;
        PointerProgressText.Text = "Preparing scan...";
    }

    private void SetIdleUi()
    {
        _isScanRunning = false;
        ApplyGlobalValueRefreshInterval(UiUpdateRoutineSettings.ValueRefreshIntervalMs);
        StartScanButton.IsEnabled = true;
        PointerOptionsButton.IsEnabled = true;
        CancelScanButton.IsEnabled = false;
        if (PointerProgressText.Text == "Preparing scan..." || PointerProgressText.Text == "Idle")
        {
            PointerProgressText.Text = "Idle";
        }
    }

    private void UpdateOptionsText()
    {
        var updateMs = UiUpdateRoutineSettings.ValueRefreshIntervalMs;
        var limitText = _runtimeOptions.UseResultLimit ? _runtimeOptions.MaxResults.ToString(CultureInfo.InvariantCulture) : "off";
        PointerOptionsText.Text = $"Options: Threads {_runtimeOptions.ThreadCount}, Limit {limitText}, Preset d{_runtimeOptions.MaxDepth}/off{_runtimeOptions.MaxOffset}/a{_runtimeOptions.Alignment}, Update {updateMs} ms";
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

    public sealed class PointerPathRow : INotifyPropertyChanged
    {
        private string _pointerExpressionText = string.Empty;
        private string _valueText = string.Empty;
        private string _currentAddressText = "<unresolved>";

        public PointerPathRow(PointerPath path)
        {
            Path = path;
            OffsetsDisplay = string.Join(", ", path.Offsets.Select(x => $"0x{x:X}"));
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
