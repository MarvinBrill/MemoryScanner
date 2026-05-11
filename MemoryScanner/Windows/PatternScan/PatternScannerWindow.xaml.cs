using MemoryScanner.Core;
using MemoryScanner.Models;
using MemoryScanner.Windows.Shared;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;

namespace MemoryScanner.Windows;

public partial class PatternScannerWindow : Window, INotifyPropertyChanged
{
    private const string UnavailableValueText = "???";
    private const int MinResultRefreshBatchSize = 32;
    private const int MaxResultRefreshBatchSize = 512;

    private readonly PatternScanService _patternScanService;
    private readonly IMemoryAccessor _memoryAccessor;
    private readonly DispatcherTimer _valueRefreshTimer;
    private readonly PatternResultDisplayContext _displayContext;
    private CancellationTokenSource? _scanCts;
    private ScanExecutionOptions _scanOptions = new();
    private PatternGeneralRuleOptions _generalRules = new();
    private string? _currentPresetFilePath;
    private bool _isScanRunning;
    private int _resultRefreshCursor;
    private Stopwatch? _scanStopwatch;
    private string? _lastScanStatusText;
    private double _lastDisplayedProgressPercent;

    public PatternScannerWindow(PatternScanService patternScanService, IMemoryAccessor memoryAccessor)
    {
        _patternScanService = patternScanService;
        _memoryAccessor = memoryAccessor;
        _displayContext = new PatternResultDisplayContext(memoryAccessor);

        InitializeComponent();
        DataContext = this;

        RuleGrid.ItemsSource = Rules;
        ResultGrid.ItemsSource = Rows;

        StartDataTypeBox.ItemsSource = DataTypeChoices;
        StartComparisonBox.ItemsSource = RuleComparisonChoices;
        StartDataTypeBox.SelectedItem = MemoryDataType.Int32;
        StartComparisonBox.SelectedItem = RuleComparisonChoices.First();
        StepSizeText.Text = "4";

        _valueRefreshTimer = new DispatcherTimer();
        _valueRefreshTimer.Tick += ValueRefreshTimer_OnTick;
        UiUpdateRoutineSettings.ValueRefreshIntervalChanged += OnGlobalValueRefreshIntervalChanged;
        ApplyGlobalValueRefreshInterval(UiUpdateRoutineSettings.ValueRefreshIntervalMs);

        Rules.Add(new PatternRuleEditorRow(1, MemoryDataType.Int32, BuildRuleComparisonOptions().First()) { ValueText = "0" });
        RefreshRuleOffsetTexts();
        UpdateGeneralRulesButtonText();
        UpdateWindowTitle();
        RefreshStartCriterionUi();

        SetIdleUi();
    }

    public ObservableCollection<PatternRuleEditorRow> Rules { get; } = new();
    public BulkObservableCollection<PatternResultRow> Rows { get; } = new();
    public IReadOnlyList<MemoryDataType> DataTypeChoices { get; } = MemoryDataTypeUiOrder.Ordered;
    public IReadOnlyList<PatternRuleComparisonOption> RuleComparisonChoices { get; } = BuildRuleComparisonOptions();

    public event PropertyChangedEventHandler? PropertyChanged;
    public event Action<PatternScannerWindow, IReadOnlyList<PatternScanTakeItem>>? TakeSelectedRequested;

    private void MenuLoadPattern_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning)
        {
            return;
        }

        var dialog = new OpenFileDialog
        {
            Filter = "Pattern Preset (*.json)|*.json|All Files (*.*)|*.*",
            Title = "Load Pattern Preset"
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        try
        {
            var json = File.ReadAllText(dialog.FileName);
            var preset = JsonSerializer.Deserialize<PatternScannerPreset>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (preset is null)
            {
                throw new InvalidOperationException("Pattern preset file is empty or invalid.");
            }

            ApplyPreset(preset);
            _currentPresetFilePath = dialog.FileName;
            UpdateWindowTitle();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Load Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void MenuSavePattern_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(_currentPresetFilePath))
        {
            MenuSavePatternAs_OnClick(sender, e);
            return;
        }

        SavePresetToPath(_currentPresetFilePath);
    }

    private void MenuSavePatternAs_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning)
        {
            return;
        }

        var dialog = new SaveFileDialog
        {
            Filter = "Pattern Preset (*.json)|*.json|All Files (*.*)|*.*",
            Title = "Save Pattern Preset",
            FileName = Path.GetFileName(_currentPresetFilePath) ?? "PatternPreset.json"
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        SavePresetToPath(dialog.FileName);
    }

    private async void StartScan_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isScanRunning)
        {
            return;
        }

        if (!_memoryAccessor.IsAttached)
        {
            MessageBox.Show(this, "Select a process first.", "No Process", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (!TryBuildRequest(out var request))
        {
            return;
        }

        _scanCts?.Cancel();
        _scanCts?.Dispose();
        _scanCts = new CancellationTokenSource();
        _scanStopwatch = Stopwatch.StartNew();
        _lastScanStatusText = null;
        _lastDisplayedProgressPercent = 0;

        Rows.Clear();
        _resultRefreshCursor = 0;

        var progress = new Progress<ScanProgressInfo>(info =>
        {
            var displayPercent = Math.Max(_lastDisplayedProgressPercent, info.Percent);
            _lastDisplayedProgressPercent = displayPercent;
            PatternProgressBar.Value = displayPercent;
            PatternProgressText.Text = $"{info.StatusText} {displayPercent:0.0}% ({info.Processed}/{info.Total})";
        });

        SetBusyUi();

        try
        {
            var results = await Task.Run(() => _patternScanService.Scan(request, _scanOptions, progress, _scanCts.Token));
            var rows = results.Select(r => new PatternResultRow(r, _displayContext)).ToArray();
            Rows.ReplaceAll(rows);
            RefreshValuesAfterBulkLoad();
            var firstResultPercentText = BuildFirstResultPercentText(results);

            if (_scanCts.IsCancellationRequested)
            {
                _lastScanStatusText = $"Pattern scan canceled ({rows.Length} partial results){firstResultPercentText} | {FormatElapsedMs()}";
            }
            else
            {
                PatternProgressBar.Value = 100;
                _lastDisplayedProgressPercent = 100;
                _lastScanStatusText = $"Pattern scan finished ({rows.Length} results){firstResultPercentText} | {FormatElapsedMs()}";
            }
        }
        catch (OperationCanceledException)
        {
            _lastScanStatusText = $"Pattern scan canceled | {FormatElapsedMs()}";
        }
        catch (AggregateException ex) when (ExceptionUtilities.IsOnlyCancellation(ex))
        {
            _lastScanStatusText = $"Pattern scan canceled | {FormatElapsedMs()}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Pattern Scan Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _scanStopwatch?.Stop();
            _scanCts?.Dispose();
            _scanCts = null;
            SetIdleUi();
        }
    }

    private void CancelScan_OnClick(object sender, RoutedEventArgs e)
    {
        _scanCts?.Cancel();
    }

    private void PatternScanOptions_OnClick(object sender, RoutedEventArgs e)
    {
        var dialog = new ScanOptionsWindow(CloneScanOptions(_scanOptions))
        {
            Owner = this
        };

        if (dialog.ShowDialog() == true && dialog.SelectedOptions is not null)
        {
            _scanOptions = CloneScanOptions(dialog.SelectedOptions);
            UpdateIdleText();
        }
    }

    private void GeneralRules_OnClick(object sender, RoutedEventArgs e)
    {
        var dialog = new PatternGeneralRulesWindow(CloneGeneralRules(_generalRules))
        {
            Owner = this
        };

        if (dialog.ShowDialog() == true && dialog.SelectedOptions is not null)
        {
            _generalRules = CloneGeneralRules(dialog.SelectedOptions);
            UpdateGeneralRulesButtonText();
            UpdateIdleText();
        }
    }

    private void AddRule_OnClick(object sender, RoutedEventArgs e)
    {
        var nextStep = Rules.Count == 0 ? 1 : Rules[^1].RelativeStep + 1;
        Rules.Add(new PatternRuleEditorRow(nextStep, MemoryDataType.Int32, RuleComparisonChoices.First()) { ValueText = "0" });
    }

    private void RemoveRule_OnClick(object sender, RoutedEventArgs e)
    {
        if (RuleGrid.SelectedItem is not PatternRuleEditorRow selected)
        {
            return;
        }

        Rules.Remove(selected);
    }

    private void TakeSelected_OnClick(object sender, RoutedEventArgs e)
    {
        var items = ResultGrid.SelectedItems.OfType<PatternResultRow>()
            .Select(row => new PatternScanTakeItem(row.Address, row.DataType, row.StringByteLength))
            .ToArray();

        if (items.Length == 0)
        {
            return;
        }

        TakeSelectedRequested?.Invoke(this, items);
    }

    private void TakeAll_OnClick(object sender, RoutedEventArgs e)
    {
        var items = Rows.Select(row => new PatternScanTakeItem(row.Address, row.DataType, row.StringByteLength)).ToArray();
        if (items.Length == 0)
        {
            return;
        }

        TakeSelectedRequested?.Invoke(this, items);
    }

    private void ResultGrid_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateTakeSelectedState();
    }

    private void ResultGrid_OnMouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (_isScanRunning)
        {
            return;
        }

        if (DataGridVisualUtilities.FindAncestor<DataGridRow>(e.OriginalSource as DependencyObject)?.Item is PatternResultRow)
        {
            TakeSelected_OnClick(sender, e);
            e.Handled = true;
        }
    }

    private void ResultGrid_OnScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        RefreshVisibleRows();
    }

    private void StartDataTypeBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        RefreshStartCriterionUi();
    }

    private void StartComparisonBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        RefreshStartCriterionUi();
    }

    private void StepSizeText_OnTextChanged(object sender, TextChangedEventArgs e)
    {
        RefreshRuleOffsetTexts();
    }

    private bool TryBuildRequest(out AddressPatternScanRequest request)
    {
        request = new AddressPatternScanRequest();

        if (StartDataTypeBox.SelectedItem is not MemoryDataType startType)
        {
            MessageBox.Show(this, "Select a valid start data type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        var startComparison = StartComparisonBox.SelectedItem as PatternRuleComparisonOption;
        if (startComparison is null)
        {
            MessageBox.Show(this, "Select a valid start condition.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        if (startType == MemoryDataType.String && startComparison.Value is not (ScanComparison.Equal or ScanComparison.NotEqual))
        {
            MessageBox.Show(this, "String start values only support Equal/Not Equal.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        var startValueText = StartValueText.Text?.Trim() ?? string.Empty;
        if (!ScanService.TryParseValue(startType, startValueText, out _))
        {
            MessageBox.Show(this, "Enter a valid start value.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        var startValueToText = StartValueToText.Text?.Trim() ?? string.Empty;
        if (startComparison.Value == ScanComparison.Between
            && !ScanService.TryParseValue(startType, startValueToText, out _))
        {
            MessageBox.Show(this, "Enter a valid upper start range value.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        if (!int.TryParse(StepSizeText.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var stepSizeBytes) || stepSizeBytes <= 0)
        {
            MessageBox.Show(this, "Step size must be a positive number.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        var ruleDefinitions = new ObservableCollection<AddressPatternRuleDefinition>();
        foreach (var row in Rules)
        {
            var comparison = row.ComparisonOption?.Value ?? ScanComparison.Equal;
            if (row.DataType == MemoryDataType.String && comparison is not (ScanComparison.Equal or ScanComparison.NotEqual))
            {
                MessageBox.Show(this, $"Rule step {row.RelativeStep} only supports Equal/Not Equal for string.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            if (comparison is ScanComparison.Equal or ScanComparison.NotEqual or ScanComparison.Greater or ScanComparison.Less or ScanComparison.Between)
            {
                if (!ScanService.TryParseValue(row.DataType, row.ValueText, out _))
                {
                    MessageBox.Show(this, $"Rule step {row.RelativeStep} has an invalid value.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }
            }

            if (comparison == ScanComparison.Between && !ScanService.TryParseValue(row.DataType, row.ValueToText, out _))
            {
                MessageBox.Show(this, $"Rule step {row.RelativeStep} has an invalid upper range value.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            ruleDefinitions.Add(new AddressPatternRuleDefinition
            {
                RelativeStep = row.RelativeStep,
                DataType = row.DataType,
                Comparison = comparison,
                ValueText = row.ValueText ?? string.Empty,
                ValueToText = row.ValueToText ?? string.Empty
            });
        }

        request = new AddressPatternScanRequest
        {
            StartDataType = startType,
            StartComparison = startComparison.Value,
            StartValueText = startValueText,
            StartValueToText = startValueToText,
            StartStringByteLength = startType == MemoryDataType.String ? ResolveStringByteLength(startValueText) : 0,
            StepSizeBytes = stepSizeBytes,
            Rules = ruleDefinitions,
            GeneralRules = CloneGeneralRules(_generalRules)
        };

        RefreshRuleOffsetTexts(stepSizeBytes);
        return true;
    }

    private void SetBusyUi()
    {
        _isScanRunning = true;
        _valueRefreshTimer.Stop();
        StartScanButton.IsEnabled = false;
        PatternScanOptionsButton.IsEnabled = false;
        StartDataTypeBox.IsEnabled = false;
        StartComparisonBox.IsEnabled = false;
        StartValueText.IsEnabled = false;
        StartValueToText.IsEnabled = false;
        StepSizeText.IsEnabled = false;
        RuleGrid.IsEnabled = false;
        CancelScanButton.IsEnabled = true;
        PatternProgressBar.Value = 0;
        _lastDisplayedProgressPercent = 0;
        PatternProgressText.Text = "Preparing pattern scan...";
        UpdateTakeSelectedState();
    }

    private void SetIdleUi()
    {
        _isScanRunning = false;
        _valueRefreshTimer.Start();
        StartScanButton.IsEnabled = true;
        PatternScanOptionsButton.IsEnabled = true;
        StartDataTypeBox.IsEnabled = true;
        StartComparisonBox.IsEnabled = true;
        StartValueText.IsEnabled = true;
        StartValueToText.IsEnabled = true;
        StepSizeText.IsEnabled = true;
        RuleGrid.IsEnabled = true;
        CancelScanButton.IsEnabled = false;
        UpdateTakeSelectedState();
        RefreshStartCriterionUi();
        UpdateIdleText();
    }

    private void UpdateTakeSelectedState()
    {
        TakeSelectedButton.IsEnabled = !_isScanRunning && ResultGrid.SelectedItems.Count >= 1;
        TakeAllButton.IsEnabled = !_isScanRunning && Rows.Count > 0;
    }

    private void UpdateIdleText()
    {
        var updateMs = UiUpdateRoutineSettings.ValueRefreshIntervalMs;
        var idleText = $"Idle | {BuildGeneralRulesSummary()} | Update {updateMs} ms | Results {Rows.Count}";
        PatternProgressText.Text = string.IsNullOrWhiteSpace(_lastScanStatusText)
            ? idleText
            : $"{_lastScanStatusText} | {idleText}";
    }

    private void UpdateWindowTitle()
    {
        var fileSuffix = string.IsNullOrWhiteSpace(_currentPresetFilePath)
            ? string.Empty
            : $" - {Path.GetFileName(_currentPresetFilePath)}";
        Title = $"Pattern Scanner{fileSuffix}";
    }

    private void UpdateGeneralRulesButtonText()
    {
        if (GeneralRulesButton is null)
        {
            return;
        }

        GeneralRulesButton.Content = _generalRules.StopAfterGapFromLastMatchEnabled
            || _generalRules.SearchOrder != PatternSearchOrder.StartToEnd
            || _generalRules.SearchFocus == PatternSearchFocus.Fine
            ? $"General Rules*"
            : "General Rules";
    }

    private string BuildGeneralRulesSummary()
    {
        var orderText = _generalRules.SearchOrder switch
        {
            PatternSearchOrder.MiddleToOutside => "Order Middle->Outside",
            PatternSearchOrder.EndToStart => "Order End->Start",
            PatternSearchOrder.CustomPercentToOutside => $"Order {_generalRules.CustomSearchStartPercent}%->Outside",
            _ => "Order Start->End"
        };
        var focusText = _generalRules.SearchFocus switch
        {
            PatternSearchFocus.Fine => "Focus Fine",
            _ => "Focus Fast"
        };

        if (_generalRules.StopAfterGapFromLastMatchEnabled)
        {
            return $"{orderText} | {focusText} | Gap {_generalRules.MaxAddressesWithoutMatchAfterFirstHit}";
        }

        return $"{orderText} | {focusText}";
    }

    private void RefreshValuesAfterBulkLoad()
    {
        _resultRefreshCursor = 0;
        RefreshVisibleRows();
        RefreshValuesIncremental();
        UpdateIdleText();
    }

    private void ValueRefreshTimer_OnTick(object? sender, EventArgs e)
    {
        RefreshValuesIncremental();
    }

    private void RefreshValuesIncremental()
    {
        if (Rows.Count == 0)
        {
            return;
        }

        if (!_memoryAccessor.IsAttached)
        {
            SetUnavailableValuesIncremental();
            return;
        }

        var visibleRows = DataGridVisualUtilities.GetVisibleDataGridItems<PatternResultRow>(ResultGrid);
        var visibleSet = visibleRows.Count > 0 ? new HashSet<PatternResultRow>(visibleRows) : null;
        foreach (var row in visibleRows)
        {
            UpdateRowValue(row);
        }

        if (_resultRefreshCursor >= Rows.Count)
        {
            _resultRefreshCursor = 0;
        }

        var backgroundBudget = Math.Min(Rows.Count, RefreshBatchSizer.Compute(Rows.Count, MinResultRefreshBatchSize, MaxResultRefreshBatchSize));
        while (backgroundBudget-- > 0 && Rows.Count > 0)
        {
            if (_resultRefreshCursor >= Rows.Count)
            {
                _resultRefreshCursor = 0;
            }

            var row = Rows[_resultRefreshCursor];
            _resultRefreshCursor++;
            if (visibleSet is not null && visibleSet.Contains(row))
            {
                continue;
            }

            UpdateRowValue(row);
        }
    }

    private void SetUnavailableValuesIncremental()
    {
        var visibleRows = DataGridVisualUtilities.GetVisibleDataGridItems<PatternResultRow>(ResultGrid);
        var visibleSet = visibleRows.Count > 0 ? new HashSet<PatternResultRow>(visibleRows) : null;
        foreach (var row in visibleRows)
        {
            row.ValueText = UnavailableValueText;
        }

        if (_resultRefreshCursor >= Rows.Count)
        {
            _resultRefreshCursor = 0;
        }

        var backgroundBudget = Math.Min(Rows.Count, RefreshBatchSizer.Compute(Rows.Count, MinResultRefreshBatchSize, MaxResultRefreshBatchSize));
        while (backgroundBudget-- > 0 && Rows.Count > 0)
        {
            if (_resultRefreshCursor >= Rows.Count)
            {
                _resultRefreshCursor = 0;
            }

            var row = Rows[_resultRefreshCursor];
            _resultRefreshCursor++;
            if (visibleSet is not null && visibleSet.Contains(row))
            {
                continue;
            }

            row.ValueText = UnavailableValueText;
        }
    }

    private void RefreshVisibleRows()
    {
        foreach (var row in DataGridVisualUtilities.GetVisibleDataGridItems<PatternResultRow>(ResultGrid))
        {
            UpdateRowValue(row);
        }
    }

    private void UpdateRowValue(PatternResultRow row)
    {
        if (!_memoryAccessor.IsAttached)
        {
            row.ValueText = UnavailableValueText;
            return;
        }

        if (_memoryAccessor.TryReadValue(row.Address, row.DataType, out var value, row.StringByteLength))
        {
            row.ValueText = ValueTextFormatter.Format(value);
        }
        else
        {
            row.ValueText = "<invalid>";
        }
    }

    private void OnGlobalValueRefreshIntervalChanged(object? sender, int milliseconds)
    {
        ApplyGlobalValueRefreshInterval(milliseconds);
    }

    private void ApplyGlobalValueRefreshInterval(int milliseconds)
    {
        _valueRefreshTimer.Interval = TimeSpan.FromMilliseconds(milliseconds < 1 ? UiUpdateRoutineSettings.DefaultIntervalMs : milliseconds);
        if (!_valueRefreshTimer.IsEnabled && !_isScanRunning)
        {
            _valueRefreshTimer.Start();
        }

        UpdateIdleText();
    }

    private void RefreshRuleOffsetTexts(int? overrideStepSize = null)
    {
        var stepSize = overrideStepSize ?? (int.TryParse(StepSizeText.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) && parsed > 0 ? parsed : 4);
        foreach (var row in Rules)
        {
            row.StepSizeBytes = stepSize;
        }
    }

    private void RefreshStartCriterionUi()
    {
        var selectedType = StartDataTypeBox.SelectedItem as MemoryDataType? ?? MemoryDataType.Int32;
        var selectedComparison = StartComparisonBox.SelectedItem as PatternRuleComparisonOption ?? RuleComparisonChoices.First();

        if (selectedType == MemoryDataType.String
            && selectedComparison.Value is not (ScanComparison.Equal or ScanComparison.NotEqual))
        {
            var fallback = RuleComparisonChoices.FirstOrDefault(option => option.Value == ScanComparison.Equal) ?? RuleComparisonChoices.First();
            StartComparisonBox.SelectedItem = fallback;
            selectedComparison = fallback;
        }

        var isRange = selectedComparison.Value == ScanComparison.Between;
        StartValueToLabel.IsEnabled = isRange;
        StartValueToText.IsEnabled = !_isScanRunning && isRange;
        StartValueToText.Visibility = isRange ? Visibility.Visible : Visibility.Collapsed;
        StartValueToLabel.Visibility = isRange ? Visibility.Visible : Visibility.Collapsed;

        if (selectedType == MemoryDataType.String)
        {
            StartValueText.ToolTip = "String start values support Equal and Not Equal.";
        }
        else
        {
            StartValueText.ClearValue(ToolTipProperty);
        }
    }

    private static int ResolveStringByteLength(string value)
    {
        return Math.Clamp(System.Text.Encoding.UTF8.GetByteCount(value) + 1, 1, 4096);
    }

    private static ScanExecutionOptions CloneScanOptions(ScanExecutionOptions source)
    {
        return new ScanExecutionOptions
        {
            DepthProfile = source.DepthProfile,
            ThreadCount = source.ThreadCount,
            UseResultLimit = source.UseResultLimit,
            ResultLimit = source.ResultLimit,
            IncludeMapped = source.IncludeMapped
        };
    }

    private string FormatElapsedMs()
    {
        var elapsed = _scanStopwatch?.ElapsedMilliseconds ?? 0;
        return $"{elapsed} ms";
    }

    private static string BuildFirstResultPercentText(IReadOnlyList<AddressPatternScanResult> results)
    {
        if (results.Count == 0)
        {
            return string.Empty;
        }

        var firstResultPercent = results[0].GlobalAddressPercent;
        return firstResultPercent.HasValue
            ? $" | First result @ {firstResultPercent.Value:0.0}%"
            : string.Empty;
    }

    private static PatternGeneralRuleOptions CloneGeneralRules(PatternGeneralRuleOptions source)
    {
        return new PatternGeneralRuleOptions
        {
            SearchOrder = source.SearchOrder,
            SearchFocus = source.SearchFocus,
            CustomSearchStartPercent = source.CustomSearchStartPercent,
            StopAfterGapFromLastMatchEnabled = source.StopAfterGapFromLastMatchEnabled,
            MaxAddressesWithoutMatchAfterFirstHit = source.MaxAddressesWithoutMatchAfterFirstHit
        };
    }

    private void SavePresetToPath(string filePath)
    {
        try
        {
            var preset = BuildPreset();
            var json = JsonSerializer.Serialize(preset, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            File.WriteAllText(filePath, json);
            _currentPresetFilePath = filePath;
            UpdateWindowTitle();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Save Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private PatternScannerPreset BuildPreset()
    {
        var startType = StartDataTypeBox.SelectedItem as MemoryDataType? ?? MemoryDataType.Int32;
        var stepSizeBytes = int.TryParse(StepSizeText.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedStep) && parsedStep > 0
            ? parsedStep
            : 4;

        return new PatternScannerPreset
        {
            StartDataType = startType,
            StartComparison = (StartComparisonBox.SelectedItem as PatternRuleComparisonOption)?.Value ?? ScanComparison.Equal,
            StartValueText = StartValueText.Text ?? string.Empty,
            StartValueToText = StartValueToText.Text ?? string.Empty,
            StartStringByteLength = startType == MemoryDataType.String ? ResolveStringByteLength(StartValueText.Text ?? string.Empty) : 0,
            StepSizeBytes = stepSizeBytes,
            Rules = Rules.Select(row => new AddressPatternRuleDefinition
            {
                RelativeStep = row.RelativeStep,
                DataType = row.DataType,
                Comparison = row.ComparisonOption?.Value ?? ScanComparison.Equal,
                ValueText = row.ValueText ?? string.Empty,
                ValueToText = row.ValueToText ?? string.Empty
            }).ToList(),
            GeneralRules = CloneGeneralRules(_generalRules),
            ScanOptions = CloneScanOptions(_scanOptions)
        };
    }

    private void ApplyPreset(PatternScannerPreset preset)
    {
        StartDataTypeBox.SelectedItem = preset.StartDataType;
        StartComparisonBox.SelectedItem = RuleComparisonChoices.FirstOrDefault(option => option.Value == preset.StartComparison) ?? RuleComparisonChoices.First();
        StartValueText.Text = preset.StartValueText ?? string.Empty;
        StartValueToText.Text = preset.StartValueToText ?? string.Empty;
        StepSizeText.Text = Math.Max(1, preset.StepSizeBytes).ToString(CultureInfo.InvariantCulture);
        _generalRules = CloneGeneralRules(preset.GeneralRules ?? new PatternGeneralRuleOptions());
        _scanOptions = CloneScanOptions(preset.ScanOptions ?? new ScanExecutionOptions());

        Rules.Clear();
        foreach (var rule in preset.Rules ?? Enumerable.Empty<AddressPatternRuleDefinition>())
        {
            var comparisonOption = RuleComparisonChoices.FirstOrDefault(x => x.Value == rule.Comparison) ?? RuleComparisonChoices.First();
            Rules.Add(new PatternRuleEditorRow(rule.RelativeStep, rule.DataType, comparisonOption)
            {
                ValueText = rule.ValueText ?? string.Empty,
                ValueToText = rule.ValueToText ?? string.Empty
            });
        }

        if (Rules.Count == 0)
        {
            Rules.Add(new PatternRuleEditorRow(1, MemoryDataType.Int32, RuleComparisonChoices.First()) { ValueText = "0" });
        }

        RefreshRuleOffsetTexts();
        UpdateGeneralRulesButtonText();
        RefreshStartCriterionUi();
    }

    private static IReadOnlyList<PatternRuleComparisonOption> BuildRuleComparisonOptions()
    {
        return new[]
        {
            new PatternRuleComparisonOption(ScanComparison.Equal, "Equal"),
            new PatternRuleComparisonOption(ScanComparison.NotEqual, "Not Equal"),
            new PatternRuleComparisonOption(ScanComparison.Greater, "Greater"),
            new PatternRuleComparisonOption(ScanComparison.Less, "Less"),
            new PatternRuleComparisonOption(ScanComparison.Between, "Between (Range)")
        };
    }

    protected override void OnClosed(EventArgs e)
    {
        _scanCts?.Cancel();
        _scanCts?.Dispose();
        UiUpdateRoutineSettings.ValueRefreshIntervalChanged -= OnGlobalValueRefreshIntervalChanged;
        _valueRefreshTimer.Stop();
        base.OnClosed(e);
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    public sealed record PatternScanTakeItem(ulong Address, MemoryDataType DataType, int StringByteLength);

    public sealed class PatternResultRow : INotifyPropertyChanged
    {
        private string _valueText;

        public PatternResultRow(AddressPatternScanResult result, PatternResultDisplayContext displayContext)
        {
            Address = result.Address;
            DataType = result.DataType;
            StringByteLength = result.StringByteLength;
            PreviewText = result.PreviewText;
            _valueText = result.ValueText;
            DisplayAddress = displayContext.FormatAddress(Address);
            IsProcessBaseDisplay = displayContext.IsProcessBaseAddress(DisplayAddress);
        }

        public ulong Address { get; }
        public string AddressHex => $"0x{Address:X}";
        public string DisplayAddress { get; }
        public bool IsProcessBaseDisplay { get; }
        public string PreviewText { get; }
        public MemoryDataType DataType { get; }
        public int StringByteLength { get; }

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
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ValueText)));
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
    }

    public sealed class PatternRuleEditorRow : INotifyPropertyChanged
    {
        private int _relativeStep;
        private MemoryDataType _dataType;
        private PatternRuleComparisonOption? _comparisonOption;
        private string _valueText = string.Empty;
        private string _valueToText = string.Empty;
        private int _stepSizeBytes = 4;

        public PatternRuleEditorRow(int relativeStep, MemoryDataType dataType, PatternRuleComparisonOption comparisonOption)
        {
            _relativeStep = relativeStep;
            _dataType = dataType;
            _comparisonOption = comparisonOption;
        }

        public int RelativeStep
        {
            get => _relativeStep;
            set
            {
                if (_relativeStep == value)
                {
                    return;
                }

                _relativeStep = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(EffectiveOffsetText));
            }
        }

        public MemoryDataType DataType
        {
            get => _dataType;
            set
            {
                if (_dataType == value)
                {
                    return;
                }

                _dataType = value;
                OnPropertyChanged();
            }
        }

        public PatternRuleComparisonOption? ComparisonOption
        {
            get => _comparisonOption;
            set
            {
                if (Equals(_comparisonOption, value))
                {
                    return;
                }

                _comparisonOption = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(ComparisonLabel));
            }
        }

        public string ComparisonLabel => ComparisonOption?.Label ?? string.Empty;

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

        public string ValueToText
        {
            get => _valueToText;
            set
            {
                if (_valueToText == value)
                {
                    return;
                }

                _valueToText = value;
                OnPropertyChanged();
            }
        }

        public int StepSizeBytes
        {
            get => _stepSizeBytes;
            set
            {
                if (_stepSizeBytes == value)
                {
                    return;
                }

                _stepSizeBytes = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(EffectiveOffsetText));
            }
        }

        public string EffectiveOffsetText => $"{RelativeStep * StepSizeBytes:+#;-#;0} bytes";

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public sealed class PatternRuleComparisonOption
    {
        public PatternRuleComparisonOption(ScanComparison value, string label)
        {
            Value = value;
            Label = label;
        }

        public ScanComparison Value { get; }
        public string Label { get; }

        public override bool Equals(object? obj)
        {
            return obj is PatternRuleComparisonOption other && other.Value == Value;
        }

        public override int GetHashCode()
        {
            return (int)Value;
        }
    }

    public sealed class PatternResultDisplayContext
    {
        private readonly bool _useProcessBaseFormatting;
        private readonly string? _processBasePrefix;
        private readonly string _processName = "Process";
        private readonly List<ModuleRange> _modules = new();

        public PatternResultDisplayContext(IMemoryAccessor memoryAccessor)
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
