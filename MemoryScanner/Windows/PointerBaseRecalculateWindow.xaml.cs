using MemoryScanner.Core;
using MemoryScanner.Models;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows;

namespace MemoryScanner.Windows;

public partial class PointerBaseRecalculateWindow : Window
{
    private readonly IMemoryAccessor _memoryAccessor;
    private readonly int[] _offsets;
    private readonly int _pointerSizeBytesHint;
    private readonly MemoryDataType _dataType;

    public ulong CurrentBaseAddress { get; }
    public ulong? SelectedBaseAddress { get; private set; }
    public int SelectedPointerSizeBytes { get; private set; }

    public PointerBaseRecalculateWindow(
        IMemoryAccessor memoryAccessor,
        ulong currentBaseAddress,
        IReadOnlyList<int> offsets,
        int pointerSizeBytesHint,
        MemoryDataType dataType)
    {
        InitializeComponent();

        _memoryAccessor = memoryAccessor;
        CurrentBaseAddress = currentBaseAddress;
        _offsets = offsets.ToArray();
        _pointerSizeBytesHint = pointerSizeBytesHint;
        _dataType = dataType;
        SelectedPointerSizeBytes = pointerSizeBytesHint;

        CurrentBaseText.Text = $"Current base: {_memoryAccessor.FormatAddress(currentBaseAddress)} (0x{currentBaseAddress:X})";

        DirectionBox.ItemsSource = new[]
        {
            new DirectionOption("Add (+)", DirectionMode.Add),
            new DirectionOption("Subtract (-)", DirectionMode.Subtract)
        };
        DirectionBox.SelectedIndex = 0;

        DifferenceTextBox.Text = "0x0";
        ApplyButton.IsEnabled = false;
    }

    private void DifferenceTextBox_OnTextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        UpdatePreview();
    }

    private void DirectionBox_OnSelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        UpdatePreview();
    }

    private void UpdatePreview()
    {
        ApplyButton.IsEnabled = false;
        SelectedBaseAddress = null;

        if (!TryParseUlongInput(DifferenceTextBox.Text, out var difference))
        {
            RecalculatedBaseText.Text = "-";
            ResolvedAddressText.Text = "-";
            ValuePreviewText.Text = "-";
            StatusText.Text = "Difference must be a decimal value or hex value (0x...).";
            return;
        }

        var mode = (DirectionBox.SelectedItem as DirectionOption)?.Mode ?? DirectionMode.Add;
        if (!TryCalculateBase(CurrentBaseAddress, difference, mode, out var recalculatedBase))
        {
            RecalculatedBaseText.Text = "-";
            ResolvedAddressText.Text = "-";
            ValuePreviewText.Text = "-";
            StatusText.Text = "Overflow/underflow for selected direction.";
            return;
        }

        RecalculatedBaseText.Text = $"{_memoryAccessor.FormatAddress(recalculatedBase)} (0x{recalculatedBase:X})";

        if (!_memoryAccessor.IsAttached)
        {
            ResolvedAddressText.Text = "<process not attached>";
            ValuePreviewText.Text = "???";
            StatusText.Text = "Process not attached. Address preview only.";
            ApplyButton.IsEnabled = true;
            SelectedBaseAddress = recalculatedBase;
            return;
        }

        var tempEntry = new WatchEntry
        {
            Kind = WatchEntryKind.PointerChain,
            PointerBaseAddress = recalculatedBase,
            PointerSizeBytes = _pointerSizeBytesHint,
            DataType = _dataType,
            Offsets = new ObservableCollection<int>(_offsets)
        };

        if (!_memoryAccessor.TryResolveWatchAddress(tempEntry, out var resolvedAddress, out var resolvedDisplay))
        {
            ResolvedAddressText.Text = "<unresolved>";
            ValuePreviewText.Text = "???";
            StatusText.Text = "Pointer could not be resolved for this base.";
            ApplyButton.IsEnabled = true;
            SelectedBaseAddress = recalculatedBase;
            return;
        }

        ResolvedAddressText.Text = $"{resolvedDisplay} (0x{resolvedAddress:X})";
        if (_memoryAccessor.TryReadValue(resolvedAddress, _dataType, out var value))
        {
            ValuePreviewText.Text = FormatValue(value);
            StatusText.Text = "Preview ready.";
        }
        else
        {
            ValuePreviewText.Text = "???";
            StatusText.Text = "Address resolved, but value could not be read.";
        }

        SelectedBaseAddress = recalculatedBase;
        ApplyButton.IsEnabled = true;
    }

    private static bool TryCalculateBase(ulong current, ulong difference, DirectionMode mode, out ulong result)
    {
        result = 0;
        if (mode == DirectionMode.Add)
        {
            if (current > ulong.MaxValue - difference)
            {
                return false;
            }

            result = current + difference;
            return true;
        }

        if (current < difference)
        {
            return false;
        }

        result = current - difference;
        return true;
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

    private static string FormatValue(object value)
    {
        return value switch
        {
            float f => f.ToString("0.######", CultureInfo.InvariantCulture),
            double d => d.ToString("0.######", CultureInfo.InvariantCulture),
            _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty
        };
    }

    private void Apply_OnClick(object sender, RoutedEventArgs e)
    {
        if (!SelectedBaseAddress.HasValue)
        {
            return;
        }

        DialogResult = true;
    }

    private void Cancel_OnClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private sealed record DirectionOption(string Label, DirectionMode Mode)
    {
        public override string ToString() => Label;
    }

    private enum DirectionMode
    {
        Add,
        Subtract
    }
}
