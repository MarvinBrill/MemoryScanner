using MemoryScanner.Core;
using MemoryScanner.Models;
using System.Globalization;
using System.Windows;

namespace MemoryScanner.Windows;

public enum PointerRescanMode
{
    Address,
    Value
}

public sealed class PointerRescanRequest
{
    public PointerRescanMode Mode { get; init; }
    public ulong Address { get; init; }
    public MemoryDataType ValueDataType { get; init; }
    public object? Value { get; init; }
    public string ValueTextRaw { get; init; } = string.Empty;
}

public partial class PointerRescanWindow : Window
{
    public PointerRescanRequest? Request { get; private set; }

    public PointerRescanWindow(ulong defaultAddress, MemoryDataType defaultValueType)
    {
        InitializeComponent();

        AddressText.Text = $"0x{defaultAddress:X}";
        ValueTypeBox.ItemsSource = MemoryDataTypeUiOrder.Ordered;
        ValueTypeBox.SelectedItem = defaultValueType;

        ByAddressRadio.IsChecked = true;
        UpdateInputState();
    }

    private void ModeChanged_OnChecked(object sender, RoutedEventArgs e)
    {
        UpdateInputState();
    }

    private void UpdateInputState()
    {
        var isAddress = ByAddressRadio.IsChecked == true;
        AddressText.IsEnabled = isAddress;
        ValueTypeBox.IsEnabled = !isAddress;
        ValueText.IsEnabled = !isAddress;
    }

    private void Cancel_OnClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private void Apply_OnClick(object sender, RoutedEventArgs e)
    {
        if (ByAddressRadio.IsChecked == true)
        {
            if (!TryParseAddress(AddressText.Text, out var address))
            {
                MessageBox.Show(this, "Invalid address.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            Request = new PointerRescanRequest
            {
                Mode = PointerRescanMode.Address,
                Address = address
            };

            DialogResult = true;
            return;
        }

        if (ValueTypeBox.SelectedItem is not MemoryDataType valueType)
        {
            MessageBox.Show(this, "Select a value data type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!ScanService.TryParseValue(valueType, ValueText.Text?.Trim() ?? string.Empty, out var parsedValue))
        {
            MessageBox.Show(this, "Invalid value for selected data type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        Request = new PointerRescanRequest
        {
            Mode = PointerRescanMode.Value,
            ValueDataType = valueType,
            Value = parsedValue,
            ValueTextRaw = ValueText.Text?.Trim() ?? string.Empty
        };

        DialogResult = true;
    }

    private static bool TryParseAddress(string? text, out ulong address)
    {
        address = 0;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var trimmed = text.Trim();
        if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed[2..];
        }

        return ulong.TryParse(trimmed, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out address)
            || ulong.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out address);
    }
}

