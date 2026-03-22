using MemoryScanner.Core;
using MemoryScanner.Models;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;

namespace MemoryScanner.Windows;

public partial class AddWatchEntryWindow : Window
{
    public WatchEntry? CreatedEntry { get; private set; }

    public AddWatchEntryWindow(string? suggestedName = null, ulong? suggestedAddress = null)
    {
        InitializeComponent();
        DataTypeBox.ItemsSource = Enum.GetValues<MemoryDataType>();
        DataTypeBox.SelectedItem = MemoryDataType.Int32;
        ModeBox.SelectedIndex = 0;

        if (!string.IsNullOrWhiteSpace(suggestedName))
        {
            NameText.Text = suggestedName;
        }

        if (suggestedAddress.HasValue)
        {
            AddressText.Text = $"0x{suggestedAddress.Value:X}";
        }
    }

    public AddWatchEntryWindow(PointerPath pointerPath, MemoryDataType dataType)
    {
        InitializeComponent();
        DataTypeBox.ItemsSource = Enum.GetValues<MemoryDataType>();
        DataTypeBox.SelectedItem = dataType;

        ModeBox.SelectedIndex = 1;
        NameText.Text = "PointerEntry";
        AddressText.Text = $"0x{pointerPath.BaseAddress:X}";
        OffsetsText.Text = AddressParser.OffsetsToText(pointerPath.Offsets);
        ModuleNameText.Text = pointerPath.BaseModuleName;
        ModuleOffsetText.Text = pointerPath.BaseModuleOffset == 0 ? string.Empty : $"0x{pointerPath.BaseModuleOffset:X}";
        SetModeVisibility();
    }

    private void ModeBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        SetModeVisibility();
    }

    private void SetModeVisibility()
    {
        bool pointerMode = ModeBox.SelectedIndex == 1;
        AddressLabel.Text = pointerMode ? "Pointer Base Address" : "Address";

        ModuleNameLabel.Visibility = pointerMode ? Visibility.Visible : Visibility.Collapsed;
        ModuleNameText.Visibility = pointerMode ? Visibility.Visible : Visibility.Collapsed;
        ModuleOffsetLabel.Visibility = pointerMode ? Visibility.Visible : Visibility.Collapsed;
        ModuleOffsetText.Visibility = pointerMode ? Visibility.Visible : Visibility.Collapsed;
        OffsetsLabel.Visibility = pointerMode ? Visibility.Visible : Visibility.Collapsed;
        OffsetsText.Visibility = pointerMode ? Visibility.Visible : Visibility.Collapsed;
    }

    private void Cancel_OnClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private void Add_OnClick(object sender, RoutedEventArgs e)
    {
        if (!AddressParser.TryParseAddress(AddressText.Text, out var baseAddress))
        {
            MessageBox.Show(this, "Invalid address/base address.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (DataTypeBox.SelectedItem is not MemoryDataType dataType)
        {
            MessageBox.Show(this, "Select a valid data type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var name = string.IsNullOrWhiteSpace(NameText.Text) ? "Entry" : NameText.Text.Trim();

        if (ModeBox.SelectedIndex == 0)
        {
            CreatedEntry = new WatchEntry
            {
                Name = name,
                Kind = WatchEntryKind.DirectAddress,
                DataType = dataType,
                DirectAddress = baseAddress
            };
        }
        else
        {
            if (!AddressParser.TryParseOffsets(OffsetsText.Text, out var offsets))
            {
                MessageBox.Show(this, "Invalid offsets format.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            ulong moduleOffset = 0;
            if (!string.IsNullOrWhiteSpace(ModuleOffsetText.Text) && !AddressParser.TryParseAddress(ModuleOffsetText.Text, out moduleOffset))
            {
                MessageBox.Show(this, "Invalid module offset.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            CreatedEntry = new WatchEntry
            {
                Name = name,
                Kind = WatchEntryKind.PointerChain,
                DataType = dataType,
                PointerBaseAddress = baseAddress,
                PointerBaseModuleName = ModuleNameText.Text.Trim(),
                PointerBaseModuleOffset = moduleOffset,
                Offsets = new ObservableCollection<int>(offsets)
            };
        }

        DialogResult = true;
    }
}
