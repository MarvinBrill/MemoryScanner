using MemoryScanner.Core;
using MemoryScanner.Models;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;

namespace MemoryScanner.Windows;

public partial class PointerScanOptionsWindow : Window
{
    private readonly PointerScanOptions _current;

    public PointerScanOptions? SelectedOptions { get; private set; }

    public PointerScanOptionsWindow(PointerScanOptions current)
    {
        InitializeComponent();
        _current = current;

        MaxDepthText.Text = current.MaxDepth.ToString(CultureInfo.InvariantCulture);
        MaxOffsetBox.Text = current.MaxOffset.ToString(CultureInfo.InvariantCulture);
        ThreadCountText.Text = current.ThreadCount.ToString(CultureInfo.InvariantCulture);
        UseResultLimitBox.IsChecked = current.UseResultLimit;
        ResultLimitText.Text = current.MaxResults.ToString(CultureInfo.InvariantCulture);

        IncludePrivateBox.IsChecked = current.IncludePrivate;
        IncludeMappedBox.IsChecked = current.IncludeMapped;
        IncludeImageBox.IsChecked = current.IncludeModuleImage;
        RequireStaticRootBox.IsChecked = current.RequireStaticRoot;
        ExcludeReadOnlyNodesBox.IsChecked = current.ExcludeReadOnlyNodes;
        NoLoopingPointersBox.IsChecked = current.NoLoopingPointers;
        StopTraversingAfterStaticRootBox.IsChecked = current.StopTraversingAfterStaticRoot;
        AggressiveNodeDeduplicationBox.IsChecked = current.AggressiveNodeDeduplication;
        AllowNegativeOffsetsBox.IsChecked = current.AllowNegativeOffsets;

        UseAddressRangeBox.IsChecked = current.UseAddressRange;
        AddressRangeFromText.Text = $"0x{current.AddressRangeFrom:X}";
        AddressRangeToText.Text = $"0x{current.AddressRangeTo:X}";
        RequireRootInRangeBox.IsChecked = current.RequireRootInAddressRange;
        RequireAllNodesInRangeBox.IsChecked = current.RequireAllNodesInAddressRange;

        AlignmentBox.Text = Math.Max(1, current.Alignment).ToString(CultureInfo.InvariantCulture);
        PointerWidthModeBox.SelectedIndex = current.PointerWidthMode switch
        {
            PointerValueWidthMode.Force32Bit => 1,
            PointerValueWidthMode.Force64Bit => 2,
            _ => 0
        };

        UpdateResultLimitState();
        UpdateRangeState();
    }

    private void UseResultLimitBox_OnChanged(object sender, RoutedEventArgs e)
    {
        UpdateResultLimitState();
    }

    private void UseAddressRangeBox_OnChanged(object sender, RoutedEventArgs e)
    {
        UpdateRangeState();
    }

    private void UpdateResultLimitState()
    {
        var enabled = UseResultLimitBox.IsChecked == true;
        ResultLimitText.IsEnabled = enabled;
    }

    private void UpdateRangeState()
    {
        var enabled = UseAddressRangeBox.IsChecked == true;
        AddressRangeFromText.IsEnabled = enabled;
        AddressRangeToText.IsEnabled = enabled;
        RequireRootInRangeBox.IsEnabled = enabled;
        RequireAllNodesInRangeBox.IsEnabled = enabled;
    }

    private void Cancel_OnClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private void Apply_OnClick(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(MaxDepthText.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var maxDepth) || maxDepth < 1 || maxDepth > 8)
        {
            MessageBox.Show(this, "Max depth must be between 1 and 8.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!int.TryParse(MaxOffsetBox.Text?.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var maxOffset) || maxOffset < 0)
        {
            MessageBox.Show(this, "Max offset must be 0 or greater.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!int.TryParse(AlignmentBox.Text?.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var alignment)
            || alignment <= 0)
        {
            MessageBox.Show(this, "Alignment must be a positive integer (e.g. 1, 2, 4, 8).", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!int.TryParse(ThreadCountText.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var threadCount) || threadCount <= 0)
        {
            MessageBox.Show(this, "Thread count must be a positive number.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var pointerWidthMode = PointerValueWidthMode.Auto;
        if (PointerWidthModeBox.SelectedItem is ComboBoxItem pointerWidthItem)
        {
            pointerWidthMode = pointerWidthItem.Tag?.ToString() switch
            {
                "Force32Bit" => PointerValueWidthMode.Force32Bit,
                "Force64Bit" => PointerValueWidthMode.Force64Bit,
                _ => PointerValueWidthMode.Auto
            };
        }

        var useResultLimit = UseResultLimitBox.IsChecked == true;
        var maxResults = _current.NormalizedResultLimit();
        if (useResultLimit)
        {
            if (!int.TryParse(ResultLimitText.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out maxResults) || maxResults <= 0)
            {
                MessageBox.Show(this, "Result limit must be a positive number.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }

        var useAddressRange = UseAddressRangeBox.IsChecked == true;
        var rangeFrom = _current.AddressRangeFrom;
        var rangeTo = _current.AddressRangeTo;
        var requireRootInRange = false;
        var requireAllNodesInRange = false;

        if (useAddressRange)
        {
            if (!AddressParser.TryParseAddress(AddressRangeFromText.Text, out rangeFrom))
            {
                MessageBox.Show(this, "Range From is invalid.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!AddressParser.TryParseAddress(AddressRangeToText.Text, out rangeTo))
            {
                MessageBox.Show(this, "Range To is invalid.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            requireRootInRange = RequireRootInRangeBox.IsChecked == true;
            requireAllNodesInRange = RequireAllNodesInRangeBox.IsChecked == true;
        }

        SelectedOptions = new PointerScanOptions
        {
            MaxDepth = maxDepth,
            MaxOffset = maxOffset,
            Alignment = alignment,
            PointerWidthMode = pointerWidthMode,
            ThreadCount = threadCount,
            UseResultLimit = useResultLimit,
            MaxResults = maxResults,
            IncludePrivate = IncludePrivateBox.IsChecked == true,
            IncludeMapped = IncludeMappedBox.IsChecked == true,
            IncludeModuleImage = IncludeImageBox.IsChecked == true,
            RequireStaticRoot = RequireStaticRootBox.IsChecked == true,
            ExcludeReadOnlyNodes = ExcludeReadOnlyNodesBox.IsChecked == true,
            NoLoopingPointers = NoLoopingPointersBox.IsChecked != false,
            StopTraversingAfterStaticRoot = StopTraversingAfterStaticRootBox.IsChecked == true,
            AggressiveNodeDeduplication = AggressiveNodeDeduplicationBox.IsChecked != false,
            AllowNegativeOffsets = AllowNegativeOffsetsBox.IsChecked == true,
            UseAddressRange = useAddressRange,
            AddressRangeFrom = rangeFrom,
            AddressRangeTo = rangeTo,
            RequireRootInAddressRange = requireRootInRange,
            RequireAllNodesInAddressRange = requireAllNodesInRange
        };

        DialogResult = true;
    }
}

