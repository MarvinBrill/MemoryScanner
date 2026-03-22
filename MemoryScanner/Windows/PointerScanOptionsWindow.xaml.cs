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
        MaxOffsetText.Text = current.MaxOffset.ToString(CultureInfo.InvariantCulture);
        ThreadCountText.Text = current.ThreadCount.ToString(CultureInfo.InvariantCulture);
        UseResultLimitBox.IsChecked = current.UseResultLimit;
        ResultLimitText.Text = current.MaxResults.ToString(CultureInfo.InvariantCulture);
        IncludePrivateBox.IsChecked = current.IncludePrivate;
        IncludeMappedBox.IsChecked = current.IncludeMapped;
        IncludeImageBox.IsChecked = current.IncludeModuleImage;
        RequireStaticRootBox.IsChecked = current.RequireStaticRoot;

        AlignmentBox.SelectedIndex = current.Alignment == 8 ? 1 : 0;
        UpdateResultLimitState();
    }

    private void UseResultLimitBox_OnChanged(object sender, RoutedEventArgs e)
    {
        UpdateResultLimitState();
    }

    private void UpdateResultLimitState()
    {
        var enabled = UseResultLimitBox.IsChecked == true;
        ResultLimitText.IsEnabled = enabled;
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

        if (!int.TryParse(MaxOffsetText.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var maxOffset) || maxOffset < 0)
        {
            MessageBox.Show(this, "Max offset must be 0 or greater.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (AlignmentBox.SelectedItem is not ComboBoxItem alignmentItem
            || !int.TryParse(alignmentItem.Content?.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var alignment)
            || (alignment != 4 && alignment != 8))
        {
            MessageBox.Show(this, "Alignment must be 4 or 8.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!int.TryParse(ThreadCountText.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var threadCount) || threadCount <= 0)
        {
            MessageBox.Show(this, "Thread count must be a positive number.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
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

        SelectedOptions = new PointerScanOptions
        {
            MaxDepth = maxDepth,
            MaxOffset = maxOffset,
            Alignment = alignment,
            ThreadCount = threadCount,
            UseResultLimit = useResultLimit,
            MaxResults = maxResults,
            IncludePrivate = IncludePrivateBox.IsChecked == true,
            IncludeMapped = IncludeMappedBox.IsChecked == true,
            IncludeModuleImage = IncludeImageBox.IsChecked == true,
            RequireStaticRoot = RequireStaticRootBox.IsChecked == true
        };

        DialogResult = true;
    }
}
