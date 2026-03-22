using System.Globalization;
using System.Windows;
using System.Windows.Controls;

namespace MemoryScanner.Windows;

public partial class PointerScanPresetWindow : Window
{
    public int MaxDepth { get; private set; }
    public int MaxOffset { get; private set; }
    public int Alignment { get; private set; }

    public PointerScanPresetWindow(int maxDepth, int maxOffset, int alignment)
    {
        InitializeComponent();

        MaxDepth = maxDepth;
        MaxOffset = maxOffset;
        Alignment = alignment;

        DepthText.Text = MaxDepth.ToString(CultureInfo.InvariantCulture);
        OffsetText.Text = MaxOffset.ToString(CultureInfo.InvariantCulture);
        AlignmentBox.SelectedIndex = alignment == 8 ? 1 : 0;
    }

    private void Apply_OnClick(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(DepthText.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var depth) || depth < 1 || depth > 8)
        {
            MessageBox.Show(this, "Max depth must be between 1 and 8.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!int.TryParse(OffsetText.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var maxOffset) || maxOffset < 0)
        {
            MessageBox.Show(this, "Max offset must be 0 or greater.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (AlignmentBox.SelectedItem is not ComboBoxItem selectedItem
            || !int.TryParse(selectedItem.Content?.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var alignment)
            || (alignment != 4 && alignment != 8))
        {
            MessageBox.Show(this, "Alignment must be 4 or 8.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        MaxDepth = depth;
        MaxOffset = maxOffset;
        Alignment = alignment;
        DialogResult = true;
    }
}
