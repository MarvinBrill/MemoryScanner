using MemoryScanner.Models;
using System.Windows;

namespace MemoryScanner.Windows;

public partial class PointerSaveOptionsWindow : Window
{
    private readonly PointerSessionSaveOptions _current;

    public PointerSessionSaveOptions? SelectedOptions { get; private set; }

    public PointerSaveOptionsWindow(PointerSessionSaveOptions current)
    {
        InitializeComponent();
        _current = current.Clone();

        EnableCompressionBox.IsChecked = _current.EnableGZipCompression;
        CompactJsonBox.IsChecked = _current.CompactJson;
        UseCompactSchemaBox.IsChecked = _current.UseCompactSchema;

        UpdateInfoText();
    }

    private void EnableCompressionBox_OnChanged(object sender, RoutedEventArgs e)
    {
        UpdateInfoText();
    }

    private void UpdateInfoText()
    {
        var compressionOn = EnableCompressionBox.IsChecked == true;
        InfoText.Text = compressionOn
            ? "Output: .json.gz (auto) when compression is enabled. Files stay loadable in MemoryScanner."
            : "Output: .json without GZip compression. Files stay loadable in MemoryScanner.";
    }

    private void Cancel_OnClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private void Apply_OnClick(object sender, RoutedEventArgs e)
    {
        SelectedOptions = new PointerSessionSaveOptions
        {
            EnableGZipCompression = EnableCompressionBox.IsChecked == true,
            CompactJson = CompactJsonBox.IsChecked == true,
            UseCompactSchema = UseCompactSchemaBox.IsChecked == true
        };

        DialogResult = true;
    }
}
