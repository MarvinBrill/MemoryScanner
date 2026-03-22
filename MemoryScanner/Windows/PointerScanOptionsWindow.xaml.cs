using MemoryScanner.Models;
using System.Windows;

namespace MemoryScanner.Windows;

public partial class PointerScanOptionsWindow : Window
{
    public PointerScanOptions? SelectedOptions { get; private set; }

    public PointerScanOptionsWindow(PointerScanOptions current)
    {
        InitializeComponent();
        ThreadCountText.Text = current.ThreadCount.ToString();
        ResultLimitText.Text = current.MaxResults.ToString();
    }

    private void Cancel_OnClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private void Apply_OnClick(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(ThreadCountText.Text, out var threadCount) || threadCount <= 0)
        {
            MessageBox.Show(this, "Thread count must be a positive number.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!int.TryParse(ResultLimitText.Text, out var maxResults) || maxResults <= 0)
        {
            MessageBox.Show(this, "Result limit must be a positive number.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        SelectedOptions = new PointerScanOptions
        {
            ThreadCount = threadCount,
            MaxResults = maxResults
        };

        DialogResult = true;
    }
}
