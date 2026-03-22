using MemoryScanner.Models;
using System.Windows;

namespace MemoryScanner.Windows;

public partial class ScanOptionsWindow : Window
{
    public ScanExecutionOptions? SelectedOptions { get; private set; }

    public ScanOptionsWindow(ScanExecutionOptions currentOptions)
    {
        InitializeComponent();

        DepthProfileBox.ItemsSource = Enum.GetValues<ScanDepthProfile>();
        DepthProfileBox.SelectedItem = currentOptions.DepthProfile;
        ThreadCountText.Text = currentOptions.ThreadCount.ToString();
        IncludeMappedBox.IsChecked = currentOptions.IncludeMapped;

        UseResultLimitBox.IsChecked = currentOptions.UseResultLimit;
        ResultLimitText.Text = currentOptions.ResultLimit.ToString();
        UpdateResultLimitState();
    }

    private void UseResultLimitBox_OnCheckedChanged(object sender, RoutedEventArgs e)
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
        if (DepthProfileBox.SelectedItem is not ScanDepthProfile profile)
        {
            MessageBox.Show(this, "Select a valid depth profile.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!int.TryParse(ThreadCountText.Text, out var threadCount) || threadCount <= 0)
        {
            MessageBox.Show(this, "Thread count must be a positive number.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var useResultLimit = UseResultLimitBox.IsChecked == true;
        var resultLimit = 5000;
        if (useResultLimit)
        {
            if (!int.TryParse(ResultLimitText.Text, out resultLimit) || resultLimit <= 0)
            {
                MessageBox.Show(this, "Result limit must be a positive number.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }

        SelectedOptions = new ScanExecutionOptions
        {
            DepthProfile = profile,
            ThreadCount = threadCount,
            UseResultLimit = useResultLimit,
            ResultLimit = resultLimit,
            IncludeMapped = IncludeMappedBox.IsChecked == true
        };

        DialogResult = true;
    }
}
