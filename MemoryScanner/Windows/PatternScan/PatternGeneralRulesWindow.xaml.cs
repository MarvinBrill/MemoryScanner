using MemoryScanner.Models;
using System.Windows;

namespace MemoryScanner.Windows;

public partial class PatternGeneralRulesWindow : Window
{
    private sealed class SearchOrderOption
    {
        public SearchOrderOption(PatternSearchOrder value, string label)
        {
            Value = value;
            Label = label;
        }

        public PatternSearchOrder Value { get; }
        public string Label { get; }

        public override string ToString()
        {
            return Label;
        }
    }

    private sealed class SearchFocusOption
    {
        public SearchFocusOption(PatternSearchFocus value, string label)
        {
            Value = value;
            Label = label;
        }

        public PatternSearchFocus Value { get; }
        public string Label { get; }

        public override string ToString()
        {
            return Label;
        }
    }

    public PatternGeneralRuleOptions? SelectedOptions { get; private set; }

    public PatternGeneralRulesWindow(PatternGeneralRuleOptions currentOptions)
    {
        InitializeComponent();

        var searchOrders = new[]
        {
            new SearchOrderOption(PatternSearchOrder.StartToEnd, "Start to End"),
            new SearchOrderOption(PatternSearchOrder.MiddleToOutside, "Middle to Outside"),
            new SearchOrderOption(PatternSearchOrder.EndToStart, "End to Start"),
            new SearchOrderOption(PatternSearchOrder.CustomPercentToOutside, "Custom Percent to Outside")
        };
        var searchFocuses = new[]
        {
            new SearchFocusOption(PatternSearchFocus.Coarse, "Coarse"),
            new SearchFocusOption(PatternSearchFocus.Balanced, "Balanced"),
            new SearchFocusOption(PatternSearchFocus.Fine, "Fine")
        };
        SearchOrderBox.ItemsSource = searchOrders;
        SearchOrderBox.SelectedItem = searchOrders.FirstOrDefault(x => x.Value == currentOptions.SearchOrder) ?? searchOrders[0];
        SearchFocusBox.ItemsSource = searchFocuses;
        SearchFocusBox.SelectedItem = searchFocuses.FirstOrDefault(x => x.Value == currentOptions.SearchFocus) ?? searchFocuses[1];
        CustomStartPercentText.Text = currentOptions.CustomSearchStartPercent.ToString();
        StopAfterGapBox.IsChecked = currentOptions.StopAfterGapFromLastMatchEnabled;
        GapAddressesText.Text = currentOptions.MaxAddressesWithoutMatchAfterFirstHit.ToString();
        UpdateUiState();
    }

    private void SearchOrderBox_OnSelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        UpdateUiState();
    }

    private void StopAfterGapBox_OnCheckedChanged(object sender, RoutedEventArgs e)
    {
        UpdateUiState();
    }

    private void UpdateUiState()
    {
        var searchOrder = (SearchOrderBox.SelectedItem as SearchOrderOption)?.Value ?? PatternSearchOrder.StartToEnd;
        CustomStartPercentText.IsEnabled = searchOrder == PatternSearchOrder.CustomPercentToOutside;
        var enabled = StopAfterGapBox.IsChecked == true;
        GapAddressesText.IsEnabled = enabled;
    }

    private void Cancel_OnClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private void Apply_OnClick(object sender, RoutedEventArgs e)
    {
        if (SearchOrderBox.SelectedItem is not SearchOrderOption searchOrder)
        {
            MessageBox.Show(this, "Select a valid search order.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (SearchFocusBox.SelectedItem is not SearchFocusOption searchFocus)
        {
            MessageBox.Show(this, "Select a valid search focus.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var customStartPercent = 50;
        if (searchOrder.Value == PatternSearchOrder.CustomPercentToOutside)
        {
            if (!int.TryParse(CustomStartPercentText.Text, out customStartPercent) || customStartPercent < 0 || customStartPercent > 100)
            {
                MessageBox.Show(this, "Custom start percent must be a whole number between 0 and 100.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }

        var useStopAfterGap = StopAfterGapBox.IsChecked == true;
        var gapAddresses = 10000;
        if (useStopAfterGap)
        {
            if (!int.TryParse(GapAddressesText.Text, out gapAddresses) || gapAddresses <= 0)
            {
                MessageBox.Show(this, "Gap after last match must be a positive number.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }

        SelectedOptions = new PatternGeneralRuleOptions
        {
            SearchOrder = searchOrder.Value,
            SearchFocus = searchFocus.Value,
            CustomSearchStartPercent = customStartPercent,
            StopAfterGapFromLastMatchEnabled = useStopAfterGap,
            MaxAddressesWithoutMatchAfterFirstHit = gapAddresses
        };

        DialogResult = true;
    }
}
