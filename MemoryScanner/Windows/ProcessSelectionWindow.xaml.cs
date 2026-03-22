using System.Diagnostics;
using System.Windows;

namespace MemoryScanner.Windows;

public partial class ProcessSelectionWindow : Window
{
    public Process? SelectedProcess { get; private set; }

    public ProcessSelectionWindow()
    {
        InitializeComponent();
        RefreshList();
    }

    private void RefreshList()
    {
        var items = Process.GetProcesses()
            .OrderBy(p => p.ProcessName)
            .ToList();
        ProcessGrid.ItemsSource = items;
    }

    private void Refresh_OnClick(object sender, RoutedEventArgs e)
    {
        RefreshList();
    }

    private void Select_OnClick(object sender, RoutedEventArgs e)
    {
        if (ProcessGrid.SelectedItem is Process process)
        {
            SelectedProcess = process;
            DialogResult = true;
        }
    }

    private void Cancel_OnClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private void ProcessGrid_OnMouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        Select_OnClick(sender, e);
    }
}
