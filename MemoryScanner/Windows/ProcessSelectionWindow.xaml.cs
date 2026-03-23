using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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
        var processes = Process.GetProcesses();
        var items = new List<ProcessListItem>(processes.Length);

        foreach (var process in processes)
        {
            try
            {
                items.Add(new ProcessListItem(process));
            }
            catch
            {
                // Process may exit while enumerating.
            }
        }

        ProcessGrid.ItemsSource = items
            .OrderByDescending(item => item.HasWindowTitle)
            .ThenBy(item => item.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private void Refresh_OnClick(object sender, RoutedEventArgs e)
    {
        RefreshList();
    }

    private void Select_OnClick(object sender, RoutedEventArgs e)
    {
        if (ProcessGrid.SelectedItem is ProcessListItem item)
        {
            SelectedProcess = item.Process;
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

    private sealed class ProcessListItem
    {
        public ProcessListItem(Process process)
        {
            Process = process;
            ProcessName = TryGetString(() => process.ProcessName);
            Id = TryGetInt(() => process.Id);
            MainWindowTitle = TryGetString(() => process.MainWindowTitle).Trim();
            HasWindowTitle = !string.IsNullOrWhiteSpace(MainWindowTitle);
        }

        public Process Process { get; }
        public string ProcessName { get; }
        public int Id { get; }
        public string MainWindowTitle { get; }
        public bool HasWindowTitle { get; }

        private static string TryGetString(Func<string> getter)
        {
            try
            {
                return getter() ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        private static int TryGetInt(Func<int> getter)
        {
            try
            {
                return getter();
            }
            catch
            {
                return 0;
            }
        }
    }
}
