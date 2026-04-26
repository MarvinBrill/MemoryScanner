using System.ComponentModel;
using System.Globalization;
using System.Windows;

namespace MemoryScanner.Windows;

public partial class PointerSaveProgressWindow : Window
{
    private bool _allowClose;

    public PointerSaveProgressWindow()
    {
        InitializeComponent();
    }

    public void UpdateProgress(double percent, string stage, string detail)
    {
        SaveProgressBar.Value = Math.Clamp(percent, 0, 100);
        StageText.Text = string.IsNullOrWhiteSpace(stage) ? "Saving..." : stage;
        DetailText.Text = string.IsNullOrWhiteSpace(detail)
            ? $"Progress {SaveProgressBar.Value.ToString("0.0", CultureInfo.InvariantCulture)}%"
            : detail;
    }

    public void CloseSafely()
    {
        _allowClose = true;
        Close();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_allowClose)
        {
            e.Cancel = true;
            return;
        }

        base.OnClosing(e);
    }
}
