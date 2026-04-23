using System.ComponentModel;
using System.Globalization;
using System.Windows;

namespace MemoryScanner.Windows;

public partial class PointerLoadProgressWindow : Window
{
    private bool _allowClose;

    public PointerLoadProgressWindow()
    {
        InitializeComponent();
    }

    public void UpdateProgress(double percent, string stage, string detail)
    {
        LoadProgressBar.Value = Math.Clamp(percent, 0, 100);
        StageText.Text = string.IsNullOrWhiteSpace(stage) ? "Loading..." : stage;
        DetailText.Text = string.IsNullOrWhiteSpace(detail)
            ? $"Progress {LoadProgressBar.Value.ToString("0.0", CultureInfo.InvariantCulture)}%"
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
