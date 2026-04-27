using MemoryScanner.Models;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows;

namespace MemoryScanner.Windows;

public partial class PointerMetadataWindow : Window
{
    private readonly ObservableCollection<PointerMetadataStageRow> _rows = new();

    public PointerMetadataWindow(WatchEntry entry, PointerRepairMetadata metadata)
    {
        InitializeComponent();

        StageGrid.ItemsSource = _rows;

        EntryNameText.Text = string.IsNullOrWhiteSpace(entry.Name) ? "Entry" : entry.Name;
        CapturedAtText.Text = metadata.CapturedAtUtc == default
            ? "-"
            : metadata.CapturedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        SourceExpressionText.Text = string.IsNullOrWhiteSpace(metadata.SourceExpression) ? "-" : metadata.SourceExpression;
        CapturedBaseText.Text = $"0x{metadata.CapturedBaseAddress:X}";
        CapturedFinalAddressText.Text = $"0x{metadata.CapturedFinalAddress:X}";
        CapturedFinalValueText.Text = string.IsNullOrWhiteSpace(metadata.CapturedFinalValueText)
            ? "-"
            : metadata.CapturedFinalValueText;

        foreach (var stage in metadata.Stages.OrderBy(s => s.DepthIndex))
        {
            _rows.Add(new PointerMetadataStageRow
            {
                DepthIndex = stage.DepthIndex,
                ReadAddressText = $"0x{stage.ReadAddress:X}",
                PointerValueText = $"0x{stage.PointerValue:X}",
                OffsetText = FormatOffset(stage.Offset),
                ResolvedAddressText = $"0x{stage.ResolvedAddress:X}"
            });
        }
    }

    private void Close_OnClick(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private static string FormatOffset(int offset)
    {
        return offset < 0 ? $"-0x{Math.Abs(offset):X}" : $"0x{offset:X}";
    }

    private sealed class PointerMetadataStageRow
    {
        public int DepthIndex { get; init; }
        public string ReadAddressText { get; init; } = string.Empty;
        public string PointerValueText { get; init; } = string.Empty;
        public string OffsetText { get; init; } = string.Empty;
        public string ResolvedAddressText { get; init; } = string.Empty;
    }
}
