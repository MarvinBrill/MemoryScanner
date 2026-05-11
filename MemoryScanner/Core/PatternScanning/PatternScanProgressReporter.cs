using MemoryScanner.Models;
using System.Diagnostics;

namespace MemoryScanner.Core;

internal static class PatternScanProgressReporter
{
    internal static void TryReportProgressThrottled(
        IProgress<ScanProgressInfo>? progress,
        object gate,
        ref long lastReportTicks,
        long processed,
        long total,
        string status)
    {
        var now = Stopwatch.GetTimestamp();
        var minDelta = Stopwatch.Frequency / 20;

        lock (gate)
        {
            if (lastReportTicks != 0 && now - lastReportTicks < minDelta)
            {
                return;
            }

            lastReportTicks = now;
        }

        progress?.Report(new ScanProgressInfo
        {
            Processed = processed,
            Total = total,
            StatusText = status
        });
    }
}
