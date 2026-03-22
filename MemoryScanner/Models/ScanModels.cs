namespace MemoryScanner.Models;

public enum ScanDepthProfile
{
    Quick,
    Balanced,
    Deep
}

public sealed class ScanExecutionOptions
{
    public ScanDepthProfile DepthProfile { get; set; } = ScanDepthProfile.Balanced;
    public int ThreadCount { get; set; } = Math.Max(1, Environment.ProcessorCount / 2);
    public bool UseResultLimit { get; set; } = false;
    public int ResultLimit { get; set; } = 5000;

    public int NormalizedThreadCount()
    {
        if (ThreadCount <= 0)
        {
            return 1;
        }

        return Math.Min(ThreadCount, Environment.ProcessorCount);
    }

    public int NormalizedResultLimit()
    {
        if (!UseResultLimit)
        {
            return int.MaxValue;
        }

        return Math.Max(1, ResultLimit);
    }
}

public sealed class ScanProgressInfo
{
    public long Processed { get; init; }
    public long Total { get; init; }
    public string StatusText { get; init; } = string.Empty;

    public double Percent => Total <= 0 ? 0 : Math.Clamp((Processed * 100.0) / Total, 0, 100);
}
