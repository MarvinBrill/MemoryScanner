namespace MemoryScanner.Core;

internal static class RefreshBatchSizer
{
    public static int Compute(int totalCount, int minBatchSize, int maxBatchSize)
    {
        if (totalCount <= 0)
        {
            return 0;
        }

        var scaled = totalCount / 20;
        return Math.Clamp(scaled, minBatchSize, maxBatchSize);
    }
}
