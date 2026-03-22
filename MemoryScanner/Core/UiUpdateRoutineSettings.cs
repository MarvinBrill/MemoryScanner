namespace MemoryScanner.Core;

public static class UiUpdateRoutineSettings
{
    public const int DefaultIntervalMs = 500;

    private static int _valueRefreshIntervalMs = DefaultIntervalMs;

    public static event EventHandler<int>? ValueRefreshIntervalChanged;

    public static int ValueRefreshIntervalMs => Volatile.Read(ref _valueRefreshIntervalMs);

    public static bool TrySetValueRefreshInterval(int milliseconds)
    {
        if (milliseconds < 1)
        {
            return false;
        }

        var previous = Interlocked.Exchange(ref _valueRefreshIntervalMs, milliseconds);
        if (previous != milliseconds)
        {
            ValueRefreshIntervalChanged?.Invoke(null, milliseconds);
        }

        return true;
    }
}