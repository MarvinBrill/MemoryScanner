namespace MemoryScanner.Core;

internal static class ExceptionUtilities
{
    public static bool IsOnlyCancellation(AggregateException ex)
    {
        return ex.Flatten().InnerExceptions.All(inner => inner is OperationCanceledException);
    }
}
