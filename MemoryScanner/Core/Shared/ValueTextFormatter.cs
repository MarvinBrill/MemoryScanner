using System.Globalization;

namespace MemoryScanner.Core;

internal static class ValueTextFormatter
{
    public static string Format(object value)
    {
        return value switch
        {
            float f => f.ToString("0.######", CultureInfo.InvariantCulture),
            double d => d.ToString("0.######", CultureInfo.InvariantCulture),
            _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty
        };
    }
}
