using MemoryScanner.Models;
using System.Globalization;

namespace MemoryScanner.Core;

public static class AddressParser
{
    public static bool TryParseAddress(string? text, out ulong address)
    {
        address = 0;
        if (string.IsNullOrWhiteSpace(text)) return false;

        var value = text.Trim();
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            value = value[2..];
        }

        return ulong.TryParse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out address) ||
               ulong.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out address);
    }

    public static bool TryParseOffsets(string? text, out List<int> offsets)
    {
        offsets = new List<int>();
        if (string.IsNullOrWhiteSpace(text)) return true;

        var parts = text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var part in parts)
        {
            var raw = part;
            if (raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                raw = raw[2..];
                if (!int.TryParse(raw, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hexOffset))
                {
                    return false;
                }
                offsets.Add(hexOffset);
                continue;
            }

            if (!int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var offset))
            {
                return false;
            }

            offsets.Add(offset);
        }

        return true;
    }

    public static string OffsetsToText(IEnumerable<int> offsets)
    {
        return string.Join(", ", offsets.Select(o => $"0x{o:X}"));
    }
}
