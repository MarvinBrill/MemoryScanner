namespace MemoryScanner.Models;

public sealed class PointerSessionSaveOptions
{
    public bool EnableGZipCompression { get; set; } = true;
    public bool CompactJson { get; set; } = true;
    public bool UseCompactSchema { get; set; } = true;

    public PointerSessionSaveOptions Clone()
    {
        return new PointerSessionSaveOptions
        {
            EnableGZipCompression = EnableGZipCompression,
            CompactJson = CompactJson,
            UseCompactSchema = UseCompactSchema
        };
    }
}
