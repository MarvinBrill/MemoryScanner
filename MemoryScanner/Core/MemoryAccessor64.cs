using MemoryScanner.Models;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace MemoryScanner.Core;

public interface IMemoryAccessor
{
    Process Process { get; }
    IReadOnlyList<ModuleRange> Modules { get; }
    bool IsAttached { get; }
    bool TryAttach(Process process, out string error);
    void Detach();
    bool TryReadBytes(ulong address, int count, out byte[] data);
    bool TryReadBytes(ulong address, byte[] buffer, int count, out int bytesRead);
    bool TryReadValue(ulong address, MemoryDataType dataType, out object value, int stringByteLength = 0);
    bool TryWriteValue(ulong address, MemoryDataType dataType, object value, int stringByteLength = 0);
    bool TryResolveWatchAddress(WatchEntry entry, out ulong finalAddress, out string displayAddress);
    string FormatAddress(ulong address);
}

public sealed class MemoryAccessor64 : IMemoryAccessor
{
    private const int DefaultStringByteLength = 64;
    private const int MinStringByteLength = 1;
    private const int MaxStringByteLength = 4096;

    private MemoryHelper64? _helper;
    private Process? _process;
    private List<ModuleRange> _modules = new();

    public Process Process => _process ?? throw new InvalidOperationException("No process attached.");
    public IReadOnlyList<ModuleRange> Modules => _modules;
    public bool IsAttached => _helper is not null && _process is not null && !_process.HasExited;

    public bool TryAttach(Process process, out string error)
    {
        error = string.Empty;
        try
        {
            if (!Environment.Is64BitProcess)
            {
                error = "MemoryScanner must run as x64.";
                return false;
            }

            if (process.HasExited)
            {
                error = "Process already exited.";
                return false;
            }

            if (!Environment.Is64BitOperatingSystem)
            {
                error = "64-bit operating system is required.";
                return false;
            }

            _ = process.MainModule?.BaseAddress;
            _process = process;
            _helper = new MemoryHelper64(process);
            _modules = LoadModules(process);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    public void Detach()
    {
        try { _helper?.Close(); } catch { }
        _helper = null;
        _process = null;
        _modules = new();
    }

    public bool TryReadBytes(ulong address, int count, out byte[] data)
    {
        data = Array.Empty<byte>();
        if (_helper is null || count <= 0)
        {
            return false;
        }

        try
        {
            data = new byte[count];
            if (!_helper.TryReadMemoryBytes(address, data, count, out var bytesRead) || bytesRead < count)
            {
                data = Array.Empty<byte>();
                return false;
            }

            return true;
        }
        catch
        {
            data = Array.Empty<byte>();
            return false;
        }
    }

    public bool TryReadBytes(ulong address, byte[] buffer, int count, out int bytesRead)
    {
        bytesRead = 0;
        if (_helper is null || buffer.Length == 0 || count <= 0)
        {
            return false;
        }

        try
        {
            return _helper.TryReadMemoryBytes(address, buffer, count, out bytesRead);
        }
        catch
        {
            bytesRead = 0;
            return false;
        }
    }
    public bool TryReadValue(ulong address, MemoryDataType dataType, out object value, int stringByteLength = 0)
    {
        value = 0;
        if (_helper is null) return false;

        try
        {
            if (dataType == MemoryDataType.String)
            {
                return TryReadStringValue(address, stringByteLength, out value);
            }

            value = dataType switch
            {
                MemoryDataType.Byte => _helper.ReadMemory<byte>(address),
                MemoryDataType.Int16 => _helper.ReadMemory<short>(address),
                MemoryDataType.Int32 => _helper.ReadMemory<int>(address),
                MemoryDataType.Int64 => _helper.ReadMemory<long>(address),
                MemoryDataType.Float => _helper.ReadMemory<float>(address),
                MemoryDataType.Double => _helper.ReadMemory<double>(address),
                _ => 0
            };
            return true;
        }
        catch
        {
            return false;
        }
    }

    public bool TryWriteValue(ulong address, MemoryDataType dataType, object value, int stringByteLength = 0)
    {
        if (_helper is null) return false;

        try
        {
            if (dataType == MemoryDataType.String)
            {
                return TryWriteStringValue(address, Convert.ToString(value) ?? string.Empty, stringByteLength);
            }

            return dataType switch
            {
                MemoryDataType.Byte => _helper.WriteMemory(address, Convert.ToByte(value)),
                MemoryDataType.Int16 => _helper.WriteMemory(address, Convert.ToInt16(value)),
                MemoryDataType.Int32 => _helper.WriteMemory(address, Convert.ToInt32(value)),
                MemoryDataType.Int64 => _helper.WriteMemory(address, Convert.ToInt64(value)),
                MemoryDataType.Float => _helper.WriteMemory(address, Convert.ToSingle(value)),
                MemoryDataType.Double => _helper.WriteMemory(address, Convert.ToDouble(value)),
                _ => false
            };
        }
        catch
        {
            return false;
        }
    }

    public bool TryResolveWatchAddress(WatchEntry entry, out ulong finalAddress, out string displayAddress)
    {
        finalAddress = 0;
        displayAddress = string.Empty;
        if (_helper is null) return false;

        try
        {
            if (entry.Kind == WatchEntryKind.DirectAddress)
            {
                var resolvedAddress = entry.DirectAddress;
                if (!string.IsNullOrWhiteSpace(entry.PointerBaseModuleName))
                {
                    var moduleByName = _modules.FirstOrDefault(m => string.Equals(m.Name, entry.PointerBaseModuleName, StringComparison.OrdinalIgnoreCase));
                    if (moduleByName is not null)
                    {
                        resolvedAddress = moduleByName.Base + entry.PointerBaseModuleOffset;
                    }
                }

                finalAddress = resolvedAddress;
                displayAddress = FormatAddress(finalAddress);
                return true;
            }

            var pointerBaseAddress = entry.PointerBaseAddress;
            if (!string.IsNullOrWhiteSpace(entry.PointerBaseModuleName))
            {
                var moduleByName = _modules.FirstOrDefault(m => string.Equals(m.Name, entry.PointerBaseModuleName, StringComparison.OrdinalIgnoreCase));
                if (moduleByName is not null)
                {
                    pointerBaseAddress = moduleByName.Base + entry.PointerBaseModuleOffset;
                }
            }

            var offsets = entry.Offsets.ToArray();

            // Pointer-chain with no offsets is effectively a static base address target.
            if (offsets.Length == 0)
            {
                finalAddress = pointerBaseAddress;
                displayAddress = FormatAddress(pointerBaseAddress);
                return true;
            }

            if (!TryResolvePointerChainAddress(pointerBaseAddress, offsets, entry.PointerSizeBytes, out var resolved))
            {
                return false;
            }

            finalAddress = resolved;

            // When attached, always prefer process-relative/module-resolved formatting.
            var baseText = FormatAddress(pointerBaseAddress);

            var offsetText = string.Join(",", offsets.Select(FormatOffset));
            displayAddress = $"{baseText} [{offsetText}] -> {FormatAddress(finalAddress)}";
            return true;
        }
        catch
        {
            return false;
        }
    }

    private bool TryResolvePointerChainAddress(ulong baseAddress, int[] offsets, int pointerSizeBytesHint, out ulong resolvedAddress)
    {
        resolvedAddress = baseAddress;
        if (_helper is null)
        {
            return false;
        }

        var pointerSizeBytes = ResolvePointerSizeBytes(pointerSizeBytesHint);
        foreach (var offset in offsets)
        {
            if (pointerSizeBytes == 4)
            {
                uint pointer = _helper.ReadMemory<uint>(resolvedAddress);
                var next = (long)pointer + offset;
                if (next < 0 || next > uint.MaxValue)
                {
                    return false;
                }

                resolvedAddress = (uint)next;
                continue;
            }

            ulong pointer64 = _helper.ReadMemory<ulong>(resolvedAddress);
            resolvedAddress = unchecked((ulong)((long)pointer64 + offset));
        }

        return true;
    }

    private int ResolvePointerSizeBytes(int pointerSizeBytesHint)
    {
        if (pointerSizeBytesHint == 4 || pointerSizeBytesHint == 8)
        {
            return pointerSizeBytesHint;
        }

        return IsWow64Process(Process.Handle, out var wow64) && wow64 ? 4 : 8;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr processHandle, out bool wow64Process);
    public string FormatAddress(ulong address)
    {
        var module = _modules.FirstOrDefault(m => m.Contains(address));
        if (module is null)
        {
            return $"0x{address:X}";
        }

        var offset = address - module.Base;
        var processName = _process?.ProcessName ?? "Process";
        return $"{processName}+0x{offset:X}";
    }

    private static string FormatOffset(int offset)
    {
        return offset < 0 ? "-0x" + Math.Abs(offset).ToString("X") : "0x" + offset.ToString("X");
    }

    private bool TryReadStringValue(ulong address, int requestedLength, out object value)
    {
        value = string.Empty;
        if (_helper is null)
        {
            return false;
        }

        var length = NormalizeStringByteLength(requestedLength);
        var buffer = new byte[length];
        if (!_helper.TryReadMemoryBytes(address, buffer, length, out var bytesRead) || bytesRead <= 0)
        {
            return false;
        }

        value = DecodeStringBytes(buffer.AsSpan(0, bytesRead));
        return true;
    }

    private bool TryWriteStringValue(ulong address, string text, int requestedLength)
    {
        if (_helper is null)
        {
            return false;
        }

        var payload = Encoding.UTF8.GetBytes(text);
        byte[] bytesToWrite;

        if (requestedLength > 0)
        {
            var length = NormalizeStringByteLength(requestedLength);
            bytesToWrite = new byte[length];
            if (length > 1)
            {
                var copyCount = Math.Min(length - 1, payload.Length);
                Array.Copy(payload, bytesToWrite, copyCount);
            }
        }
        else
        {
            bytesToWrite = new byte[payload.Length + 1];
            if (payload.Length > 0)
            {
                Array.Copy(payload, bytesToWrite, payload.Length);
            }
        }

        return _helper.TryWriteMemoryBytes(address, bytesToWrite, bytesToWrite.Length, out var bytesWritten)
            && bytesWritten == bytesToWrite.Length;
    }

    private static int NormalizeStringByteLength(int requestedLength)
    {
        if (requestedLength <= 0)
        {
            return DefaultStringByteLength;
        }

        return Math.Clamp(requestedLength, MinStringByteLength, MaxStringByteLength);
    }

    private static string DecodeStringBytes(ReadOnlySpan<byte> bytes)
    {
        var terminatorIndex = bytes.IndexOf((byte)0);
        var content = terminatorIndex >= 0
            ? bytes[..terminatorIndex]
            : bytes;

        if (content.Length == 0)
        {
            return string.Empty;
        }

        return Encoding.UTF8.GetString(content);
    }

    private static List<ModuleRange> LoadModules(Process process)
    {
        var modules = new List<ModuleRange>();
        foreach (ProcessModule module in process.Modules)
        {
            var baseAddress = (ulong)module.BaseAddress.ToInt64();
            var end = baseAddress + (ulong)module.ModuleMemorySize;
            modules.Add(new ModuleRange
            {
                Name = module.ModuleName,
                Base = baseAddress,
                End = end
            });
        }

        return modules;
    }
}


















