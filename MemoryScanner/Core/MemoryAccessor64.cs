using MemoryScanner.Models;
using System.Diagnostics;

namespace MemoryScanner.Core;

public interface IMemoryAccessor
{
    Process Process { get; }
    IReadOnlyList<ModuleRange> Modules { get; }
    bool IsAttached { get; }
    bool TryAttach(Process process, out string error);
    void Detach();
    bool TryReadBytes(ulong address, int count, out byte[] data);
    bool TryReadValue(ulong address, MemoryDataType dataType, out object value);
    bool TryWriteValue(ulong address, MemoryDataType dataType, object value);
    bool TryResolveWatchAddress(WatchEntry entry, out ulong finalAddress, out string displayAddress);
    string FormatAddress(ulong address);
}

public sealed class MemoryAccessor64 : IMemoryAccessor
{
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
            data = _helper.ReadMemoryBytes(address, count);
            return data.Length == count;
        }
        catch
        {
            return false;
        }
    }

    public bool TryReadValue(ulong address, MemoryDataType dataType, out object value)
    {
        value = 0;
        if (_helper is null) return false;

        try
        {
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

    public bool TryWriteValue(ulong address, MemoryDataType dataType, object value)
    {
        if (_helper is null) return false;

        try
        {
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

            var resolved = MemoryUtils.OffsetCalculator(_helper, pointerBaseAddress, offsets);
            finalAddress = resolved;

            // When attached, always prefer process-relative/module-resolved formatting.
            var baseText = FormatAddress(pointerBaseAddress);

            var offsetText = string.Join(",", offsets.Select(o => $"0x{o:X}"));
            displayAddress = $"{baseText} [{offsetText}] -> {FormatAddress(finalAddress)}";
            return true;
        }
        catch
        {
            return false;
        }
    }

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









