using MemoryScanner.Models;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MemoryScanner.Core;

public sealed class MemoryRegion
{
    public ulong BaseAddress { get; init; }
    public ulong RegionSize { get; init; }
    public uint State { get; init; }
    public uint Protect { get; init; }
    public uint Type { get; init; }

    public bool IsReadable => State == MEM_COMMIT && (Protect & PAGE_GUARD) == 0 && (Protect & PAGE_NOACCESS) == 0;
    public bool IsWritable => (Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_PRIVATE = 0x20000;
    public const uint MEM_MAPPED = 0x40000;
    public const uint MEM_IMAGE = 0x1000000;
    public const uint PAGE_NOACCESS = 0x01;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_WRITECOPY = 0x08;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    public const uint PAGE_GUARD = 0x100;
}

public sealed class MemoryRegionEnumerator
{
    public IReadOnlyList<MemoryRegion> Enumerate(Process process, bool includePrivate, bool includeImage, bool includeMapped = false)
    {
        var list = new List<MemoryRegion>();
        ulong current = 0;

        while (current < 0x00007FFF_FFFF_FFFF)
        {
            var mbi = new MEMORY_BASIC_INFORMATION64();
            var result = VirtualQueryEx(process.Handle, (IntPtr)current, out mbi, (IntPtr)Marshal.SizeOf<MEMORY_BASIC_INFORMATION64>());
            if (result == IntPtr.Zero)
            {
                break;
            }

            if (mbi.RegionSize == 0)
            {
                current += 0x1000;
                continue;
            }

            var region = new MemoryRegion
            {
                BaseAddress = mbi.BaseAddress,
                RegionSize = mbi.RegionSize,
                State = mbi.State,
                Protect = mbi.Protect,
                Type = mbi.Type
            };

            if (region.IsReadable)
            {
                var allowed = (includePrivate && region.Type == MemoryRegion.MEM_PRIVATE) ||
                              (includeMapped && region.Type == MemoryRegion.MEM_MAPPED) ||
                              (includeImage && region.Type == MemoryRegion.MEM_IMAGE);
                if (allowed)
                {
                    list.Add(region);
                }
            }

            ulong next = region.BaseAddress + region.RegionSize;
            if (next <= current)
            {
                break;
            }

            current = next;
        }

        return list;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION64
    {
        public ulong BaseAddress;
        public ulong AllocationBase;
        public uint AllocationProtect;
        public uint __alignment1;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
        public uint __alignment2;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualQueryEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION64 lpBuffer,
        IntPtr dwLength);
}

