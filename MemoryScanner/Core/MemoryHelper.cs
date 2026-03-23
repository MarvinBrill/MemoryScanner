using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace MemoryScanner.Core;

public class MemoryHelper32
{
    private readonly Process process;

    public MemoryHelper32(Process TargetProcess)
    {
        process = TargetProcess;
    }

    public uint GetBaseAddress(uint StartingAddress)
    {
        return (uint)process.MainModule.BaseAddress + StartingAddress;
    }

    public byte[] ReadMemoryBytes(uint MemoryAddress, uint Bytes)
    {
        byte[] data = new byte[Bytes];
        ReadProcessMemory(process.Handle, MemoryAddress, data, data.Length, out _);
        return data;
    }

    public string ReadMemoryString(uint MemoryAddress, int length)
    {
        byte[] data = new byte[length];
        ReadProcessMemory(process.Handle, MemoryAddress, data, data.Length, out _);
        string s = Encoding.Default.GetString(data);
        string result = "";
        char[] charArr = s.ToCharArray();

        for (int i = 0; i < charArr.Length - 1; i++)
        {
            if (charArr[i] != '\0' && charArr[i] != '\t') result += charArr[i];
        }

        return Regex.Match(result, "([A-Za-z0-9_./ ])+").Value;
    }

    public T ReadMemory<T>(uint MemoryAddress)
    {
        byte[] data = ReadMemoryBytes(MemoryAddress, (uint)Marshal.SizeOf(typeof(T)));

        T t;
        GCHandle PinnedStruct = GCHandle.Alloc(data, GCHandleType.Pinned);
        try { t = (T)Marshal.PtrToStructure(PinnedStruct.AddrOfPinnedObject(), typeof(T)); }
        catch (Exception ex) { throw ex; }
        finally { PinnedStruct.Free(); }

        return t;
    }

    public bool WriteMemory<T>(uint MemoryAddress, T Value)
    {
        IntPtr bw = IntPtr.Zero;

        int sz = ObjectType.GetSize<T>();
        byte[] data = ObjectType.GetBytes(Value);
        bool result = WriteProcessMemory(process.Handle, MemoryAddress, data, sz, out bw);
        return result && bw != IntPtr.Zero;
    }

    public bool WriteMemoryAsString(uint MemoryAddress, string Value)
    {
        IntPtr bw = IntPtr.Zero;

        int sz = Value.Length;
        byte[] data = Encoding.ASCII.GetBytes(Value);
        bool result = WriteProcessMemory(process.Handle, MemoryAddress, data, sz, out bw);
        return result && bw != IntPtr.Zero;
    }

    public bool WriteMemoryAsString(uint MemoryAddress, string Value, int length)
    {
        IntPtr bw = IntPtr.Zero;

        int sz = length;
        byte[] data = Encoding.ASCII.GetBytes(Value);
        bool result = WriteProcessMemory(process.Handle, MemoryAddress, data, sz, out bw);
        return result && bw != IntPtr.Zero;
    }

    public void Close()
    {
        CloseHandle(process.Handle);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr hProcess,
        uint lpBaseAddress,
        byte[] lpBuffer,
        int nSize,
        out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(
        IntPtr hProcess,
        uint lpBaseAddress,
        byte[] lpBuffer,
        int nSize,
        out IntPtr lpNumberOfBytesWritten
    );

    [DllImport("kernel32.dll")]
    private static extern int CloseHandle(IntPtr hProcess);
}

public class MemoryHelper64
{
    private readonly Process process;

    public MemoryHelper64(Process TargetProcess)
    {
        process = TargetProcess;
    }

    public ulong GetBaseAddress(ulong StartingAddress)
    {
        return (ulong)process.MainModule.BaseAddress.ToInt64() + StartingAddress;
    }

    public byte[] ReadMemoryBytes(ulong MemoryAddress, int Bytes)
    {
        byte[] data = new byte[Bytes];
        _ = TryReadMemoryBytes(MemoryAddress, data, data.Length, out _);
        return data;
    }

    public bool TryReadMemoryBytes(ulong memoryAddress, byte[] buffer, int count, out int bytesRead)
    {
        bytesRead = 0;
        if (buffer.Length == 0 || count <= 0)
        {
            return false;
        }

        if (count > buffer.Length)
        {
            count = buffer.Length;
        }

        var ok = ReadProcessMemory(process.Handle, memoryAddress, buffer, count, out var bytesReadPtr);
        bytesRead = bytesReadPtr.ToInt32();
        return bytesRead > 0;
    }

    public T ReadMemory<T>(ulong MemoryAddress)
    {
        byte[] data = ReadMemoryBytes(MemoryAddress, Marshal.SizeOf(typeof(T)));

        T t;
        GCHandle PinnedStruct = GCHandle.Alloc(data, GCHandleType.Pinned);
        try { t = (T)Marshal.PtrToStructure(PinnedStruct.AddrOfPinnedObject(), typeof(T)); }
        catch (Exception ex) { throw ex; }
        finally { PinnedStruct.Free(); }

        return t;
    }

    public bool WriteMemory<T>(ulong MemoryAddress, T Value)
    {
        IntPtr bw = IntPtr.Zero;

        int sz = ObjectType.GetSize<T>();
        byte[] data = ObjectType.GetBytes(Value);
        bool result = WriteProcessMemory(process.Handle, MemoryAddress, data, sz, out bw);
        return result && bw != IntPtr.Zero;
    }

    public void Close()
    {
        CloseHandle(process.Handle);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr hProcess,
        ulong lpBaseAddress,
        byte[] lpBuffer,
        int nSize,
        out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(
        IntPtr hProcess,
        ulong lpBaseAddress,
        byte[] lpBuffer,
        int nSize,
        out IntPtr lpNumberOfBytesWritten
    );

    [DllImport("kernel32.dll")]
    private static extern int CloseHandle(IntPtr hProcess);
}

static class MemoryUtils
{
    public static uint OffsetCalculator(MemoryHelper32 TargetMemory, uint BaseAddress, int[] Offsets)
    {
        var address = BaseAddress;
        foreach (var offset in Offsets)
        {
            var pointerValue = TargetMemory.ReadMemory<uint>(address);
            var next = (long)pointerValue + offset;
            if (next < 0 || next > uint.MaxValue)
            {
                return 0;
            }

            address = (uint)next;
        }

        return address;
    }

    public static ulong OffsetCalculator(MemoryHelper64 TargetMemory, ulong BaseAddress, int[] Offsets)
    {
        var address = BaseAddress;
        foreach (var offset in Offsets)
        {
            var pointerValue = TargetMemory.ReadMemory<ulong>(address);
            address = unchecked((ulong)((long)pointerValue + offset));
        }

        return address;
    }
}

public static class ObjectType
{
    public static int GetSize<T>()
    {
        return Marshal.SizeOf(typeof(T));
    }

    public static byte[] GetBytes<T>(T Value)
    {
        string typename = typeof(T).ToString();
        Console.WriteLine(typename);
        switch (typename)
        {
            case "System.Single":
                return BitConverter.GetBytes((float)Convert.ChangeType(Value, typeof(float)));
            case "System.Int32":
                return BitConverter.GetBytes((int)Convert.ChangeType(Value, typeof(int)));
            case "System.Int64":
                return BitConverter.GetBytes((long)Convert.ChangeType(Value, typeof(long)));
            case "System.Double":
                return BitConverter.GetBytes((double)Convert.ChangeType(Value, typeof(double)));
            case "System.Byte":
                return new[] { (byte)Convert.ChangeType(Value, typeof(byte)) };
            case "System.String":
                return Encoding.Unicode.GetBytes((string)Convert.ChangeType(Value, typeof(string)));
            default:
                return Array.Empty<byte>();
        }
    }
}







