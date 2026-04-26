using MemoryScanner.Models;
using Microsoft.Win32.SafeHandles;
using System.Buffers.Binary;
using System.IO;
using System.Runtime.InteropServices;

namespace MemoryScanner.Core;

public sealed partial class PointerScanService
{
    private interface IParentLookup : IDisposable
    {
        bool TryGetParents(ulong targetAddress, List<PointerParentCandidate> buffer);
    }

    private sealed class MemoryParentLookup : IParentLookup
    {
        private readonly MergeShard[] _mergeShards;
        private bool _disposed;

        public MemoryParentLookup(MergeShard[] mergeShards)
        {
            _mergeShards = mergeShards;
        }

        public bool TryGetParents(ulong targetAddress, List<PointerParentCandidate> buffer)
        {
            buffer.Clear();
            if (_disposed)
            {
                return false;
            }

            var shard = _mergeShards[GetMergeShardIndex(targetAddress)];
            if (!shard.ParentsByTarget.TryGetValue(targetAddress, out var parents) || parents.Count == 0)
            {
                return false;
            }

            buffer.AddRange(parents);
            return true;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            ClearParentShards(_mergeShards);
        }
    }

    private sealed class DiskParentLookup : IParentLookup
    {
        private readonly string _path;
        private readonly Dictionary<ulong, long> _indexByTarget;
        private readonly SafeFileHandle _handle;
        private readonly TempStorageGuard _tempStorageGuard;
        private readonly long _reservedBytes;
        private bool _disposed;

        public DiskParentLookup(string path, Dictionary<ulong, long> indexByTarget, long reservedBytes, TempStorageGuard tempStorageGuard)
        {
            _path = path;
            _indexByTarget = indexByTarget;
            _reservedBytes = Math.Max(0, reservedBytes);
            _tempStorageGuard = tempStorageGuard;
            _handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        }

        public bool TryGetParents(ulong targetAddress, List<PointerParentCandidate> buffer)
        {
            buffer.Clear();
            if (_disposed)
            {
                return false;
            }

            if (!_indexByTarget.TryGetValue(targetAddress, out var blockOffset))
            {
                return false;
            }

            Span<byte> header = stackalloc byte[sizeof(ulong) + sizeof(int)];
            ReadExact(_handle, header, blockOffset);
            var storedTarget = BinaryPrimitives.ReadUInt64LittleEndian(header[..sizeof(ulong)]);
            var count = BinaryPrimitives.ReadInt32LittleEndian(header.Slice(sizeof(ulong), sizeof(int)));
            if (storedTarget != targetAddress || count <= 0)
            {
                return false;
            }

            var payloadSize = checked(count * (sizeof(ulong) + sizeof(int)));
            var payload = payloadSize <= 0 ? Array.Empty<byte>() : new byte[payloadSize];
            if (payloadSize > 0)
            {
                ReadExact(_handle, payload, blockOffset + header.Length);
            }

            for (var i = 0; i < count; i++)
            {
                var baseOffset = i * (sizeof(ulong) + sizeof(int));
                var parentAddress = BinaryPrimitives.ReadUInt64LittleEndian(payload.AsSpan(baseOffset, sizeof(ulong)));
                var offset = BinaryPrimitives.ReadInt32LittleEndian(payload.AsSpan(baseOffset + sizeof(ulong), sizeof(int)));
                buffer.Add(new PointerParentCandidate(parentAddress, offset));
            }

            return buffer.Count > 0;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _indexByTarget.Clear();
            _handle.Dispose();
            _tempStorageGuard.Release(_reservedBytes);
            TryDeleteFile(_path);
        }

        private static void ReadExact(SafeFileHandle handle, Span<byte> buffer, long fileOffset)
        {
            var totalRead = 0;
            while (totalRead < buffer.Length)
            {
                var read = RandomAccess.Read(handle, buffer[totalRead..], fileOffset + totalRead);
                if (read <= 0)
                {
                    throw new EndOfStreamException("Unexpected end of temp parent lookup file.");
                }

                totalRead += read;
            }
        }
    }

    private sealed class TempStorageGuard
    {
        private const long OneGbBytes = 1024L * 1024L * 1024L;
        private const long FreeSpaceSafetyMarginBytes = 256L * 1024L * 1024L;

        private readonly bool _enabled;
        private readonly long _maxBytes;
        private long _reservedBytes;

        public TempStorageGuard(PointerScanOptions options)
        {
            _enabled = options.EnableDiskSpillToTemp;
            _maxBytes = Math.Max(1, options.MaxTempStorageGigabytes) * OneGbBytes;
        }

        public void Reserve(string tempPath, long bytes)
        {
            if (!_enabled || bytes <= 0)
            {
                return;
            }

            if (_reservedBytes > _maxBytes - bytes)
            {
                throw new TempStorageLimitExceededException($"temp storage limit ({FormatBytes(_maxBytes)}) reached");
            }

            var root = Path.GetPathRoot(tempPath);
            if (!string.IsNullOrWhiteSpace(root))
            {
                var driveInfo = new DriveInfo(root);
                var required = bytes + FreeSpaceSafetyMarginBytes;
                if (driveInfo.AvailableFreeSpace < required)
                {
                    throw new TempStorageLimitExceededException($"insufficient free temp disk space on {driveInfo.Name.TrimEnd('\\')} (need at least {FormatBytes(required)})");
                }
            }

            _reservedBytes += bytes;
        }

        public void Release(long bytes)
        {
            if (!_enabled || bytes <= 0)
            {
                return;
            }

            _reservedBytes -= bytes;
            if (_reservedBytes < 0)
            {
                _reservedBytes = 0;
            }
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes >= OneGbBytes)
            {
                return $"{bytes / (double)OneGbBytes:0.##} GB";
            }

            const long oneMbBytes = 1024L * 1024L;
            return $"{bytes / (double)oneMbBytes:0.##} MB";
        }
    }

    private sealed class TempStorageLimitExceededException : Exception
    {
        public TempStorageLimitExceededException(string message)
            : base(message)
        {
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr processHandle, out bool wow64Process);

    private sealed class ModuleLookup
    {
        private readonly ModuleRange[] _modulesByBase;
        private readonly ulong[] _bases;

        private ModuleLookup(ModuleRange[] modulesByBase)
        {
            _modulesByBase = modulesByBase;
            _bases = modulesByBase.Select(m => m.Base).ToArray();
        }

        public static ModuleLookup Create(IReadOnlyList<ModuleRange> modules)
        {
            if (modules.Count == 0)
            {
                return new ModuleLookup(Array.Empty<ModuleRange>());
            }

            var ordered = modules
                .OrderBy(m => m.Base)
                .ToArray();

            return new ModuleLookup(ordered);
        }

        public bool Contains(ulong address)
        {
            return TryFind(address, out _);
        }

        public bool TryFind(ulong address, out ModuleRange? module)
        {
            module = null;
            if (_modulesByBase.Length == 0)
            {
                return false;
            }

            var index = Array.BinarySearch(_bases, address);
            if (index >= 0)
            {
                var exact = _modulesByBase[index];
                if (exact.Contains(address))
                {
                    module = exact;
                    return true;
                }
            }

            var probe = index >= 0 ? index : (~index) - 1;
            if (probe < 0 || probe >= _modulesByBase.Length)
            {
                return false;
            }

            var candidate = _modulesByBase[probe];
            if (!candidate.Contains(address))
            {
                return false;
            }

            module = candidate;
            return true;
        }
    }

    private readonly struct PointerParentCandidate
    {
        public PointerParentCandidate(ulong parentAddress, int offset)
        {
            ParentAddress = parentAddress;
            Offset = offset;
        }

        public ulong ParentAddress { get; }
        public int Offset { get; }
    }

    private sealed class PointerChainNode
    {
        public ulong CurrentAddress { get; set; }
        public PointerChainNode? ChildNode { get; set; }
        public int OffsetToChild { get; set; }
        public int Depth { get; set; }
    }

    private sealed class LocalExpansionCollector
    {
        public List<PointerChainNode> NextFrontier { get; } = new(1024);
        public List<PointerPath> Results { get; } = new(128);
        public List<PointerParentCandidate> ParentsBuffer { get; } = new(128);
        public long PendingProgress { get; set; }
    }

    private sealed class LocalParentCollector
    {
        private byte[] _readBuffer;

        public LocalParentCollector(int initialBufferSize)
        {
            _readBuffer = new byte[Math.Max(1024, initialBufferSize)];
        }

        public Dictionary<ulong, List<PointerParentCandidate>> ParentsByTarget { get; } = new();
        public long PendingProgress { get; set; }
        public int CandidateCount { get; private set; }

        public byte[] GetReadBuffer(int requiredSize)
        {
            if (_readBuffer.Length < requiredSize)
            {
                _readBuffer = new byte[requiredSize];
            }

            return _readBuffer;
        }

        public void AddCandidate(ulong childAddress, ulong parentAddress, int offset)
        {
            ref var listRef = ref CollectionsMarshal.GetValueRefOrAddDefault(ParentsByTarget, childAddress, out var exists);
            if (!exists || listRef is null)
            {
                listRef = new List<PointerParentCandidate>(8);
            }

            listRef.Add(new PointerParentCandidate(parentAddress, offset));
            CandidateCount++;
        }

        public void ClearCandidates()
        {
            ParentsByTarget.Clear();
            CandidateCount = 0;
        }
    }

    private sealed class MergeShard
    {
        public object SyncRoot { get; } = new();
        public Dictionary<ulong, List<PointerParentCandidate>> ParentsByTarget { get; } = new();
    }

    private readonly record struct ScanSlice(ulong Start, ulong End, bool IsWritable);
}
