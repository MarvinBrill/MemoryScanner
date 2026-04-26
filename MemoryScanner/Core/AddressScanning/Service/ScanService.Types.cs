using MemoryScanner.Models;
using System.IO;

namespace MemoryScanner.Core;

public sealed partial class ScanService
{
    private readonly record struct ScanCandidate(ulong Address, ulong RawValue, MemoryDataType ValueType);

    private sealed class LocalCollector
    {
        public List<ScanResult> Results { get; } = new(CandidateFlushBatchSize);
        public List<ScanCandidate> Candidates { get; } = new(CandidateFlushBatchSize);
        public long ProcessedCount { get; set; }

        public void AddMatch(ulong address, object value, MemoryDataType type, bool includeResults, int stringByteLength = 0)
        {
            if (includeResults)
            {
                Results.Add(new ScanResult
                {
                    Address = address,
                    DataType = type,
                    StringByteLength = type == MemoryDataType.String ? Math.Max(1, stringByteLength) : 0,
                    ValueText = FormatValue(value)
                });
            }

            var candidateRawValue = type == MemoryDataType.String
                ? (ulong)Math.Max(1, stringByteLength)
                : PackCandidateValue(value, type);

            Candidates.Add(new ScanCandidate(address, candidateRawValue, type));
        }
    }

    private sealed class CandidateSnapshotWriter : IDisposable
    {
        public const int RecordSize = sizeof(ulong) + sizeof(ulong) + sizeof(byte);

        private readonly FileStream _stream;
        private readonly BinaryWriter _writer;
        private bool _committed;

        public string FilePath { get; }
        public int Count { get; private set; }

        private CandidateSnapshotWriter(string filePath)
        {
            FilePath = filePath;
            _stream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None, 256 * 1024, FileOptions.SequentialScan);
            _writer = new BinaryWriter(_stream);
        }

        public static CandidateSnapshotWriter Create()
        {
            var path = Path.Combine(Path.GetTempPath(), $"MemoryScanner_scan_{Guid.NewGuid():N}.bin");
            return new CandidateSnapshotWriter(path);
        }

        public void Add(in ScanCandidate candidate)
        {
            _writer.Write(candidate.Address);
            _writer.Write(candidate.RawValue);
            _writer.Write((byte)candidate.ValueType);
            Count++;
        }

        public void AddRange(List<ScanCandidate> candidates, int count)
        {
            for (int i = 0; i < count; i++)
            {
                Add(candidates[i]);
            }
        }

        public SnapshotCommit Commit()
        {
            _writer.Flush();
            _stream.Flush(true);
            _committed = true;
            return new SnapshotCommit(FilePath, Count);
        }

        public void Dispose()
        {
            _writer.Dispose();
            _stream.Dispose();

            if (!_committed)
            {
                TryDeleteFile(FilePath);
            }
        }
    }

    private readonly record struct SnapshotCommit(string FilePath, int Count);

    private readonly record struct ScanSlice(ulong Start, ulong End);
}
