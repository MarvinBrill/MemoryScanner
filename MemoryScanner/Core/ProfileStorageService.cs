using MemoryScanner.Models;
using System.Text.Json;
using System.IO;

namespace MemoryScanner.Core;

public sealed class ProfileStorageService
{
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = true
    };

    public void Save(string filePath, string processName, IEnumerable<WatchEntry> entries)
    {
        var model = new WatchProfile
        {
            ProcessName = processName,
            Entries = entries.Select(ToDto).ToList()
        };

        var json = JsonSerializer.Serialize(model, _jsonOptions);
        File.WriteAllText(filePath, json);
    }

    public (string ProcessName, List<WatchEntry> Entries) Load(string filePath)
    {
        var json = File.ReadAllText(filePath);
        var profile = JsonSerializer.Deserialize<WatchProfile>(json) ?? new WatchProfile();
        return (profile.ProcessName, profile.Entries.Select(FromDto).ToList());
    }

    private static WatchEntryDto ToDto(WatchEntry entry)
    {
        return new WatchEntryDto
        {
            Id = entry.Id,
            Name = entry.Name,
            Kind = entry.Kind,
            DataType = entry.DataType,
            DirectAddress = entry.DirectAddress,
            PointerBaseAddress = entry.PointerBaseAddress,
            PointerSizeBytes = entry.PointerSizeBytes,
            PointerBaseModuleName = entry.PointerBaseModuleName,
            PointerBaseModuleOffset = entry.PointerBaseModuleOffset,
            Offsets = entry.Offsets.ToList(),
            PointerRepairMetadata = ToDto(entry.PointerRepairMetadata),
            IsFrozen = entry.IsFrozen,
            FreezeValueText = entry.FreezeValueText
        };
    }

    private static WatchEntry FromDto(WatchEntryDto dto)
    {
        return new WatchEntry
        {
            Id = dto.Id == Guid.Empty ? Guid.NewGuid() : dto.Id,
            Name = dto.Name,
            Kind = dto.Kind,
            DataType = dto.DataType,
            DirectAddress = dto.DirectAddress,
            PointerBaseAddress = dto.PointerBaseAddress,
            PointerSizeBytes = dto.PointerSizeBytes,
            PointerBaseModuleName = dto.PointerBaseModuleName,
            PointerBaseModuleOffset = dto.PointerBaseModuleOffset,
            Offsets = new System.Collections.ObjectModel.ObservableCollection<int>(dto.Offsets),
            PointerRepairMetadata = FromDto(dto.PointerRepairMetadata),
            IsFrozen = dto.IsFrozen,
            FreezeValueText = dto.FreezeValueText
        };
    }

    private static PointerRepairMetadataDto? ToDto(PointerRepairMetadata? metadata)
    {
        if (metadata is null)
        {
            return null;
        }

        return new PointerRepairMetadataDto
        {
            CapturedAtUtc = metadata.CapturedAtUtc,
            SourceExpression = metadata.SourceExpression,
            CapturedBaseAddress = metadata.CapturedBaseAddress,
            CapturedFinalAddress = metadata.CapturedFinalAddress,
            CapturedFinalValueText = metadata.CapturedFinalValueText,
            Stages = metadata.Stages.Select(stage => new PointerRepairStageSnapshotDto
            {
                DepthIndex = stage.DepthIndex,
                ReadAddress = stage.ReadAddress,
                PointerValue = stage.PointerValue,
                Offset = stage.Offset,
                ResolvedAddress = stage.ResolvedAddress
            }).ToList()
        };
    }

    private static PointerRepairMetadata? FromDto(PointerRepairMetadataDto? dto)
    {
        if (dto is null)
        {
            return null;
        }

        return new PointerRepairMetadata
        {
            CapturedAtUtc = dto.CapturedAtUtc,
            SourceExpression = dto.SourceExpression,
            CapturedBaseAddress = dto.CapturedBaseAddress,
            CapturedFinalAddress = dto.CapturedFinalAddress,
            CapturedFinalValueText = dto.CapturedFinalValueText,
            Stages = dto.Stages.Select(stage => new PointerRepairStageSnapshot
            {
                DepthIndex = stage.DepthIndex,
                ReadAddress = stage.ReadAddress,
                PointerValue = stage.PointerValue,
                Offset = stage.Offset,
                ResolvedAddress = stage.ResolvedAddress
            }).ToList()
        };
    }

    private sealed class WatchProfile
    {
        public string ProcessName { get; set; } = string.Empty;
        public List<WatchEntryDto> Entries { get; set; } = new();
    }

    private sealed class WatchEntryDto
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = "Entry";
        public WatchEntryKind Kind { get; set; }
        public MemoryDataType DataType { get; set; } = MemoryDataType.Int32;
        public ulong DirectAddress { get; set; }
        public ulong PointerBaseAddress { get; set; }
        public int PointerSizeBytes { get; set; }
        public string PointerBaseModuleName { get; set; } = string.Empty;
        public ulong PointerBaseModuleOffset { get; set; }
        public List<int> Offsets { get; set; } = new();
        public PointerRepairMetadataDto? PointerRepairMetadata { get; set; }
        public bool IsFrozen { get; set; }
        public string FreezeValueText { get; set; } = string.Empty;
    }

    private sealed class PointerRepairMetadataDto
    {
        public DateTime CapturedAtUtc { get; set; } = DateTime.UtcNow;
        public string SourceExpression { get; set; } = string.Empty;
        public ulong CapturedBaseAddress { get; set; }
        public ulong CapturedFinalAddress { get; set; }
        public string CapturedFinalValueText { get; set; } = string.Empty;
        public List<PointerRepairStageSnapshotDto> Stages { get; set; } = new();
    }

    private sealed class PointerRepairStageSnapshotDto
    {
        public int DepthIndex { get; set; }
        public ulong ReadAddress { get; set; }
        public ulong PointerValue { get; set; }
        public int Offset { get; set; }
        public ulong ResolvedAddress { get; set; }
    }
}



