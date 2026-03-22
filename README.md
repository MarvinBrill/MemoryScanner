# MemoryScanner

MemoryScanner is a Windows x64 desktop tool for live process memory workflows.
It is designed as a lightweight alternative to Cheat Engine for quickly scanning memory, reading/writing values, pointer scanning, and viewing memory regions.

## Author Note

This project was developed fully with Codex.
I (the creator) needed a fast alternative to Cheat Engine for memory scanning tasks, so this tool was built to cover that workflow quickly.

## Current Capabilities

- Attach to a running process and work with module/process-relative addresses.
- Read and write live memory values for:
  - `Byte`
  - `Int32`
  - `Int64`
  - `Float`
  - `Double`
- Maintain a watch list with:
  - direct addresses
  - pointer chains
  - auto-refresh
  - freeze support (periodic write-back)
- Run memory scans with:
  - first scan
  - next scan refinement
  - progress + cancel support
  - pagination for large result sets
- Supported scan comparisons:
  - first scan: `Equal`, `NotEqual`, `Greater`, `Less`
  - next scan additionally supports: `Increased`, `Decreased`, `Changed`, `Unchanged`
- Pointer scanner with:
  - configurable depth/offset/alignment preset
  - thread + result limit options
  - save/load pointer scan sessions as JSON
  - "take selected" flow into pointer watch entries
- Memory region viewer around a selected address with:
  - up/down range view
  - auto-refresh or manual refresh
  - filter conditions using scan-comparison logic
  - "take selected" flow into watch entries
- Save/load watch profiles as JSON.

## Tech Stack

- .NET 8 (`net8.0-windows`)
- WPF
- C#
- x64 target (`PlatformTarget=x64`)

## Requirements

- Windows (64-bit)
- .NET 8 SDK
- Access rights to the target process (for some targets, run as Administrator)

## Build And Run

From repository root:

```powershell
dotnet run --project .\MemoryScanner\MemoryScanner.csproj
```

Build only:

```powershell
$env:DOTNET_CLI_HOME="$PWD\.dotnet-home"
dotnet build .\MemoryScanner\MemoryScanner.sln
```

## Basic Workflow

1. Start the app.
2. Click **Select Process** and attach to a target process.
3. Use **First Scan** with a data type + condition + value.
4. Use **Next Scan** to narrow down results.
5. Move interesting addresses to the watch list (`Take Selected` / `Take All`).
6. Read/write/freeze values from the watch list.
7. Optionally run **Pointer Scanner** or open **Memory Region Viewer** from a watch entry or scan result.

## Scan Depth Profiles

- `Quick`: faster, less complete
- `Balanced`: default behavior
- `Deep`: most complete, slower (includes unaligned scanning)

## Project Structure

- `MemoryScanner/MainWindow.xaml(.cs)` -> main UI and scan/watch workflow
- `MemoryScanner/Core/ScanService.cs` -> first/next scan engine
- `MemoryScanner/Core/PointerScanService.cs` -> pointer scan engine
- `MemoryScanner/Core/MemoryAccessor64.cs` -> process attach, read/write, address resolve
- `MemoryScanner/Core/MemoryRegionEnumerator.cs` -> readable region enumeration
- `MemoryScanner/Core/ProfileStorageService.cs` -> watch profile save/load
- `MemoryScanner/Windows/*` -> dialog windows (process selection, options, pointer scan, memory region viewer)

## Notes / Limitations

- The project is currently focused on x64 processes.
- Some UI labels are still mixed (German/English).
- Pointer scan has an `Include Mapped` option in UI; mapped-region handling is currently not effectively applied in region filtering logic.

## Safety Disclaimer

Use this software only for processes/games/applications you are allowed to inspect or modify.
You are responsible for complying with local laws, terms of service, and anti-cheat policies.
