# MemoryScanner

MemoryScanner is a lightweight Windows memory tool built with WPF on .NET 8.
It focuses on practical live-memory workflows similar to Cheat Engine, but with a smaller scope and a clean desktop UI.

## What The Project Currently Does

MemoryScanner currently provides five major workflows:

1. Process attach and live watch list management
2. Address scanning (First Scan / Next Scan)
3. Pointer scanning and pointer result management
4. Nearby-address exploration around a selected address
5. Byte-level memory viewing and write/access tracing helpers

## Core Feature Overview

### 1) Process Selection

- Opens a process picker with `Name`, `PID`, and `Window` columns.
- Processes with a non-empty window title are sorted to the top.
- Rows with a window title are highlighted in green text.
- Attach uses native Windows process/memory APIs through `MemoryAccessor64` and `MemoryHelper64`.

### 2) Main Window: Watch List (left side)

- Add entries as:
  - direct addresses
  - pointer chains (base + offsets)
- Supported data types:
  - `Byte`
  - `Int16`
  - `Int32`
  - `Int64`
  - `Float`
  - `Double`
- Per-entry freeze checkbox (`Freeze`) for periodic write-back.
- Drag and drop reordering for watch entries.
- Double-click edit behavior by column:
  - Name -> edit name dialog
  - Address/Pointer -> edit address/pointer dialog
  - Type -> edit type dialog
  - Value -> write value dialog
- Context menu actions:
  - Edit Name
  - Edit Address/Pointer
  - Edit Data Type
  - Write Value
  - Copy Address
  - Pointer scan for this address
  - Show Nearby Addresses
  - Open Memory Viewer
  - Find out what writes/accesses this address

Address display behavior:

- Direct addresses show as absolute or process+base style when resolvable.
- Process/module-relative base entries are shown in green.
- Pointer chains with offsets are shown as `P-> <resolved dynamic address>` in green.

### 3) Main Window: Address Scan (right side)

- First scan and next scan workflow.
- Scan comparisons:
  - Direct input comparisons: `Equal`, `NotEqual`, `Greater`, `Less`
  - Delta comparisons (next scan): `Increased`, `Decreased`, `Changed`, `Unchanged`
- Scan controls:
  - First Scan
  - Next Scan
  - Reset Scan
  - Cancel Scan
  - Scan Options dialog
- During scan:
  - action buttons are enabled/disabled safely to prevent duplicate start issues
  - progress bar + status text is updated
  - cancel is supported
- Scan results grid:
  - virtualized for large result sets
  - shows `Address`, `Value`, `Raw Address`, `Type`
  - process+base style addresses are highlighted in green
  - multi-selection enabled (`SelectionMode=Extended`)
- Result actions:
  - Take Selected
  - Take All
  - Double-click row -> take to watch list
  - Context menu -> Nearby Addresses / Memory Viewer / Write-Access tracer

Current UI behavior note:

- `Take Selected` is currently enabled when more than one row is selected.

### 4) Scan Options (Address Scan)

Main scan options include:

- Scan depth profile: `Quick`, `Balanced`, `Deep`
- Thread count
- Include mapped memory regions
- Optional result limit (checkbox-controlled)

Profile behavior in code:

- `Quick`
  - scans image regions
  - skips private regions
  - aligned stepping with larger step (`typeSize * 4`)
- `Balanced`
  - scans private + image regions
  - aligned stepping (`typeSize`)
- `Deep`
  - scans private + image regions
  - unaligned stepping (`step = 1`) for maximum coverage
- `IncludeMapped` can be combined with all profiles.

Result limit behavior:

- If enabled, scan stops collecting once the configured limit is reached.
- Remaining region work is skipped as soon as the limit gate is hit.

### 5) Pointer Scanner Window

Open from:

- `Tools -> Pointer Scanner`
- Watch-list context menu: `Pointer-scan for this address`

Features:

- Editable target address input.
- Data type selector for displayed pointer values.
- Result grid columns:
  - Pointer Expression
  - Value
  - Base
  - Offsets
  - Current Address (dynamic resolved address)
- Progress UI with separate scan and merge phases:
  - phase label (`Scanning` / `Merging`)
  - scan progress bar
  - merge progress bar
  - status text with progress details
- Commands:
  - Scan Options
  - Start Scan
  - Rescan
  - Cancel
  - Take Selected
- Double-click result row -> immediate take to main watch list flow.

Pointer scan options include:

- Max depth
- Max offset (editable combo with presets)
- Alignment (editable combo with presets)
- Pointer width mode:
  - Auto
  - Force 32-bit
  - Force 64-bit
- Thread count
- Optional result limit
- Region-type flags:
  - Include Private
  - Include Mapped
  - Include Image/Module
- Route filters:
  - Only Process+Base results (static roots)
  - Don't include pointers with read-only nodes
  - No looping pointers
  - Stop traversing after static root was found
  - Aggressive node deduplication (faster, may miss routes)
  - Allow negative offsets
- Optional address range filtering:
  - Range From / To
  - Require root in range
  - Require all nodes in range (strict)
- Optional `Trim memory after user cancel`.

Pointer rescan features:

- Rescan dialog supports:
  - rescan by address
  - rescan by value + data type
- Rescan filters existing pointer results and keeps matches.

### 6) Pointer Result Save/Load

Pointer session file menu supports:

- Load
- Save
- Save As
- Save Options

Formats:

- `.json`
- `.json.gz`

Save options:

- GZip compression
- Compact JSON
- Compact schema

Session content includes:

- process name snapshot
- save timestamp
- target address
- selected value data type
- pointer scan options
- pointer result paths (base/module/offset chain/pointer width)

### 7) Nearby Addresses Window

Open from watch entries or scan-result entries.

Features:

- Single paged list around a center address.
- Configurable:
  - data type
  - entries per page
- Page navigation (`Prev` / `Next`) with current range display.
- Center address shown in header.
- Center row auto-highlight and auto-centering in viewport.
- Row value refresh uses global update interval.
- Double-click row -> prompt for name -> quick take into watch list.
- Multi-select + `Take Selected`.

Special pointer helper:

- If window was opened from a pointer entry with offsets, context menu enables:
  - `Find Pointer Route To This Address`
- This runs a nearby brute-force relative pointer-route search based on the seed pointer chain.
- Found candidates can be named and taken into the watch list.

### 8) Memory Viewer Window

Features:

- Hex/ASCII memory view with pageable address range.
- Adjustable:
  - start address
  - byte count
  - bytes per row (`8/16/32`)
  - refresh interval
- Manual refresh and page navigation.
- Byte patching:
  - write hex bytes at a target address
  - example input: `90 90 90`

### 9) Write/Access Tracer Window

Purpose:

- Monitor a target address for value changes.
- Collect thread/instruction context samples to derive pointer-scan candidates.

Features:

- Configurable sampling interval and row cap.
- Tracks old/new values and instruction hit counts.
- Attempts base-candidate + offset derivation per sample.
- Actions:
  - Open Pointer Scanner For Candidate Base
  - Open Pointer Scanner (Instruction Context)
  - Copy Selected Row

Technical note:

- Full thread register instruction-context capture is primarily available for WOW64 (32-bit target) tracing.
- On unsupported targets it still detects value changes but provides reduced instruction-context detail.

## Global Value Update Routine

A global update interval (default `500 ms`) is configurable from:

- `Options -> Value Update Routine...`

This shared interval drives value updates in:

- main watch list
- main scan-result list
- pointer-scan result list
- nearby-address list

Process-exit behavior:

- If attached process is no longer running, value fields are replaced with `???` on the next scheduled update tick (not instant).
- This keeps refresh behavior incremental and avoids forced heavy UI refreshes.

## Address And Pointer Input Formats

Supported address input:

- Hex: `0x1234ABCD`
- Decimal: `305441741`

Pointer base input supports module/process-relative style:

- `ProcessName+0xOFFSET`
- `ModuleName+0xOFFSET`

Offsets format:

- comma-separated list
- hex or decimal accepted per element
- examples:
  - `0x10,0x20,0x8`
  - `16,32,8`

## Persistence

### Watch List Profiles

- Save/load as JSON via main menu `File`.
- Persists name, kind (direct/pointer), data type, addresses, module references, offsets, freeze state/value.

### Pointer Sessions

- Save/load as JSON or GZip JSON from pointer scanner.
- Persists target, options, value data type, and pointer paths.

## Tech Stack

- .NET 8 (`net8.0-windows`)
- WPF
- C#
- x64 target (`PlatformTarget=x64`)

## Requirements

- Windows 64-bit
- .NET 8 SDK
- Enough rights to open and read target process memory (Administrator may be required)

## Build And Run

From repository root:

```powershell
dotnet run --project .\MemoryScanner\MemoryScanner.csproj
```

Build solution only:

```powershell
$env:DOTNET_CLI_HOME="$PWD\.dotnet-home"
dotnet build .\MemoryScanner\MemoryScanner.sln
```

## Typical Workflow

1. Start app and select target process.
2. Run first scan with data type + condition + value.
3. Refine using next scan until useful rows remain.
4. Take results into watch list.
5. Edit/write/freeze watched values as needed.
6. Use pointer scanner to search stable pointer chains.
7. Use nearby addresses, memory viewer, and write/access tracer for deeper analysis.
8. Save watch profile and/or pointer session.

## Project Structure

- `MemoryScanner/MainWindow.xaml(.cs)` -> main UI (watch list + address scan + tool entry points)
- `MemoryScanner/Core/MemoryAccessor64.cs` -> process attach/read/write/resolve/format
- `MemoryScanner/Core/MemoryHelper.cs` -> low-level Windows memory API helper
- `MemoryScanner/Core/MemoryRegionEnumerator.cs` -> readable region discovery
- `MemoryScanner/Core/ScanService.cs` -> first/next scan engine
- `MemoryScanner/Core/PointerScanService.cs` -> pointer scan engine
- `MemoryScanner/Core/ProfileStorageService.cs` -> watch profile save/load
- `MemoryScanner/Core/UiUpdateRoutineSettings.cs` -> global value refresh interval
- `MemoryScanner/Windows/*` -> auxiliary windows (process picker, pointer scanner/options, nearby, memory viewer, write tracer)

## Known Limitations

- App is built as x64 WPF app.
- Some advanced trace details are limited for non-WOW64 targets in write/access tracer.
- Very large scans may still be expensive depending on target process memory layout and permissions.

## Safety Disclaimer

Use this tool only on software/processes you are authorized to inspect or modify.
You are responsible for legal compliance, software terms, and anti-cheat policy compliance.
