using MemoryScanner.Core;
using MemoryScanner.Models;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Threading;

namespace MemoryScanner.Windows;

public partial class WriteAccessTracerWindow : Window
{
    private const uint THREAD_SUSPEND_RESUME = 0x0002;
    private const uint THREAD_GET_CONTEXT = 0x0008;
    private const uint THREAD_QUERY_INFORMATION = 0x0040;

    private const uint WOW64_CONTEXT_i386 = 0x00010000;
    private const uint WOW64_CONTEXT_CONTROL = WOW64_CONTEXT_i386 | 0x00000001;
    private const uint WOW64_CONTEXT_INTEGER = WOW64_CONTEXT_i386 | 0x00000002;

    private const int DefaultCandidateOffsetWindow = 0x10000;
    private const int MinCandidateOffsetWindow = 0x100;
    private const int MaxCandidateOffsetWindowLimit = 0x10000000;

    private readonly IMemoryAccessor _memoryAccessor;
    private readonly Action<ulong, MemoryDataType, PointerScanOptions?>? _openPointerScannerCallback;
    private readonly DispatcherTimer _uiPulse;
    private readonly bool _supportsWow64Context;
    private readonly Dictionary<ulong, int> _instructionHitCounts = new();

    private ulong _targetAddress;
    private int _maxCandidateOffsetWindow = DefaultCandidateOffsetWindow;
    private byte[] _lastBytes = Array.Empty<byte>();
    private CancellationTokenSource? _monitorCts;
    private Task? _monitorTask;
    private volatile bool _isMonitoring;

    public ObservableCollection<TraceRow> Rows { get; } = new();

    public WriteAccessTracerWindow(
        IMemoryAccessor memoryAccessor,
        ulong targetAddress,
        MemoryDataType initialType,
        Action<ulong, MemoryDataType, PointerScanOptions?>? openPointerScannerCallback)
    {
        _memoryAccessor = memoryAccessor;
        _targetAddress = targetAddress;
        _openPointerScannerCallback = openPointerScannerCallback;

        InitializeComponent();

        TraceGrid.ItemsSource = Rows;
        DataTypeBox.ItemsSource = MemoryDataTypeUiOrder.Ordered;
        DataTypeBox.SelectedItem = initialType;
        TargetAddressText.Text = $"0x{targetAddress:X}";

        _supportsWow64Context = IsWow64Process(_memoryAccessor.Process.Handle, out var wow64) && wow64;
        if (!_supportsWow64Context)
        {
            HelpText.Text = "This helper currently captures thread instruction/register traces for 32-bit targets (WOW64). For 64-bit targets it still detects value changes, but cannot provide instruction candidates.";
        }

        _uiPulse = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        _uiPulse.Tick += (_, _) =>
        {
            if (_isMonitoring)
            {
                var top = BuildTopInstructionSummary();
                StatusText.Text = string.IsNullOrWhiteSpace(top)
                    ? $"Monitoring... Rows: {Rows.Count}"
                    : $"Monitoring... Rows: {Rows.Count} | Top instructions: {top}";
            }
        };
    }

    private void Start_OnClick(object sender, RoutedEventArgs e)
    {
        if (_isMonitoring)
        {
            return;
        }

        if (!_memoryAccessor.IsAttached)
        {
            MessageBox.Show(this, "Attach to a process first.", "No Process", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (DataTypeBox.SelectedItem is not MemoryDataType dataType)
        {
            MessageBox.Show(this, "Select a data type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!int.TryParse(IntervalMsText.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var intervalMs) || intervalMs < 1 || intervalMs > 5000)
        {
            MessageBox.Show(this, "Interval must be between 1 and 5000 ms.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!int.TryParse(MaxRowsText.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var maxRows) || maxRows < 10 || maxRows > 20000)
        {
            MessageBox.Show(this, "Max rows must be between 10 and 20000.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!TryParseOffsetWindow(MaxCandidateOffsetText.Text, out var candidateOffsetWindow)
            || candidateOffsetWindow < MinCandidateOffsetWindow
            || candidateOffsetWindow > MaxCandidateOffsetWindowLimit)
        {
            MessageBox.Show(this, $"Max candidate offset must be between 0x{MinCandidateOffsetWindow:X} and 0x{MaxCandidateOffsetWindowLimit:X}.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _maxCandidateOffsetWindow = candidateOffsetWindow;
        RebuildInstructionHitCountsFromRows();

        if (!TryReadTypedBytes(_targetAddress, dataType, out _lastBytes) || _lastBytes.Length == 0)
        {
            MessageBox.Show(this, "Unable to read target address with selected data type.", "Read Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _monitorCts?.Cancel();
        _monitorCts?.Dispose();
        _monitorCts = new CancellationTokenSource();

        _isMonitoring = true;
        StartButton.IsEnabled = false;
        StopButton.IsEnabled = true;
        StatusText.Text = "Monitoring started.";
        _uiPulse.Start();

        var token = _monitorCts.Token;
        _monitorTask = Task.Run(() => MonitorLoopAsync(dataType, intervalMs, maxRows, token), token);
    }

    private void Stop_OnClick(object sender, RoutedEventArgs e)
    {
        StopMonitoring();
    }

    private void Clear_OnClick(object sender, RoutedEventArgs e)
    {
        Rows.Clear();
        _instructionHitCounts.Clear();
        StatusText.Text = "Cleared.";
    }

    private void OpenPointerScanner_OnClick(object sender, RoutedEventArgs e)
    {
        if (TraceGrid.SelectedItem is not TraceRow row || !row.CandidateBaseAddress.HasValue)
        {
            MessageBox.Show(this, "Select a row with a valid Base Candidate first. If no candidate exists, use instruction-context open.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (DataTypeBox.SelectedItem is not MemoryDataType dataType)
        {
            dataType = MemoryDataType.Int32;
        }

        _openPointerScannerCallback?.Invoke(row.CandidateBaseAddress.Value, dataType, null);
    }

    private void OpenPointerScannerFromInstruction_OnClick(object sender, RoutedEventArgs e)
    {
        if (TraceGrid.SelectedItem is not TraceRow row)
        {
            MessageBox.Show(this, "Select an instruction row first.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (DataTypeBox.SelectedItem is not MemoryDataType dataType)
        {
            dataType = MemoryDataType.Int32;
        }

        var seedOptions = BuildInstructionContextScanSeed(row.InstructionAddress);
        _openPointerScannerCallback?.Invoke(_targetAddress, dataType, seedOptions);
    }

    private void CopySelected_OnClick(object sender, RoutedEventArgs e)
    {
        if (TraceGrid.SelectedItem is not TraceRow row)
        {
            return;
        }

        var text = $"{row.TimeText} | old={row.OldValueText} | new={row.NewValueText} | tid={row.ThreadId} | ip={row.InstructionText} | hits={row.InstructionHits} | base={row.BaseCandidateText} | off={row.OffsetText} | addr={row.CandidateAddressText}";
        try
        {
            Clipboard.SetText(text);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Clipboard Error", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async Task MonitorLoopAsync(MemoryDataType dataType, int intervalMs, int maxRows, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                if (!TryReadTypedBytes(_targetAddress, dataType, out var currentBytes) || currentBytes.Length == 0)
                {
                    await Task.Delay(intervalMs, cancellationToken);
                    continue;
                }

                if (!_lastBytes.AsSpan().SequenceEqual(currentBytes))
                {
                    var oldText = FormatTypedValue(_lastBytes, dataType);
                    var newText = FormatTypedValue(currentBytes, dataType);
                    _lastBytes = currentBytes;

                    var samples = CaptureThreadSamples(_targetAddress);
                    if (samples.Count == 0)
                    {
                        samples.Add(new ThreadSample
                        {
                            ThreadId = -1,
                            InstructionPointer = 0,
                            InstructionText = _supportsWow64Context ? "<no sample>" : "<thread context unsupported for this target>"
                        });
                    }

                    await Dispatcher.InvokeAsync(() =>
                    {
                        var time = DateTime.Now.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture);
                        foreach (var sample in samples)
                        {
                            var hits = RegisterInstructionHit(sample.InstructionPointer);
                            if (sample.InstructionPointer != 0)
                            {
                                foreach (var existingRow in Rows)
                                {
                                    if (existingRow.InstructionAddress == sample.InstructionPointer)
                                    {
                                        existingRow.InstructionHits = hits;
                                    }
                                }
                            }

                            Rows.Insert(0, new TraceRow
                            {
                                TimeText = time,
                                OldValueText = oldText,
                                NewValueText = newText,
                                ThreadId = sample.ThreadId < 0 ? "-" : sample.ThreadId.ToString(CultureInfo.InvariantCulture),
                                InstructionText = sample.InstructionText,
                                InstructionAddress = sample.InstructionPointer,
                                InstructionHits = hits,
                                BaseCandidateText = sample.BaseRegisterName is null
                                    ? "-"
                                    : $"{sample.BaseRegisterName} -> {_memoryAccessor.FormatAddress(sample.BaseCandidateAddress ?? 0)}",
                                OffsetText = sample.OffsetText,
                                CandidateAddressText = sample.BaseCandidateAddress.HasValue
                                    ? $"0x{sample.BaseCandidateAddress.Value:X}"
                                    : "-",
                                CandidateBaseAddress = sample.BaseCandidateAddress
                            });
                        }

                        while (Rows.Count > maxRows)
                        {
                            Rows.RemoveAt(Rows.Count - 1);
                        }
                    });
                }

                await Task.Delay(intervalMs, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            await Dispatcher.InvokeAsync(() =>
            {
                MessageBox.Show(this, ex.Message, "Trace Error", MessageBoxButton.OK, MessageBoxImage.Error);
            });
        }
        finally
        {
            await Dispatcher.InvokeAsync(() =>
            {
                _isMonitoring = false;
                StartButton.IsEnabled = true;
                StopButton.IsEnabled = false;
                _uiPulse.Stop();
                if (StatusText.Text.StartsWith("Monitoring", StringComparison.OrdinalIgnoreCase) ||
                    StatusText.Text.StartsWith("Stopping", StringComparison.OrdinalIgnoreCase))
                {
                    StatusText.Text = "Monitoring stopped.";
                }
            });
        }
    }

    private List<ThreadSample> CaptureThreadSamples(ulong targetAddress)
    {
        var samples = new List<ThreadSample>();
        if (!_supportsWow64Context)
        {
            return samples;
        }

        ProcessThreadCollection threads;
        try
        {
            threads = _memoryAccessor.Process.Threads;
        }
        catch
        {
            return samples;
        }

        foreach (ProcessThread thread in threads)
        {
            try
            {
                if (TryCaptureWow64ThreadSample((uint)thread.Id, targetAddress, out var sample))
                {
                    samples.Add(sample);
                }
            }
            catch
            {
                // ignore transient thread snapshot errors
            }
        }

        if (samples.Count <= 1)
        {
            return samples;
        }

        samples.Sort((a, b) =>
        {
            var aHas = a.BaseCandidateAddress.HasValue ? 0 : 1;
            var bHas = b.BaseCandidateAddress.HasValue ? 0 : 1;
            var cmp = aHas.CompareTo(bHas);
            if (cmp != 0)
            {
                return cmp;
            }

            var aScore = a.Score;
            var bScore = b.Score;
            return aScore.CompareTo(bScore);
        });

        const int maxRowsPerChange = 24;
        if (samples.Count > maxRowsPerChange)
        {
            samples.RemoveRange(maxRowsPerChange, samples.Count - maxRowsPerChange);
        }

        return samples;
    }

    private bool TryCaptureWow64ThreadSample(uint threadId, ulong targetAddress, out ThreadSample sample)
    {
        sample = new ThreadSample();

        var threadHandle = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, false, threadId);
        if (threadHandle == IntPtr.Zero)
        {
            return false;
        }

        var suspended = false;
        try
        {
            if (SuspendThread(threadHandle) == uint.MaxValue)
            {
                return false;
            }

            suspended = true;

            var ctx = new WOW64_CONTEXT
            {
                ContextFlags = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER,
                FloatSave = new WOW64_FLOATING_SAVE_AREA
                {
                    RegisterArea = new byte[80]
                },
                ExtendedRegisters = new byte[512]
            };

            if (!Wow64GetThreadContext(threadHandle, ref ctx))
            {
                return false;
            }

            var ip = ctx.Eip;
            var instructionText = _memoryAccessor.FormatAddress(ip) + $" (0x{ip:X})";

            var regs = new (string Name, ulong Value)[]
            {
                ("EAX", ctx.Eax),
                ("EBX", ctx.Ebx),
                ("ECX", ctx.Ecx),
                ("EDX", ctx.Edx),
                ("ESI", ctx.Esi),
                ("EDI", ctx.Edi),
                ("EBP", ctx.Ebp),
                ("ESP", ctx.Esp)
            };

            string? bestReg = null;
            ulong? bestBase = null;
            int bestOffset = 0;
            var bestScore = int.MaxValue;

            foreach (var reg in regs)
            {
                var delta = targetAddress >= reg.Value
                    ? (long)(targetAddress - reg.Value)
                    : -(long)(reg.Value - targetAddress);

                if (delta < int.MinValue || delta > int.MaxValue)
                {
                    continue;
                }

                var abs = Math.Abs((int)delta);
                if (abs > _maxCandidateOffsetWindow)
                {
                    continue;
                }

                if (abs < bestScore)
                {
                    bestScore = abs;
                    bestReg = reg.Name;
                    bestBase = reg.Value;
                    bestOffset = (int)delta;
                }
            }

            sample = new ThreadSample
            {
                ThreadId = (int)threadId,
                InstructionPointer = ip,
                InstructionText = instructionText,
                BaseRegisterName = bestReg,
                BaseCandidateAddress = bestBase,
                Offset = bestBase.HasValue ? bestOffset : null,
                OffsetText = bestBase.HasValue ? FormatOffset(bestOffset) : "-",
                Score = bestScore
            };

            return true;
        }
        finally
        {
            if (suspended)
            {
                ResumeThread(threadHandle);
            }

            CloseHandle(threadHandle);
        }
    }

    private int RegisterInstructionHit(ulong instructionAddress)
    {
        if (instructionAddress == 0)
        {
            return 0;
        }

        if (_instructionHitCounts.TryGetValue(instructionAddress, out var count))
        {
            count++;
            _instructionHitCounts[instructionAddress] = count;
            return count;
        }

        _instructionHitCounts[instructionAddress] = 1;
        return 1;
    }

    private void RebuildInstructionHitCountsFromRows()
    {
        _instructionHitCounts.Clear();
        foreach (var row in Rows)
        {
            if (row.InstructionAddress == 0)
            {
                continue;
            }

            if (_instructionHitCounts.TryGetValue(row.InstructionAddress, out var count))
            {
                _instructionHitCounts[row.InstructionAddress] = count + 1;
            }
            else
            {
                _instructionHitCounts[row.InstructionAddress] = 1;
            }
        }

        foreach (var row in Rows)
        {
            if (row.InstructionAddress != 0 && _instructionHitCounts.TryGetValue(row.InstructionAddress, out var hits))
            {
                row.InstructionHits = hits;
            }
            else
            {
                row.InstructionHits = 0;
            }
        }
    }

    private string BuildTopInstructionSummary(int take = 3)
    {
        var top = _instructionHitCounts
            .Where(kv => kv.Key != 0)
            .OrderByDescending(kv => kv.Value)
            .ThenBy(kv => kv.Key)
            .Take(take)
            .ToArray();

        if (top.Length == 0)
        {
            return string.Empty;
        }

        var parts = new List<string>(top.Length);
        foreach (var item in top)
        {
            parts.Add($"{_memoryAccessor.FormatAddress(item.Key)} x{item.Value}");
        }

        return string.Join(", ", parts);
    }

    private PointerScanOptions? BuildInstructionContextScanSeed(ulong instructionAddress)
    {
        if (instructionAddress == 0)
        {
            return null;
        }

        var module = _memoryAccessor.Modules.FirstOrDefault(m => m.Contains(instructionAddress));
        if (module is null)
        {
            return null;
        }

        var rangeTo = module.End > module.Base ? module.End - 1 : module.End;
        return new PointerScanOptions
        {
            UseAddressRange = true,
            AddressRangeFrom = module.Base,
            AddressRangeTo = rangeTo,
            RequireRootInAddressRange = true,
            RequireAllNodesInAddressRange = false
        };
    }

    private static bool TryParseOffsetWindow(string? text, out int value)
    {
        value = 0;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var input = text.Trim();
        if (input.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (!long.TryParse(input[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var parsedHex))
            {
                return false;
            }

            if (parsedHex < 0 || parsedHex > int.MaxValue)
            {
                return false;
            }

            value = (int)parsedHex;
            return true;
        }

        return int.TryParse(input, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private bool TryReadTypedBytes(ulong address, MemoryDataType dataType, out byte[] bytes)
    {
        var size = GetTypeSize(dataType);
        if (size <= 0)
        {
            bytes = Array.Empty<byte>();
            return false;
        }

        return _memoryAccessor.TryReadBytes(address, size, out bytes);
    }

    private static int GetTypeSize(MemoryDataType dataType) => dataType switch
    {
        MemoryDataType.Byte => sizeof(byte),
        MemoryDataType.Int16 => sizeof(short),
        MemoryDataType.Int32 => sizeof(int),
        MemoryDataType.Int64 => sizeof(long),
        MemoryDataType.Float => sizeof(float),
        MemoryDataType.Double => sizeof(double),
        MemoryDataType.String => 64,
        _ => sizeof(int)
    };

    private static string FormatTypedValue(byte[] bytes, MemoryDataType dataType)
    {
        if (bytes.Length == 0)
        {
            return "<n/a>";
        }

        try
        {
            return dataType switch
            {
                MemoryDataType.Byte => bytes[0].ToString(CultureInfo.InvariantCulture),
                MemoryDataType.Int16 when bytes.Length >= 2 => BitConverter.ToInt16(bytes, 0).ToString(CultureInfo.InvariantCulture),
                MemoryDataType.Int32 when bytes.Length >= 4 => BitConverter.ToInt32(bytes, 0).ToString(CultureInfo.InvariantCulture),
                MemoryDataType.Int64 when bytes.Length >= 8 => BitConverter.ToInt64(bytes, 0).ToString(CultureInfo.InvariantCulture),
                MemoryDataType.Float when bytes.Length >= 4 => BitConverter.ToSingle(bytes, 0).ToString("0.######", CultureInfo.InvariantCulture),
                MemoryDataType.Double when bytes.Length >= 8 => BitConverter.ToDouble(bytes, 0).ToString("0.######", CultureInfo.InvariantCulture),
                MemoryDataType.String => DecodeUtf8(bytes),
                _ => BitConverter.ToString(bytes)
            };
        }
        catch
        {
            return BitConverter.ToString(bytes);
        }
    }

    private static string DecodeUtf8(byte[] bytes)
    {
        var terminator = Array.IndexOf(bytes, (byte)0);
        if (terminator < 0)
        {
            terminator = bytes.Length;
        }

        if (terminator == 0)
        {
            return string.Empty;
        }

        return System.Text.Encoding.UTF8.GetString(bytes, 0, terminator);
    }

    private static string FormatOffset(int offset)
    {
        if (offset < 0)
        {
            return $"-0x{Math.Abs(offset):X}";
        }

        return $"+0x{offset:X}";
    }

    private void StopMonitoring()
    {
        if (!_isMonitoring)
        {
            return;
        }

        _monitorCts?.Cancel();
        StatusText.Text = "Stopping...";
    }

    protected override void OnClosed(EventArgs e)
    {
        StopMonitoring();
        _monitorCts?.Dispose();
        base.OnClosed(e);
    }

    public sealed class TraceRow : INotifyPropertyChanged
    {
        private string _timeText = string.Empty;
        private string _oldValueText = string.Empty;
        private string _newValueText = string.Empty;
        private string _threadId = string.Empty;
        private string _instructionText = string.Empty;
        private int _instructionHits;
        private string _baseCandidateText = string.Empty;
        private string _offsetText = string.Empty;
        private string _candidateAddressText = string.Empty;

        public string TimeText { get => _timeText; set => Set(ref _timeText, value); }
        public string OldValueText { get => _oldValueText; set => Set(ref _oldValueText, value); }
        public string NewValueText { get => _newValueText; set => Set(ref _newValueText, value); }
        public string ThreadId { get => _threadId; set => Set(ref _threadId, value); }
        public string InstructionText { get => _instructionText; set => Set(ref _instructionText, value); }
        public int InstructionHits { get => _instructionHits; set => Set(ref _instructionHits, value); }
        public string BaseCandidateText { get => _baseCandidateText; set => Set(ref _baseCandidateText, value); }
        public string OffsetText { get => _offsetText; set => Set(ref _offsetText, value); }
        public string CandidateAddressText { get => _candidateAddressText; set => Set(ref _candidateAddressText, value); }

        public ulong InstructionAddress { get; set; }
        public ulong? CandidateBaseAddress { get; set; }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void Set<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value))
            {
                return;
            }

            field = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    private sealed class ThreadSample
    {
        public int ThreadId { get; set; }
        public ulong InstructionPointer { get; set; }
        public string InstructionText { get; set; } = string.Empty;
        public string? BaseRegisterName { get; set; }
        public ulong? BaseCandidateAddress { get; set; }
        public int? Offset { get; set; }
        public string OffsetText { get; set; } = "-";
        public int Score { get; set; } = int.MaxValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WOW64_FLOATING_SAVE_AREA
    {
        public uint ControlWord;
        public uint StatusWord;
        public uint TagWord;
        public uint ErrorOffset;
        public uint ErrorSelector;
        public uint DataOffset;
        public uint DataSelector;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
        public byte[] RegisterArea;
        public uint Cr0NpxState;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WOW64_CONTEXT
    {
        public uint ContextFlags;
        public uint Dr0;
        public uint Dr1;
        public uint Dr2;
        public uint Dr3;
        public uint Dr6;
        public uint Dr7;
        public WOW64_FLOATING_SAVE_AREA FloatSave;
        public uint SegGs;
        public uint SegFs;
        public uint SegEs;
        public uint SegDs;
        public uint Edi;
        public uint Esi;
        public uint Ebx;
        public uint Edx;
        public uint Ecx;
        public uint Eax;
        public uint Ebp;
        public uint Eip;
        public uint SegCs;
        public uint EFlags;
        public uint Esp;
        public uint SegSs;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] ExtendedRegisters;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Wow64GetThreadContext(IntPtr hThread, ref WOW64_CONTEXT lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr processHandle, out bool wow64Process);
}









