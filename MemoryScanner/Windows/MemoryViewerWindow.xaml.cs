using MemoryScanner.Core;
using MemoryScanner.Models;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace MemoryScanner.Windows;

public partial class MemoryViewerWindow : Window
{
    private const int DefaultByteCount = 1024;
    private const int MaxByteCount = 262144;
    private const int MinByteCount = 16;

    private readonly IMemoryAccessor _memoryAccessor;
    private readonly DispatcherTimer _timer;

    private ulong _startAddress;
    private int _byteCount = DefaultByteCount;
    private int _bytesPerRow = 16;

    public ObservableCollection<MemoryLineRow> Rows { get; } = new();

    public MemoryViewerWindow(IMemoryAccessor memoryAccessor, ulong startAddress)
    {
        _memoryAccessor = memoryAccessor;
        _startAddress = startAddress;

        InitializeComponent();

        MemoryGrid.ItemsSource = Rows;
        BytesPerRowBox.ItemsSource = new[] { "8", "16", "32" };
        BytesPerRowBox.SelectedItem = "16";

        AddressText.Text = FormatRawAddress(_startAddress);
        PatchAddressText.Text = FormatRawAddress(_startAddress);
        ByteCountText.Text = _byteCount.ToString(CultureInfo.InvariantCulture);

        _timer = new DispatcherTimer();
        _timer.Tick += Timer_OnTick;

        ApplySettings(showMessageOnError: false);
    }

    private void Apply_OnClick(object sender, RoutedEventArgs e)
    {
        ApplySettings(showMessageOnError: true);
    }

    private void RefreshNow_OnClick(object sender, RoutedEventArgs e)
    {
        RefreshMemory();
    }

    private void PrevPage_OnClick(object sender, RoutedEventArgs e)
    {
        _startAddress = _startAddress >= (ulong)_byteCount ? _startAddress - (ulong)_byteCount : 0;
        AddressText.Text = FormatRawAddress(_startAddress);
        PatchAddressText.Text = AddressText.Text;
        RefreshMemory();
    }

    private void NextPage_OnClick(object sender, RoutedEventArgs e)
    {
        var step = (ulong)_byteCount;
        if (_startAddress > ulong.MaxValue - step)
        {
            _startAddress = ulong.MaxValue - step;
        }
        else
        {
            _startAddress += step;
        }

        AddressText.Text = FormatRawAddress(_startAddress);
        PatchAddressText.Text = AddressText.Text;
        RefreshMemory();
    }

    private void WriteBytes_OnClick(object sender, RoutedEventArgs e)
    {
        if (!AddressParser.TryParseAddress(PatchAddressText.Text, out var patchAddress))
        {
            MessageBox.Show(this, "Invalid patch address.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!TryParseHexBytes(PatchBytesText.Text, out var bytes))
        {
            MessageBox.Show(this, "Invalid patch bytes. Use hex values like '90 90 90'.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        for (var i = 0; i < bytes.Length; i++)
        {
            var targetAddress = patchAddress + (ulong)i;
            if (!_memoryAccessor.TryWriteValue(targetAddress, MemoryDataType.Byte, bytes[i]))
            {
                MessageBox.Show(this, $"Write failed at {FormatRawAddress(targetAddress)}.", "Memory Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
        }

        StatusText.Text = $"Wrote {bytes.Length} byte(s) at {FormatRawAddress(patchAddress)}.";
        RefreshMemory();
    }

    private void MemoryGrid_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (MemoryGrid.SelectedItem is MemoryLineRow row)
        {
            PatchAddressText.Text = FormatRawAddress(row.Address);
        }
    }

    private void Timer_OnTick(object? sender, EventArgs e)
    {
        RefreshMemory();
    }

    private void ApplySettings(bool showMessageOnError)
    {
        if (!TryReadSettings(out var startAddress, out var byteCount, out var bytesPerRow, out var refreshMs))
        {
            if (showMessageOnError)
            {
                MessageBox.Show(this, "Invalid settings. Check address, size, row width and refresh interval.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            return;
        }

        _startAddress = startAddress;
        _byteCount = byteCount;
        _bytesPerRow = bytesPerRow;

        AddressText.Text = FormatRawAddress(_startAddress);
        ByteCountText.Text = _byteCount.ToString(CultureInfo.InvariantCulture);
        BytesPerRowBox.SelectedItem = _bytesPerRow.ToString(CultureInfo.InvariantCulture);

        if (refreshMs <= 0)
        {
            _timer.Stop();
        }
        else
        {
            _timer.Interval = TimeSpan.FromMilliseconds(refreshMs);
            _timer.Start();
        }

        RefreshMemory();
    }

    private bool TryReadSettings(out ulong startAddress, out int byteCount, out int bytesPerRow, out int refreshMs)
    {
        startAddress = _startAddress;
        byteCount = _byteCount;
        bytesPerRow = _bytesPerRow;
        refreshMs = 200;

        if (!AddressParser.TryParseAddress(AddressText.Text, out startAddress))
        {
            return false;
        }

        if (!int.TryParse(ByteCountText.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out byteCount))
        {
            return false;
        }

        byteCount = Math.Clamp(byteCount, MinByteCount, MaxByteCount);

        if (BytesPerRowBox.SelectedItem is not string rowText ||
            !int.TryParse(rowText, NumberStyles.Integer, CultureInfo.InvariantCulture, out bytesPerRow) ||
            (bytesPerRow != 8 && bytesPerRow != 16 && bytesPerRow != 32))
        {
            return false;
        }

        if (!int.TryParse(RefreshMsText.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out refreshMs) || refreshMs < 0 || refreshMs > 60000)
        {
            return false;
        }

        return true;
    }

    private void RefreshMemory()
    {
        if (!_memoryAccessor.IsAttached)
        {
            StatusText.Text = "No process attached.";
            return;
        }

        var data = new byte[_byteCount];
        var readable = new bool[_byteCount];

        if (_memoryAccessor.TryReadBytes(_startAddress, _byteCount, out var block) && block.Length == _byteCount)
        {
            Buffer.BlockCopy(block, 0, data, 0, _byteCount);
            Array.Fill(readable, true);
        }
        else
        {
            for (var i = 0; i < _byteCount; i++)
            {
                var address = _startAddress + (ulong)i;
                if (_memoryAccessor.TryReadValue(address, MemoryDataType.Byte, out var value))
                {
                    data[i] = Convert.ToByte(value, CultureInfo.InvariantCulture);
                    readable[i] = true;
                }
            }
        }

        RebuildRows(data, readable);

        var endAddress = _startAddress + (ulong)Math.Max(0, _byteCount - 1);
        PageInfoText.Text = $"{FormatRawAddress(_startAddress)} .. {FormatRawAddress(endAddress)}";

        var unreadableCount = readable.Count(flag => !flag);
        StatusText.Text = unreadableCount == 0
            ? $"Showing {_byteCount} byte(s)."
            : $"Showing {_byteCount} byte(s), unreadable bytes: {unreadableCount}.";
    }

    private void RebuildRows(byte[] data, bool[] readable)
    {
        var rowCount = (data.Length + _bytesPerRow - 1) / _bytesPerRow;

        while (Rows.Count < rowCount)
        {
            Rows.Add(new MemoryLineRow());
        }

        while (Rows.Count > rowCount)
        {
            Rows.RemoveAt(Rows.Count - 1);
        }

        for (var rowIndex = 0; rowIndex < rowCount; rowIndex++)
        {
            var offset = rowIndex * _bytesPerRow;
            var length = Math.Min(_bytesPerRow, data.Length - offset);
            var rowAddress = _startAddress + (ulong)offset;

            var hexBuilder = new StringBuilder(length * 3);
            var asciiBuilder = new StringBuilder(length);

            for (var i = 0; i < length; i++)
            {
                var index = offset + i;
                var isReadable = readable[index];

                if (i > 0)
                {
                    hexBuilder.Append(' ');
                }

                if (isReadable)
                {
                    var currentByte = data[index];
                    hexBuilder.Append(currentByte.ToString("X2", CultureInfo.InvariantCulture));
                    asciiBuilder.Append(currentByte >= 32 && currentByte <= 126 ? (char)currentByte : '.');
                }
                else
                {
                    hexBuilder.Append("??");
                    asciiBuilder.Append('.');
                }
            }

            var formatted = _memoryAccessor.FormatAddress(rowAddress);
            var displayAddress = $"{formatted} (0x{rowAddress:X})";
            Rows[rowIndex].Update(rowAddress, displayAddress, hexBuilder.ToString(), asciiBuilder.ToString());
        }
    }

    private static string FormatRawAddress(ulong address)
    {
        return $"0x{address:X}";
    }

    private static bool TryParseHexBytes(string? input, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var tokens = input
            .Replace(',', ' ')
            .Replace(';', ' ')
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (tokens.Length == 0)
        {
            return false;
        }

        var parsed = new List<byte>(tokens.Length);
        foreach (var token in tokens)
        {
            var normalized = token.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                ? token[2..]
                : token;

            if (!byte.TryParse(normalized, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var value))
            {
                return false;
            }

            parsed.Add(value);
        }

        if (parsed.Count == 0)
        {
            return false;
        }

        bytes = parsed.ToArray();
        return true;
    }

    protected override void OnClosed(EventArgs e)
    {
        _timer.Stop();
        base.OnClosed(e);
    }

    public sealed class MemoryLineRow : INotifyPropertyChanged
    {
        private string _displayAddress = string.Empty;
        private string _hexBytes = string.Empty;
        private string _asciiText = string.Empty;

        public ulong Address { get; private set; }

        public string DisplayAddress
        {
            get => _displayAddress;
            private set
            {
                if (_displayAddress == value)
                {
                    return;
                }

                _displayAddress = value;
                OnPropertyChanged();
            }
        }

        public string HexBytes
        {
            get => _hexBytes;
            private set
            {
                if (_hexBytes == value)
                {
                    return;
                }

                _hexBytes = value;
                OnPropertyChanged();
            }
        }

        public string AsciiText
        {
            get => _asciiText;
            private set
            {
                if (_asciiText == value)
                {
                    return;
                }

                _asciiText = value;
                OnPropertyChanged();
            }
        }

        public void Update(ulong address, string displayAddress, string hexBytes, string asciiText)
        {
            Address = address;
            DisplayAddress = displayAddress;
            HexBytes = hexBytes;
            AsciiText = asciiText;
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
