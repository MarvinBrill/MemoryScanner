using MemoryScanner.Core;
using MemoryScanner.Models;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;

namespace MemoryScanner.Windows;

public partial class AddWatchEntryWindow : Window
{
    private readonly List<ModuleRange> _modules = new();
    private string _processName = string.Empty;
    private bool _addressOnlyEditMode;
    private string _preferredModuleName = string.Empty;
    private ulong _fallbackBaseAddress;
    private int _pointerSizeBytesHint;

    public WatchEntry? CreatedEntry { get; private set; }

    public AddWatchEntryWindow(
        string? suggestedName = null,
        ulong? suggestedAddress = null,
        string? processName = null,
        IReadOnlyList<ModuleRange>? modules = null)
    {
        InitializeDefaults(processName, modules);

        if (!string.IsNullOrWhiteSpace(suggestedName))
        {
            NameText.Text = suggestedName;
        }

        if (suggestedAddress.HasValue)
        {
            AddressText.Text = $"0x{suggestedAddress.Value:X}";
        }

        UpdateResolvedBaseAddressPreview();
    }

    public AddWatchEntryWindow(
        PointerPath pointerPath,
        MemoryDataType dataType,
        string? processName = null,
        IReadOnlyList<ModuleRange>? modules = null)
    {
        InitializeDefaults(processName, modules);

        DataTypeBox.SelectedItem = dataType;
        ModeBox.SelectedIndex = 1;
        NameText.Text = "PointerEntry";

        _preferredModuleName = pointerPath.BaseModuleName;
        _fallbackBaseAddress = pointerPath.BaseAddress;
        _pointerSizeBytesHint = pointerPath.PointerSizeBytes;
        AddressText.Text = FormatPointerBaseInput(pointerPath.BaseAddress, pointerPath.BaseModuleName, pointerPath.BaseModuleOffset);
        OffsetsText.Text = AddressParser.OffsetsToText(pointerPath.Offsets);

        SetInternalModuleFields(pointerPath.BaseModuleName, pointerPath.BaseModuleOffset);
        SetModeVisibility();
    }

    public AddWatchEntryWindow(
        WatchEntry entry,
        bool addressOnlyEditMode,
        string? processName = null,
        IReadOnlyList<ModuleRange>? modules = null)
    {
        InitializeDefaults(processName, modules);

        _addressOnlyEditMode = addressOnlyEditMode;
        ConfirmButton.Content = "Apply";
        Title = addressOnlyEditMode ? "Edit Address / Pointer" : "Edit Entry";

        PopulateFromEntry(entry);

        if (addressOnlyEditMode)
        {
            NameText.IsReadOnly = true;
            DataTypeBox.IsEnabled = false;

            NameLabel.Visibility = Visibility.Collapsed;
            NameText.Visibility = Visibility.Collapsed;
            DataTypeLabel.Visibility = Visibility.Collapsed;
            DataTypeBox.Visibility = Visibility.Collapsed;
        }

        UpdateResolvedBaseAddressPreview();
    }

    private void InitializeDefaults(string? processName, IReadOnlyList<ModuleRange>? modules)
    {
        InitializeComponent();
        DataTypeBox.ItemsSource = MemoryDataTypeUiOrder.Ordered;
        DataTypeBox.SelectedItem = MemoryDataType.Int32;
        ModeBox.SelectedIndex = 0;

        _processName = processName?.Trim() ?? string.Empty;
        if (modules is not null)
        {
            _modules.AddRange(modules);
        }

        SetModeVisibility();
    }

    private void PopulateFromEntry(WatchEntry entry)
    {
        NameText.Text = entry.Name;
        DataTypeBox.SelectedItem = entry.DataType;

        var usePointerPresentation = entry.Kind == WatchEntryKind.PointerChain || !string.IsNullOrWhiteSpace(entry.PointerBaseModuleName);
        if (!usePointerPresentation)
        {
            ModeBox.SelectedIndex = 0;
            AddressText.Text = $"0x{entry.DirectAddress:X}";
            OffsetsText.Text = string.Empty;
            SetInternalModuleFields(string.Empty, 0);
            SetModeVisibility();
            return;
        }

        ModeBox.SelectedIndex = 1;

        var pointerBaseAddress = entry.Kind == WatchEntryKind.PointerChain ? entry.PointerBaseAddress : entry.DirectAddress;
        _fallbackBaseAddress = pointerBaseAddress;
        var pointerBaseModuleName = entry.PointerBaseModuleName;
        var pointerBaseModuleOffset = entry.PointerBaseModuleOffset;

        if (string.IsNullOrWhiteSpace(pointerBaseModuleName) && TryFindContainingModule(pointerBaseAddress, out var containingModule))
        {
            pointerBaseModuleName = containingModule.Name;
            pointerBaseModuleOffset = pointerBaseAddress - containingModule.Base;
        }

        _preferredModuleName = pointerBaseModuleName;
        _pointerSizeBytesHint = entry.PointerSizeBytes;

        AddressText.Text = FormatPointerBaseInput(pointerBaseAddress, pointerBaseModuleName, pointerBaseModuleOffset);
        OffsetsText.Text = entry.Kind == WatchEntryKind.PointerChain
            ? AddressParser.OffsetsToText(entry.Offsets)
            : string.Empty;

        SetInternalModuleFields(pointerBaseModuleName, pointerBaseModuleOffset);
        SetModeVisibility();
    }

    private void ModeBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        SetModeVisibility();
    }

    private void AddressText_OnTextChanged(object sender, TextChangedEventArgs e)
    {
        UpdateResolvedBaseAddressPreview();
    }

    private void SetModeVisibility()
    {
        bool pointerMode = ModeBox.SelectedIndex == 1;
        AddressLabel.Text = pointerMode ? "Pointer Base Address" : "Address";

        ResolvedPointerBaseLabel.Visibility = pointerMode ? Visibility.Visible : Visibility.Collapsed;
        ResolvedPointerBaseText.Visibility = pointerMode ? Visibility.Visible : Visibility.Collapsed;
        OffsetsLabel.Visibility = pointerMode ? Visibility.Visible : Visibility.Collapsed;
        OffsetsText.Visibility = pointerMode ? Visibility.Visible : Visibility.Collapsed;

        // Kept as internal-only data fields.
        ModuleNameLabel.Visibility = Visibility.Collapsed;
        ModuleNameText.Visibility = Visibility.Collapsed;
        ModuleOffsetLabel.Visibility = Visibility.Collapsed;
        ModuleOffsetText.Visibility = Visibility.Collapsed;

        UpdateResolvedBaseAddressPreview();
    }

    private void UpdateResolvedBaseAddressPreview()
    {
        if (ModeBox.SelectedIndex != 1)
        {
            ResolvedPointerBaseText.Text = string.Empty;
            return;
        }

        if (TryResolvePointerBaseInput(AddressText.Text, out var resolvedBaseAddress, out var moduleName, out var moduleOffset, out _))
        {
            ResolvedPointerBaseText.Text = $"0x{resolvedBaseAddress:X}";
            SetInternalModuleFields(moduleName, moduleOffset);
            return;
        }

        ResolvedPointerBaseText.Text = "<unresolved>";
    }

    private static bool TryParseRelativeAddressInput(string? text, out string prefix, out ulong offset)
    {
        prefix = string.Empty;
        offset = 0;

        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var value = text.Trim();
        var separatorIndex = value.LastIndexOf('+');
        if (separatorIndex <= 0 || separatorIndex >= value.Length - 1)
        {
            return false;
        }

        var left = value[..separatorIndex].Trim();
        var right = value[(separatorIndex + 1)..].Trim();
        if (string.IsNullOrWhiteSpace(left))
        {
            return false;
        }

        if (!AddressParser.TryParseAddress(right, out offset))
        {
            return false;
        }

        prefix = left;
        return true;
    }

    private bool TryResolvePointerBaseInput(
        string? text,
        out ulong resolvedBaseAddress,
        out string moduleName,
        out ulong moduleOffset,
        out string error)
    {
        resolvedBaseAddress = 0;
        moduleName = string.Empty;
        moduleOffset = 0;
        error = string.Empty;

        if (AddressParser.TryParseAddress(text, out var absoluteAddress))
        {
            resolvedBaseAddress = absoluteAddress;
            if (TryFindContainingModule(absoluteAddress, out var containingModule))
            {
                moduleName = containingModule.Name;
                moduleOffset = absoluteAddress - containingModule.Base;
            }
            return true;
        }

        if (!TryParseRelativeAddressInput(text, out var prefix, out var parsedOffset))
        {
            error = "Invalid pointer base address.";
            return false;
        }

        moduleOffset = parsedOffset;
        var module = ResolveModuleByPrefix(prefix);
        if (module is null)
        {
            if (_addressOnlyEditMode)
            {
                moduleName = PrefixMatchesProcess(prefix) && !string.IsNullOrWhiteSpace(_preferredModuleName)
                    ? _preferredModuleName
                    : prefix;
                resolvedBaseAddress = _fallbackBaseAddress != 0 ? _fallbackBaseAddress : parsedOffset;
                return true;
            }

            error = "Could not resolve process/module prefix to a loaded module.";
            return false;
        }

        moduleName = module.Name;

        try
        {
            resolvedBaseAddress = checked(module.Base + parsedOffset);
            return true;
        }
        catch (OverflowException)
        {
            error = "Pointer base address overflow.";
            return false;
        }
    }

    private ModuleRange? ResolveModuleByPrefix(string prefix)
    {
        if (_modules.Count == 0)
        {
            return null;
        }

        if (PrefixMatchesProcess(prefix) && !string.IsNullOrWhiteSpace(_preferredModuleName))
        {
            var preferred = _modules.FirstOrDefault(m => string.Equals(m.Name, _preferredModuleName, StringComparison.OrdinalIgnoreCase));
            if (preferred is not null)
            {
                return preferred;
            }
        }

        var exact = _modules.FirstOrDefault(m => string.Equals(m.Name, prefix, StringComparison.OrdinalIgnoreCase));
        if (exact is not null)
        {
            return exact;
        }

        if (!prefix.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            var exe = _modules.FirstOrDefault(m => string.Equals(m.Name, prefix + ".exe", StringComparison.OrdinalIgnoreCase));
            if (exe is not null)
            {
                return exe;
            }
        }

        if (!prefix.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
        {
            var dll = _modules.FirstOrDefault(m => string.Equals(m.Name, prefix + ".dll", StringComparison.OrdinalIgnoreCase));
            if (dll is not null)
            {
                return dll;
            }
        }

        if (PrefixMatchesProcess(prefix))
        {
            var mainModule = FindMainModule();
            if (mainModule is not null)
            {
                return mainModule;
            }
        }

        return null;
    }

    private ModuleRange? FindMainModule()
    {
        if (_modules.Count == 0)
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(_processName))
        {
            var processExe = _processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? _processName
                : _processName + ".exe";

            var byExeName = _modules.FirstOrDefault(m => string.Equals(m.Name, processExe, StringComparison.OrdinalIgnoreCase));
            if (byExeName is not null)
            {
                return byExeName;
            }
        }

        return _modules[0];
    }

    private bool PrefixMatchesProcess(string prefix)
    {
        return !string.IsNullOrWhiteSpace(_processName) &&
               string.Equals(prefix, _processName, StringComparison.OrdinalIgnoreCase);
    }

    private bool TryFindContainingModule(ulong address, out ModuleRange module)
    {
        module = _modules.FirstOrDefault(m => m.Contains(address)) ?? new ModuleRange();
        return !string.IsNullOrWhiteSpace(module.Name);
    }

    private string FormatPointerBaseInput(ulong baseAddress, string moduleName, ulong moduleOffset)
    {
        if (!string.IsNullOrWhiteSpace(moduleName))
        {
            var prefix = string.IsNullOrWhiteSpace(_processName) ? moduleName : _processName;
            return $"{prefix}+0x{moduleOffset:X}";
        }

        return $"0x{baseAddress:X}";
    }

    private void SetInternalModuleFields(string moduleName, ulong moduleOffset)
    {
        ModuleNameText.Text = moduleName;
        ModuleOffsetText.Text = string.IsNullOrWhiteSpace(moduleName)
            ? string.Empty
            : $"0x{moduleOffset:X}";
    }

    private void Cancel_OnClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private void Add_OnClick(object sender, RoutedEventArgs e)
    {
        if (DataTypeBox.SelectedItem is not MemoryDataType dataType)
        {
            MessageBox.Show(this, "Select a valid data type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var name = string.IsNullOrWhiteSpace(NameText.Text) ? "Entry" : NameText.Text.Trim();

        if (ModeBox.SelectedIndex == 0)
        {
            if (!AddressParser.TryParseAddress(AddressText.Text, out var directAddress))
            {
                MessageBox.Show(this, "Invalid address.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var entry = new WatchEntry
            {
                Name = name,
                Kind = WatchEntryKind.DirectAddress,
                DataType = dataType,
                DirectAddress = directAddress
            };

            if (TryFindContainingModule(directAddress, out var containingModule))
            {
                entry.PointerBaseModuleName = containingModule.Name;
                entry.PointerBaseModuleOffset = directAddress - containingModule.Base;
            }

            CreatedEntry = entry;
        }
        else
        {
            if (!AddressParser.TryParseOffsets(OffsetsText.Text, out var offsets))
            {
                MessageBox.Show(this, "Invalid offsets format.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!TryResolvePointerBaseInput(AddressText.Text, out var baseAddress, out var moduleName, out var moduleOffset, out var parseError))
            {
                var message = string.IsNullOrWhiteSpace(parseError)
                    ? "Invalid pointer base address."
                    : parseError;
                MessageBox.Show(this, message, "Input Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            CreatedEntry = new WatchEntry
            {
                Name = name,
                Kind = WatchEntryKind.PointerChain,
                DataType = dataType,
                PointerBaseAddress = baseAddress,
                PointerBaseModuleName = moduleName,
                PointerBaseModuleOffset = moduleOffset,
                Offsets = new ObservableCollection<int>(offsets),
                PointerSizeBytes = _pointerSizeBytesHint
            };
        }

        if (_addressOnlyEditMode && CreatedEntry is not null)
        {
            CreatedEntry.Name = NameText.Text.Trim();
            CreatedEntry.DataType = dataType;
        }

        DialogResult = true;
    }
}





