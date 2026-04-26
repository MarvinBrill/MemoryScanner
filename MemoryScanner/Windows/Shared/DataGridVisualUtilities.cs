using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace MemoryScanner.Windows.Shared;

internal static class DataGridVisualUtilities
{
    public static T? FindAncestor<T>(DependencyObject? current) where T : DependencyObject
    {
        while (current is not null)
        {
            if (current is T typed)
            {
                return typed;
            }

            current = VisualTreeHelper.GetParent(current);
        }

        return null;
    }

    public static IReadOnlyList<T> GetVisibleDataGridItems<T>(DataGrid grid) where T : class
    {
        var indexedItems = new List<(int Index, T Item)>();
        foreach (var row in FindVisualChildren<DataGridRow>(grid))
        {
            if (!row.IsVisible)
            {
                continue;
            }

            var index = row.GetIndex();
            if (index < 0 || index >= grid.Items.Count)
            {
                continue;
            }

            if (grid.Items[index] is T item)
            {
                indexedItems.Add((index, item));
            }
        }

        if (indexedItems.Count <= 1)
        {
            return indexedItems.Select(x => x.Item).ToArray();
        }

        indexedItems.Sort((a, b) => a.Index.CompareTo(b.Index));
        var deduplicated = new List<T>(indexedItems.Count);
        var lastIndex = -1;
        foreach (var entry in indexedItems)
        {
            if (entry.Index == lastIndex)
            {
                continue;
            }

            deduplicated.Add(entry.Item);
            lastIndex = entry.Index;
        }

        return deduplicated;
    }

    private static IEnumerable<T> FindVisualChildren<T>(DependencyObject? parent) where T : DependencyObject
    {
        if (parent is null)
        {
            yield break;
        }

        var childCount = VisualTreeHelper.GetChildrenCount(parent);
        for (var i = 0; i < childCount; i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T typedChild)
            {
                yield return typedChild;
            }

            foreach (var descendant in FindVisualChildren<T>(child))
            {
                yield return descendant;
            }
        }
    }
}
