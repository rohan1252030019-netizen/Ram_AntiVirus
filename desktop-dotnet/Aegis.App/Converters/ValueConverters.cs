using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using Aegis.Core.Enums;

namespace Aegis.App.Converters;

public class BooleanToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool b = value is true;
        if (Invert) b = !b;
        return b ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is Visibility.Visible;
}

public class SeverityToBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush CriticalBrush = new(Color.FromRgb(239, 68, 68)); // Red #EF4444
    private static readonly SolidColorBrush HighBrush = new(Color.FromRgb(249, 115, 22));    // Orange #F97316
    private static readonly SolidColorBrush MediumBrush = new(Color.FromRgb(234, 179, 8));   // Yellow #EAB308
    private static readonly SolidColorBrush LowBrush = new(Color.FromRgb(59, 130, 246));     // Blue #3B82F6
    private static readonly SolidColorBrush DefaultBrush = new(Color.FromRgb(148, 163, 184));

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is Severity s)
        {
            return s switch
            {
                Severity.Critical => CriticalBrush,
                Severity.High => HighBrush,
                Severity.Medium => MediumBrush,
                Severity.Low => LowBrush,
                _ => DefaultBrush
            };
        }
        return DefaultBrush;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotImplementedException();
}

public class NullToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
    {
        bool hasValue = value != null && (value is not string s || !string.IsNullOrWhiteSpace(s));
        if (Invert) hasValue = !hasValue;
        return hasValue ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotImplementedException();
}
