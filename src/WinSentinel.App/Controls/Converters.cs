using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace WinSentinel.App.Controls;

/// <summary>
/// Converts bool (IsUser) to HorizontalAlignment (Right for user, Left for bot).
/// </summary>
public class BoolToAlignmentConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is true ? HorizontalAlignment.Right : HorizontalAlignment.Left;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

/// <summary>
/// Converts bool (IsUser) to bubble background color.
/// </summary>
public class BoolToBubbleColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is true
            ? new SolidColorBrush(Color.FromArgb(255, 0, 120, 212))  // Blue for user
            : new SolidColorBrush(Color.FromArgb(255, 45, 45, 61));   // Dark for bot
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

/// <summary>
/// Negates a boolean value.
/// </summary>
public class BoolNegationConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is bool b ? !b : true;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is bool b ? !b : true;
    }
}

/// <summary>
/// Converts bool to Visibility. Set Invert=True for inverse behavior.
/// </summary>
public class BoolToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var visible = value is true;
        if (Invert) visible = !visible;
        return visible ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

/// <summary>
/// Converts severity string to a SolidColorBrush.
/// Critical=Red, High=Orange, Warning/Medium=Yellow, Info/Low=Blue, Pass=Green.
/// </summary>
public class SeverityToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var severity = value?.ToString() ?? "";
        var color = severity switch
        {
            "Critical" => Color.FromRgb(0xF4, 0x43, 0x36),
            "High" => Color.FromRgb(0xFF, 0x98, 0x00),
            "Medium" or "Warning" => Color.FromRgb(0xFF, 0xC1, 0x07),
            "Low" or "Info" => Color.FromRgb(0x21, 0x96, 0xF3),
            _ => Color.FromRgb(0x4C, 0xAF, 0x50)
        };
        return new SolidColorBrush(color);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

/// <summary>
/// Converts an integer to Visibility. 0 or less = Collapsed, >0 = Visible.
/// </summary>
public class CountToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is int count && count > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}
