using System.Windows;
using System.Windows.Controls;
using WinSentinel.App.Views;

namespace WinSentinel.App;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        ContentFrame.Navigate(new DashboardPage());
    }

    private void NavDashboard_Click(object sender, RoutedEventArgs e)
        => ContentFrame.Navigate(new DashboardPage());

    private void NavChat_Click(object sender, RoutedEventArgs e)
        => ContentFrame.Navigate(new ChatPage());

    private void NavAudit_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string category)
            ContentFrame.Navigate(new AuditDetailPage(category));
    }
}
