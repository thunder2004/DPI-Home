using System.Windows;
using DPI_Home.ViewModels;

namespace DPI_Home.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Loaded += Window_Loaded;
        Closing += Window_Closing;
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        FitToWorkArea();

        if (DataContext is MainViewModel vm)
            vm.StartApi();
    }

    /// <summary>Flush the alert history to disk on shutdown — the periodic save timer
    /// (every 10s) might not have run since the last alert arrived.</summary>
    private void Window_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (DataContext is MainViewModel vm)
            vm.SaveHistoryNow();
    }

    /// <summary>
    /// The XAML declares a fixed Height="900" with WindowStartupLocation="CenterScreen".
    /// CenterScreen computes Top = (screenHeight - windowHeight) / 2 — on any screen whose
    /// work area is shorter than 900px (common: 1366x768 laptops, or larger screens with
    /// 125-150% DPI scaling reducing the effective logical height), that comes out negative,
    /// placing the window's top — including the header with all the controls — above the
    /// visible screen area. Clamp to the actual work area and re-center within it.
    /// </summary>
    private void FitToWorkArea()
    {
        var workArea = SystemParameters.WorkArea;

        if (Width > workArea.Width) Width = workArea.Width;
        if (Height > workArea.Height) Height = workArea.Height;

        Left = workArea.Left + Math.Max(0, (workArea.Width - Width) / 2);
        Top = workArea.Top + Math.Max(0, (workArea.Height - Height) / 2);
    }
}
