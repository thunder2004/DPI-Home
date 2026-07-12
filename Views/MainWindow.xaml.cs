using System.Windows;
using DPI_Home.ViewModels;

namespace DPI_Home.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Loaded += Window_Loaded;
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel vm)
            vm.StartApi();
    }
}
