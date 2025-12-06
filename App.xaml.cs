using System.Windows;
using System.Windows.Threading;

namespace NetworkScanner;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        
        // Catch unhandled exceptions on the UI thread
        DispatcherUnhandledException += App_DispatcherUnhandledException;
        
        // Catch unhandled exceptions on background threads
        AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
        
        // Catch unhandled task exceptions
        TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;
    }

    private void App_DispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(
            $"An error occurred:\n\n{e.Exception.Message}\n\n{e.Exception.StackTrace}",
            "Error",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
        
        e.Handled = true; // Prevent app from crashing
    }

    private void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception ex)
        {
            MessageBox.Show(
                $"A critical error occurred:\n\n{ex.Message}",
                "Critical Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void TaskScheduler_UnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        e.SetObserved(); // Prevent app crash from unobserved task exceptions
    }
}

