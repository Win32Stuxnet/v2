using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using NetworkScanner.Core;

namespace NetworkScanner;

public partial class MainWindow : Window
{
    private FastScanner? _scanner;
    private CancellationTokenSource? _cts;
    private readonly ObservableCollection<ScanResult> _results = new();
    private DateTime _startTime;

    public MainWindow()
    {
        InitializeComponent();
        ResultsList.ItemsSource = _results;
    }

    private async void ScanButton_Click(object sender, RoutedEventArgs e)
    {
        var target = TargetInput.Text.Trim();
        if (string.IsNullOrEmpty(target))
        {
            StatusText.Text = "Enter a target IP, hostname, or CIDR range";
            return;
        }

        // Parse ports
        var ports = ParsePorts(PortsInput.Text);
        if (ports.Count == 0)
        {
            StatusText.Text = "Enter valid port numbers";
            return;
        }

        // Cancel and dispose any existing scan
        if (_cts != null)
        {
            try
            {
                await _cts.CancelAsync();
                _cts.Dispose();
            }
            catch { }
        }

        // Setup
        _results.Clear();
        _cts = new CancellationTokenSource();
        _startTime = DateTime.Now;
        
        ScanButton.IsEnabled = false;
        StopButton.IsEnabled = true;
        ProgressBar.Value = 0;

        _scanner = new FastScanner(new ScanOptions
        {
            Ports = ports,
            PortTimeout = 300,
            PingTimeout = 500,
            MaxHostConcurrency = 50,
            MaxPortConcurrency = 100,
            PingFirst = true,
            SkipOfflineHosts = false,
            GrabBanners = false
        });

        _scanner.OnProgress += progress =>
        {
            try
            {
                Dispatcher.Invoke(() =>
                {
                    ProgressBar.Value = progress.Percent;
                    StatusText.Text = $"Scanning {progress.CurrentHost} ({progress.ScannedHosts}/{progress.TotalHosts})";
                });
            }
            catch (TaskCanceledException) { }
            catch (ObjectDisposedException) { }
        };

        _scanner.OnHostComplete += result =>
        {
            try
            {
                Dispatcher.Invoke(() => _results.Add(result.Result));
            }
            catch (TaskCanceledException) { }
            catch (ObjectDisposedException) { }
        };

        try
        {
            StatusText.Text = $"Scanning {target}...";
            await _scanner.ScanAsync(target, _cts.Token);
            
            var elapsed = DateTime.Now - _startTime;
            var openCount = _results.Sum(r => r.OpenPorts.Count);
            var onlineCount = _results.Count(r => r.IsOnline);
            
            StatusText.Text = $"Complete in {elapsed.TotalSeconds:F1}s";
            SummaryText.Text = $"{_results.Count} hosts scanned | {onlineCount} online | {openCount} open ports";
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = "Scan cancelled";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Error: {ex.Message}";
        }
        finally
        {
            ScanButton.IsEnabled = true;
            StopButton.IsEnabled = false;
            ProgressBar.Value = 100;
            
            // Cleanup
            try
            {
                _cts?.Dispose();
            }
            catch { }
            _cts = null;
        }
    }

    private void StopButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _cts?.Cancel();
        }
        catch (ObjectDisposedException) { }
        StatusText.Text = "Stopping...";
    }

    private void ResultsList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ResultsList.SelectedItem is ScanResult result)
        {
            PortsList.ItemsSource = result.OpenPorts;
        }
    }

    private void ExportJson_Click(object sender, RoutedEventArgs e)
    {
        if (_results.Count == 0) return;
        
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "JSON|*.json",
            FileName = $"scan_{DateTime.Now:yyyyMMdd_HHmmss}.json"
        };
        
        if (dialog.ShowDialog() == true)
        {
            var json = JsonSerializer.Serialize(_results, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(dialog.FileName, json);
            StatusText.Text = $"Exported to {dialog.FileName}";
        }
    }

    private void ExportCsv_Click(object sender, RoutedEventArgs e)
    {
        if (_results.Count == 0) return;
        
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "CSV|*.csv",
            FileName = $"scan_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
        };
        
        if (dialog.ShowDialog() == true)
        {
            var lines = new List<string> { "Host,Online,Latency,Port,Service,Banner" };
            foreach (var r in _results)
            {
                if (r.OpenPorts.Count == 0)
                    lines.Add($"{r.Host},{r.IsOnline},{r.Latency},,,");
                else
                    foreach (var p in r.OpenPorts)
                        lines.Add($"{r.Host},{r.IsOnline},{r.Latency},{p.Port},{p.Service},\"{p.Banner}\"");
            }
            File.WriteAllLines(dialog.FileName, lines);
            StatusText.Text = $"Exported to {dialog.FileName}";
        }
    }

    private static List<int> ParsePorts(string input)
    {
        var ports = new HashSet<int>();
        foreach (var part in input.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = part.Trim();
            if (trimmed.Contains('-'))
            {
                var range = trimmed.Split('-');
                if (range.Length == 2 && int.TryParse(range[0], out var s) && int.TryParse(range[1], out var e))
                    for (var i = Math.Max(1, s); i <= Math.Min(65535, e); i++)
                        ports.Add(i);
            }
            else if (int.TryParse(trimmed, out var p) && p >= 1 && p <= 65535)
                ports.Add(p);
        }
        return ports.OrderBy(p => p).ToList();
    }
}

public class BoolToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? new SolidColorBrush(Color.FromRgb(34, 197, 94)) : new SolidColorBrush(Color.FromRgb(239, 68, 68));
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => throw new NotImplementedException();
}

public class StringToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        string.IsNullOrEmpty(value as string) ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => throw new NotImplementedException();
}

