using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetworkScanner.Core;

/// <summary>
/// High-performance network scanner using parallel async operations.
/// </summary>
public class FastScanner
{
    private readonly ScanOptions _options;
    private readonly ConcurrentBag<ScanResult> _results = new();
    private int _scannedCount;
    private int _totalCount;

    public event Action<ScanProgress>? OnProgress;
    public event Action<HostResult>? OnHostComplete;

    public FastScanner(ScanOptions? options = null)
    {
        _options = options ?? new ScanOptions();
    }

    public async Task<List<ScanResult>> ScanAsync(string target, CancellationToken ct = default)
    {
        var hosts = ParseTarget(target);
        _totalCount = hosts.Count;
        _scannedCount = 0;
        _results.Clear();

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = _options.MaxHostConcurrency,
            CancellationToken = ct
        };

        await Parallel.ForEachAsync(hosts, parallelOptions, async (host, token) =>
        {
            var result = await ScanHostAsync(host, token);
            _results.Add(result);
            Interlocked.Increment(ref _scannedCount);
            
            OnProgress?.Invoke(new ScanProgress
            {
                ScannedHosts = _scannedCount,
                TotalHosts = _totalCount,
                CurrentHost = host,
                Percent = (double)_scannedCount / _totalCount * 100
            });
            
            OnHostComplete?.Invoke(new HostResult { Host = host, Result = result });
        });

        return _results.ToList();
    }

    private async Task<ScanResult> ScanHostAsync(string host, CancellationToken ct)
    {
        var result = new ScanResult { Host = host };

        // Quick ping check
        if (_options.PingFirst)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(host, _options.PingTimeout);
                result.IsOnline = reply.Status == IPStatus.Success;
                result.Latency = reply.RoundtripTime;
            }
            catch (PingException) { result.IsOnline = false; }
            catch (SocketException) { result.IsOnline = false; }
            catch (InvalidOperationException) { result.IsOnline = false; }
            catch (Exception) { result.IsOnline = false; }

            if (!result.IsOnline && _options.SkipOfflineHosts)
                return result;
        }
        else
        {
            result.IsOnline = true; // Assume online if not pinging
        }

        // Parallel port scan
        var openPorts = new ConcurrentBag<PortResult>();
        var ports = _options.Ports;

        try
        {
            await Parallel.ForEachAsync(ports, new ParallelOptions
            {
                MaxDegreeOfParallelism = _options.MaxPortConcurrency,
                CancellationToken = ct
            }, async (port, token) =>
            {
                var portResult = await ScanPortAsync(host, port, token);
                if (portResult.IsOpen)
                    openPorts.Add(portResult);
            });
        }
        catch (OperationCanceledException) { }
        catch (Exception) { }

        result.OpenPorts = openPorts.OrderBy(p => p.Port).ToList();
        return result;
    }

    private async Task<PortResult> ScanPortAsync(string host, int port, CancellationToken ct)
    {
        var result = new PortResult { Port = port };

        try
        {
            // Resolve address family dynamically to support both IPv4 and IPv6
            var addressFamily = AddressFamily.InterNetwork;
            try
            {
                if (IPAddress.TryParse(host, out var ip))
                {
                    addressFamily = ip.AddressFamily;
                }
                else
                {
                    // For hostnames, try to resolve and get the address family
                    var addresses = await Dns.GetHostAddressesAsync(host, ct);
                    if (addresses.Length > 0)
                    {
                        addressFamily = addresses[0].AddressFamily;
                    }
                }
            }
            catch
            {
                // Fall back to IPv4 if resolution fails
                addressFamily = AddressFamily.InterNetwork;
            }

            using var socket = new Socket(addressFamily, SocketType.Stream, ProtocolType.Tcp);
            socket.Blocking = false;

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(_options.PortTimeout);

            await socket.ConnectAsync(host, port, cts.Token);
            result.IsOpen = true;
            result.Service = GetServiceName(port);

            // Quick banner grab if enabled
            if (_options.GrabBanners && socket.Connected)
            {
                result.Banner = await GrabBannerAsync(socket, port, ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (SocketException) { }
        catch { }

        return result;
    }

    private async Task<string> GrabBannerAsync(Socket socket, int port, CancellationToken ct)
    {
        try
        {
            socket.ReceiveTimeout = 500;
            socket.SendTimeout = 500;

            // Send HTTP probe for web ports
            if (port is 80 or 8080 or 8000 or 443 or 8443)
            {
                var probe = "HEAD / HTTP/1.0\r\nHost: x\r\n\r\n"u8.ToArray();
                await socket.SendAsync(probe, SocketFlags.None, ct);
            }

            await Task.Delay(100, ct);

            if (socket.Available > 0)
            {
                var buffer = new byte[512];
                var received = await socket.ReceiveAsync(buffer, SocketFlags.None, ct);
                if (received > 0)
                {
                    var banner = System.Text.Encoding.UTF8.GetString(buffer, 0, Math.Min(received, 200));
                    return CleanBanner(banner);
                }
            }
        }
        catch { }
        return string.Empty;
    }

    private static string CleanBanner(string s) =>
        new(s.Where(c => c >= 32 && c < 127).Take(150).ToArray());

    private static List<string> ParseTarget(string target)
    {
        var hosts = new List<string>();
        
        if (string.IsNullOrWhiteSpace(target))
            return hosts;
            
        target = target.Trim();

        try
        {
            // CIDR: 192.168.1.0/24
            if (target.Contains('/'))
            {
                var parts = target.Split('/');
                if (parts.Length == 2 && IPAddress.TryParse(parts[0], out var baseIp) && 
                    int.TryParse(parts[1], out var prefix) && prefix >= 0 && prefix <= 32)
                {
                    var bytes = baseIp.GetAddressBytes();
                    if (bytes.Length == 4) // Only IPv4 for CIDR
                    {
                        var ip = (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
                        var hostBits = 32 - prefix;
                        var count = 1u << hostBits;
                        var network = ip & (uint.MaxValue << hostBits);

                        var start = prefix < 31 ? 1u : 0u;
                        var end = prefix < 31 ? count - 1 : count;

                        for (var i = start; i < end && hosts.Count < 65536; i++)
                        {
                            var h = network + i;
                            hosts.Add($"{h >> 24}.{(h >> 16) & 0xFF}.{(h >> 8) & 0xFF}.{h & 0xFF}");
                        }
                    }
                }
            }
            // Range: 192.168.1.1-254
            else if (System.Text.RegularExpressions.Regex.IsMatch(target, @"^\d+\.\d+\.\d+\.(\d+)-(\d+)$"))
            {
                var match = System.Text.RegularExpressions.Regex.Match(target, @"^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$");
                if (match.Success)
                {
                    var baseIp = match.Groups[1].Value;
                    if (int.TryParse(match.Groups[2].Value, out var start) && 
                        int.TryParse(match.Groups[3].Value, out var end))
                    {
                        for (var i = Math.Max(0, start); i <= Math.Min(255, end); i++)
                            hosts.Add($"{baseIp}.{i}");
                    }
                }
            }
            // Single IP or hostname
            else if (!string.IsNullOrWhiteSpace(target))
            {
                hosts.Add(target);
            }
        }
        catch
        {
            // If parsing fails completely, try to use the target as-is
            if (hosts.Count == 0 && !string.IsNullOrWhiteSpace(target))
                hosts.Add(target);
        }

        return hosts;
    }

    private static string GetServiceName(int port) => port switch
    {
        21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 => "SMTP", 53 => "DNS",
        80 => "HTTP", 110 => "POP3", 143 => "IMAP", 443 => "HTTPS", 445 => "SMB",
        993 => "IMAPS", 995 => "POP3S", 1433 => "MSSQL", 3306 => "MySQL",
        3389 => "RDP", 5432 => "PostgreSQL", 5900 => "VNC", 6379 => "Redis",
        8080 => "HTTP-Proxy", 8443 => "HTTPS-Alt", 27017 => "MongoDB",
        _ => ""
    };
}

public class ScanOptions
{
    public List<int> Ports { get; set; } = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017];
    public int PortTimeout { get; set; } = 300;
    public int PingTimeout { get; set; } = 500;
    public int MaxHostConcurrency { get; set; } = 50;
    public int MaxPortConcurrency { get; set; } = 100;
    public bool PingFirst { get; set; } = true;
    public bool SkipOfflineHosts { get; set; } = false;
    public bool GrabBanners { get; set; } = false;
}

public class ScanResult
{
    public string Host { get; set; } = "";
    public bool IsOnline { get; set; }
    public long Latency { get; set; }
    public List<PortResult> OpenPorts { get; set; } = new();
}

public class PortResult
{
    public int Port { get; set; }
    public bool IsOpen { get; set; }
    public string Service { get; set; } = "";
    public string Banner { get; set; } = "";
}

public class ScanProgress
{
    public int ScannedHosts { get; set; }
    public int TotalHosts { get; set; }
    public string CurrentHost { get; set; } = "";
    public double Percent { get; set; }
}

public class HostResult
{
    public string Host { get; set; } = "";
    public ScanResult Result { get; set; } = new();
}

