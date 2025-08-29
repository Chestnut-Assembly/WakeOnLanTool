using Spectre.Console;
using Spectre.Console.Cli;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Rule = Spectre.Console.Rule;
using ValidationResult = Spectre.Console.ValidationResult;

namespace WakeCli;

public sealed class Program
{
    public static async Task<int> Main(string[] args)
    {
        var app = new CommandApp();
        app.Configure(config =>
        {
            config.SetApplicationName("wakecli");
            config.AddCommand<WakeCommand>("wake")
                  .WithDescription("Send Wake-on-LAN (magic packets) to targets from a config file.");
            config.AddCommand<QueryCommand>("query")
                  .WithDescription("Ping targets and show which are online.");
        });

        try
        {
            return await app.RunAsync(args);
        }
        catch (CommandParseException cpe)
        {
            AnsiConsole.MarkupLine($"[red]Error:[/] {Markup.Escape(cpe.Message)}");
            return 2;
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Unhandled error:[/] {Markup.Escape(ex.ToString())}");
            return 1;
        }
    }
}

/* ============================= SETTINGS ============================= */

public class CommonSettings : CommandSettings
{
    [CommandOption("-c|--config <PATH>")]
    [Description("Path to targets file (default: ./targets.txt)")]
    public string ConfigPath { get; set; } = @"C:\TEMP\targets.txt";

    public override ValidationResult Validate()
    {
        if (string.IsNullOrWhiteSpace(ConfigPath))
            return ValidationResult.Error("Config path must be provided.");
        return ValidationResult.Success();
    }
}

public sealed class WakeSettings : CommonSettings
{
    [CommandOption("-b|--broadcast <IP>")]
    [Description("Broadcast address (default: 255.255.255.255)")]
    public string Broadcast { get; set; } = "255.255.255.255";

    [CommandOption("-p|--port <PORT>")]
    [Description("UDP port for WOL (7 or 9 are common). Default: 9")]
    public int Port { get; set; } = 9;

    [CommandOption("-r|--repeat <COUNT>")]
    [Description("Magic packets to send per target. Default: 3")]
    public int Repeat { get; set; } = 3;

    [CommandOption("-i|--interval-ms <MS>")]
    [Description("Delay between repeated packets in ms. Default: 100")]
    public int IntervalMs { get; set; } = 100;

    [CommandOption("--parallelism <N>")]
    [Description("Max degree of parallelism. Default: min(8, CPU)")]
    public int Parallelism { get; set; } = Math.Min(Environment.ProcessorCount, 8);

    [CommandOption("--try-arp")]
    [Description("If only IP is present, try to resolve MAC via ARP first. Default: true")]
    public bool TryArp { get; set; } = true;

    public override ValidationResult Validate()
    {
        var vr = base.Validate();
        if (!vr.Successful)
            return vr;

        if (!IPAddress.TryParse(Broadcast, out _))
            return ValidationResult.Error("Invalid --broadcast IP address.");
        if (Port is < 1 or > 65535) return ValidationResult.Error("Port must be between 1 and 65535.");
        if (Repeat < 1) return ValidationResult.Error("--repeat must be >= 1.");
        if (IntervalMs < 0) return ValidationResult.Error("--interval-ms must be >= 0.");
        if (Parallelism < 1) return ValidationResult.Error("--parallelism must be >= 1.");

        return ValidationResult.Success();
    }
}

public sealed class QuerySettings : CommonSettings
{
    [CommandOption("-t|--timeout-ms <MS>")]
    [Description("Ping timeout per attempt (ms). Default: 600")]
    public int TimeoutMs { get; set; } = 600;

    [CommandOption("-n|--count <COUNT>")]
    [Description("Number of pings per IP. Default: 1")]
    public int Count { get; set; } = 1;

    [CommandOption("--parallelism <N>")]
    [Description("Max degree of parallelism. Default: min(16, CPU)")]
    public int Parallelism { get; set; } = Math.Min(Environment.ProcessorCount, 16);

    [CommandOption("--try-arp")]
    [Description("If only MAC is present, try to discover IP from ARP/neighbors first. Default: true")]
    public bool TryArp { get; set; } = true;

    public override ValidationResult Validate()
    {
        var vr = base.Validate();
        if (!vr.Successful)
            return vr;

        if (TimeoutMs < 1) return ValidationResult.Error("--timeout-ms must be >= 1.");
        if (Count < 1) return ValidationResult.Error("--count must be >= 1.");
        if (Parallelism < 1) return ValidationResult.Error("--parallelism must be >= 1.");
        return ValidationResult.Success();
    }
}

/* ============================= COMMANDS ============================= */

public sealed class WakeCommand : AsyncCommand<WakeSettings>
{
    public override async Task<int> ExecuteAsync(CommandContext context, WakeSettings settings)
    {
        var broadcast = IPAddress.Parse(settings.Broadcast);
        var configFile = new FileInfo(settings.ConfigPath);

        var (targets, problems) = ConfigLoader.Load(configFile);
        SpectreUi.PrintProblems(problems);

        if (settings.TryArp)
        {
            var needMac = targets.Where(t => t.Mac is null && t.Ip is not null).ToList();
            if (needMac.Count > 0)
            {
                await AnsiConsole.Status()
                    .Spinner(Spinner.Known.Dots)
                    .StartAsync($"Attempting ARP resolution for {needMac.Count} target(s)...", async _ =>
                    {
                        await ArpHelper.TryPopulateMacsFromArpAsync(needMac);
                    });
            }
        }

        var results = new ConcurrentBag<SpectreUi.Row>();
        int ok = 0, fail = 0, skip = 0;
        var swTotal = Stopwatch.StartNew();

        await Parallel.ForEachAsync(targets, new ParallelOptions { MaxDegreeOfParallelism = settings.Parallelism }, async (t, _) =>
        {
            var sw = Stopwatch.StartNew();

            if (t.Mac is null)
            {
                results.Add(SpectreUi.Row.Fail("SKIP (no MAC)", t, sw.ElapsedMilliseconds));
                Interlocked.Increment(ref skip);
                return;
            }

            try
            {
                await WolSender.SendAsync(t.Mac, broadcast, settings.Port, settings.Repeat, settings.IntervalMs);
                results.Add(SpectreUi.Row.Ok("Sent", t, sw.ElapsedMilliseconds));
                Interlocked.Increment(ref ok);
            }
            catch (Exception ex)
            {
                results.Add(SpectreUi.Row.Fail(ex.GetType().Name, t, sw.ElapsedMilliseconds, ex.Message));
                Interlocked.Increment(ref fail);
            }
        });

        swTotal.Stop();

        SpectreUi.RenderResults(
            "Wake Results",
            results.OrderBy(r => r.Label ?? "~").ThenBy(r => r.Ip ?? string.Empty),
            $"OK={ok}, Failed={fail}, Skipped={skip}. Total [bold]{swTotal.Elapsed.TotalMilliseconds:F0} ms[/].");

        return fail == 0 ? 0 : 1;
    }
}

public sealed class QueryCommand : AsyncCommand<QuerySettings>
{
    public override async Task<int> ExecuteAsync(CommandContext context, QuerySettings settings)
    {
        var configFile = new FileInfo(settings.ConfigPath);

        var (targets, problems) = ConfigLoader.Load(configFile);
        SpectreUi.PrintProblems(problems);

        if (settings.TryArp)
        {
            var needIp = targets.Where(t => t.Ip is null && t.Mac is not null).ToList();
            if (needIp.Count > 0)
            {
                await AnsiConsole.Status()
                    .Spinner(Spinner.Known.Dots)
                    .StartAsync($"Attempting ARP/neighbor discovery for {needIp.Count} target(s)...", async _ =>
                    {
                        await ArpHelper.TryPopulateIpsFromArpAsync(needIp);
                    });
            }
        }

        var results = new ConcurrentBag<SpectreUi.Row>();
        int up = 0, down = 0, unknown = 0;
        var swTotal = Stopwatch.StartNew();

        await Parallel.ForEachAsync(targets, new ParallelOptions { MaxDegreeOfParallelism = settings.Parallelism }, async (t, _) =>
        {
            var sw = Stopwatch.StartNew();

            if (t.Ip is null)
            {
                results.Add(SpectreUi.Row.Fail("Unknown (no IP)", t, sw.ElapsedMilliseconds));
                Interlocked.Increment(ref unknown);
                return;
            }

            try
            {
                var isUp = await Pinger.PingAsync(t.Ip, settings.TimeoutMs, settings.Count);
                if (isUp)
                {
                    results.Add(SpectreUi.Row.Ok("Online", t, sw.ElapsedMilliseconds));
                    Interlocked.Increment(ref up);
                }
                else
                {
                    results.Add(SpectreUi.Row.Fail("No reply", t, sw.ElapsedMilliseconds));
                    Interlocked.Increment(ref down);
                }
            }
            catch (Exception ex)
            {
                results.Add(SpectreUi.Row.Fail(ex.GetType().Name, t, sw.ElapsedMilliseconds, ex.Message));
                Interlocked.Increment(ref down);
            }
        });

        swTotal.Stop();

        SpectreUi.RenderResults(
            "Query Results",
            results.OrderBy(r => r.Label ?? "~").ThenBy(r => r.Ip ?? string.Empty),
            $"Online={up}, Offline={down}, Unknown={unknown}. Total [bold]{swTotal.Elapsed.TotalMilliseconds:F0} ms[/].");

        return down == 0 ? 0 : 1;
    }
}

/* ============================= DOMAIN ============================= */

internal sealed class Target
{
    public string? Label { get; set; }
    public IPAddress? Ip { get; set; }
    public PhysicalAddress? Mac { get; set; }
    public string Raw { get; }

    public Target(string? label, IPAddress? ip, PhysicalAddress? mac, string raw)
    {
        Label = label;
        Ip = ip;
        Mac = mac;
        Raw = raw;
    }
}

internal static class ConfigLoader
{
    private static readonly Regex MacRegex = new(@"(?i)\b([0-9A-F]{2}([-:])){5}[0-9A-F]{2}\b", RegexOptions.Compiled);

    public static (List<Target> targets, List<string> problems) Load(FileInfo path)
    {
        var targets = new List<Target>();
        var problems = new List<string>();

        if (!path.Exists)
        {
            problems.Add($"Config file not found: {path.FullName}");
            return (targets, problems);
        }

        int lineNo = 0;
        foreach (var raw in File.ReadAllLines(path.FullName))
        {
            lineNo++;
            var line = raw.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#")) continue;

            var parts = line.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            string? label = null;
            IPAddress? ip = null;
            PhysicalAddress? mac = null;

            foreach (var token in parts.Select(p => p.Trim()))
            {
                if (IPAddress.TryParse(token, out var ipParsed))
                {
                    ip = ipParsed;
                    continue;
                }

                var macMatch = MacRegex.Match(token);
                if (macMatch.Success)
                {
                    mac = PhysicalAddress.Parse(macMatch.Value.Replace(":", "").Replace("-", ""));
                    continue;
                }

                label ??= token;
            }

            if (parts.Length == 1 && label == null && ip == null && mac == null)
            {
                var token = parts[0];
                if (IPAddress.TryParse(token, out var ipOnly)) ip = ipOnly;
                else if (MacRegex.IsMatch(token))
                    mac = PhysicalAddress.Parse(MacRegex.Match(token).Value.Replace(":", "").Replace("-", ""));
                else
                    label = token;
            }

            if (ip == null && mac == null && label != null)
            {
                problems.Add($"Line {lineNo}: '{line}' — no IP or MAC found; ignored.");
                continue;
            }

            targets.Add(new Target(label, ip, mac, line));
        }

        return (targets, problems);
    }
}

/* ============================= NET HELPERS ============================= */

internal static class WolSender
{
    public static async Task SendAsync(PhysicalAddress mac, IPAddress broadcast, int port, int repeat, int intervalMs)
    {
        var packet = BuildMagicPacket(mac);
        using var udp = new UdpClient { EnableBroadcast = true };
        var endpoint = new IPEndPoint(broadcast, port);

        for (int i = 0; i < repeat; i++)
        {
            await udp.SendAsync(packet, packet.Length, endpoint);
            if (i + 1 < repeat && intervalMs > 0)
                await Task.Delay(intervalMs);
        }
    }

    private static byte[] BuildMagicPacket(PhysicalAddress mac)
    {
        var macBytes = mac.GetAddressBytes();
        if (macBytes.Length != 6) throw new ArgumentException("MAC must be 6 bytes.", nameof(mac));

        var packet = new byte[6 + 16 * 6];
        for (int i = 0; i < 6; i++) packet[i] = 0xFF;
        for (int i = 0; i < 16; i++) Buffer.BlockCopy(macBytes, 0, packet, 6 + i * 6, 6);
        return packet;
    }
}

internal static class Pinger
{
    public static async Task<bool> PingAsync(IPAddress ip, int timeoutMs, int count)
    {
        using var p = new Ping();
        byte[] buffer = Encoding.ASCII.GetBytes("WOLPING");
        for (int i = 0; i < count; i++)
        {
            var reply = await p.SendPingAsync(ip, timeoutMs, buffer);
            if (reply.Status == IPStatus.Success) return true;
        }
        return false;
    }
}

internal static class ArpHelper
{
    public static async Task TryPopulateMacsFromArpAsync(List<Target> targets)
    {
        // Nudge ARP cache by pinging known IPs
        await Parallel.ForEachAsync(targets, new ParallelOptions { MaxDegreeOfParallelism = Math.Min(16, Environment.ProcessorCount) }, async (t, _) =>
        {
            if (t.Ip is null) return;
            try { await Pinger.PingAsync(t.Ip, 200, 1); } catch { /* ignore */ }
        });

        var table = await ReadNeighborsAsync();

        foreach (var t in targets)
        {
            if (t.Ip is null) continue;
            var found = table.FirstOrDefault(n => n.ip.Equals(t.Ip));
            if (found.mac is not null) t.Mac = found.mac;
        }
    }

    public static async Task TryPopulateIpsFromArpAsync(List<Target> targets)
    {
        var table = await ReadNeighborsAsync();

        foreach (var t in targets)
        {
            if (t.Mac is null) continue;
            var found = table.FirstOrDefault(n => SpectreUi.PhysicalAddressEquals(n.mac, t.Mac));
            if (found.ip is not null) t.Ip = found.ip;
        }
    }

    public static async Task<List<(IPAddress ip, PhysicalAddress? mac)>> ReadNeighborsAsync()
    {
        if (OperatingSystem.IsWindows())
        {
            var (ok, output) = await Run("arp", "-a");
            if (!ok) return new();
            return ParseArpWindows(output);
        }
        else if (OperatingSystem.IsLinux())
        {
            var (ok, output) = await Run("ip", "neigh show");
            if (ok) return ParseIpNeigh(output);

            (ok, output) = await Run("arp", "-an");
            if (ok) return ParseArpPosix(output);

            return new();
        }
        else // macOS and others
        {
            var (ok, output) = await Run("arp", "-an");
            if (!ok) return new();
            return ParseArpPosix(output);
        }
    }

    private static List<(IPAddress ip, PhysicalAddress? mac)> ParseArpWindows(string text)
    {
        var list = new List<(IPAddress ip, PhysicalAddress? mac)>();
        // "  192.168.1.1          00-11-22-33-44-55     dynamic"
        var rx = new Regex(@"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f\-]{17}|(?:\w+))", RegexOptions.IgnoreCase | RegexOptions.Multiline);
        foreach (Match m in rx.Matches(text))
        {
            if (!IPAddress.TryParse(m.Groups[1].Value, out var ip)) continue;
            var macStr = m.Groups[2].Value;
            if (Regex.IsMatch(macStr, @"^[0-9a-f\-]{17}$", RegexOptions.IgnoreCase))
                list.Add((ip, PhysicalAddress.Parse(macStr.Replace("-", ""))));
            else list.Add((ip, null));
        }
        return list;
    }

    private static List<(IPAddress ip, PhysicalAddress? mac)> ParseArpPosix(string text)
    {
        var list = new List<(IPAddress ip, PhysicalAddress? mac)>();
        // "? (192.168.1.10) at aa:bb:cc:dd:ee:ff on en0 ..."
        var rx = new Regex(@"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-f:]{17}|<incomplete>)", RegexOptions.IgnoreCase);
        foreach (Match m in rx.Matches(text))
        {
            if (!IPAddress.TryParse(m.Groups[1].Value, out var ip)) continue;
            var macStr = m.Groups[2].Value;
            if (!macStr.Contains("<incomplete>", StringComparison.OrdinalIgnoreCase))
                list.Add((ip, PhysicalAddress.Parse(macStr.Replace(":", ""))));
            else list.Add((ip, null));
        }
        return list;
    }

    private static List<(IPAddress ip, PhysicalAddress? mac)> ParseIpNeigh(string text)
    {
        var list = new List<(IPAddress ip, PhysicalAddress? mac)>();
        // "192.168.1.50 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        var rx = new Regex(@"(\d{1,3}(?:\.\d{1,3}){3}).*?lladdr\s+([0-9a-f:]{17})", RegexOptions.IgnoreCase);
        foreach (Match m in rx.Matches(text))
        {
            if (!IPAddress.TryParse(m.Groups[1].Value, out var ip)) continue;
            var mac = PhysicalAddress.Parse(m.Groups[2].Value.Replace(":", ""));
            list.Add((ip, mac));
        }
        return list;
    }

    private static async Task<(bool ok, string output)> Run(string fileName, string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi)!;
            var output = await p.StandardOutput.ReadToEndAsync();
            var _ = await p.StandardError.ReadToEndAsync();
            await p.WaitForExitAsync();
            return (p.ExitCode == 0, output);
        }
        catch
        {
            return (false, "");
        }
    }
}

/* ============================= UI HELPERS ============================= */

internal static class SpectreUi
{
    public record Row(bool Success, string Status, string? Label, string? Ip, string? Mac, long Ms, string? Message)
    {
        public static Row Ok(string status, Target t, long ms) =>
            new(true, status, t.Label, t.Ip?.ToString(), FormatMac(t.Mac), ms, null);

        public static Row Fail(string status, Target t, long ms, string? msg = null) =>
            new(false, status, t.Label, t.Ip?.ToString(), FormatMac(t.Mac), ms, msg);
    }

    public static void PrintProblems(IEnumerable<string> problems)
    {
        foreach (var p in problems)
        {
            AnsiConsole.MarkupLine($"[yellow]![/] {Markup.Escape(p)}");
        }
        if (problems.Any())
            AnsiConsole.WriteLine();
    }

    public static void RenderResults(string title, IEnumerable<Row> rows, string summary)
    {
        var rule = new Rule($" [bold]{title}[/] ");
        rule.RuleStyle(Style.Parse("grey"));
        rule.Justification = Justify.Center;
        AnsiConsole.Write(rule);

        var table = new Table()
            .Expand()
            .Border(TableBorder.Rounded)
            .BorderColor(Spectre.Console.Color.Grey)
            .AddColumn(new TableColumn("[bold]Status[/]").Centered())
            .AddColumn(new TableColumn("[bold]Label[/]"))
            .AddColumn(new TableColumn("[bold]IP[/]"))
            .AddColumn(new TableColumn("[bold]MAC[/]"))
            .AddColumn(new TableColumn("[bold]Time[/]").Centered())
            .AddColumn(new TableColumn("[bold]Message[/]"));

        foreach (var r in rows)
        {
            var glyph = r.Success ? "[green]✅[/]" : "[red]❌[/]";
            var msg = r.Message is null ? r.Status : $"{r.Status} — {r.Message}";
            table.AddRow(
                glyph,
                Markup.Escape(r.Label ?? "-"),
                Markup.Escape(r.Ip ?? "-"),
                Markup.Escape(r.Mac ?? "-"),
                $"{r.Ms} ms",
                Markup.Escape(msg)
            );
        }

        AnsiConsole.Write(table);
        AnsiConsole.Write(new Rule().RuleStyle(Style.Parse("grey")));
        AnsiConsole.MarkupLine(summary);
        AnsiConsole.WriteLine();
    }

    public static bool PhysicalAddressEquals(PhysicalAddress a, PhysicalAddress b)
        => a.GetAddressBytes().AsSpan().SequenceEqual(b.GetAddressBytes());

    public static string FormatMac(PhysicalAddress? mac)
    {
        if (mac is null) return "-";
        var s = mac.ToString().ToUpperInvariant(); // "AABBCCDDEEFF"
        if (s.Length != 12) return s;
        return string.Join(":", Enumerable.Range(0, 6).Select(i => s.Substring(i * 2, 2)));
    }
}
