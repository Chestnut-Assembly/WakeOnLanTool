using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Spectre.Console;
using Spectre.Console.Cli;

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

            // New: preflight / lint (same command, two entry points)
            config.AddCommand<PreflightCommand>("preflight")
                  .WithDescription("Validate targets file and environment. Fails fast with errors before showtime.");

            config.AddCommand<PreflightCommand>("lint")
                  .WithDescription("Alias of 'preflight'. Validate targets file and environment.");
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
    public string ConfigPath { get; set; } = "targets.txt";

    public override ValidationResult Validate()
    {
        if (string.IsNullOrWhiteSpace(ConfigPath))
            return ValidationResult.Error("Config path must be provided.");
        return ValidationResult.Success();
    }
}

// --- Replace WakeSettings with this version (adds --interface, removes DryRun) ---
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

    [CommandOption("--interface <IP>")]
    [Description("Source/local IPv4 address to bind when sending broadcast (useful on multi-homed hosts).")]
    public string? InterfaceIp { get; set; }

    [CommandOption("--backoff-mult <X>")]
    [Description("Backoff multiplier for gaps between WOL packets (e.g., 1.0=no backoff, 1.5=exponential). Default: 1.0")]
    public double BackoffMult { get; set; } = 1.0;

    [CommandOption("--jitter-pct <0-1>")]
    [Description("Jitter percentage applied to each inter-packet delay (0..1). Default: 0")]
    public double JitterPct { get; set; } = 0.0;

    public override ValidationResult Validate()
    {
        var vr = base.Validate();
        if (!vr.Successful) return vr;

        if (!IPAddress.TryParse(Broadcast, out _))
            return ValidationResult.Error("Invalid --broadcast IP address.");
        if (Port is < 1 or > 65535) return ValidationResult.Error("Port must be between 1 and 65535.");
        if (Repeat < 1) return ValidationResult.Error("--repeat must be >= 1.");
        if (IntervalMs < 0) return ValidationResult.Error("--interval-ms must be >= 0.");
        if (Parallelism < 1) return ValidationResult.Error("--parallelism must be >= 1.");

        if (!string.IsNullOrWhiteSpace(InterfaceIp))
        {
            if (!IPAddress.TryParse(InterfaceIp, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
                return ValidationResult.Error("--interface must be a valid IPv4 address.");
            if (ip.Equals(IPAddress.Any) || IPAddress.IsLoopback(ip))
                return ValidationResult.Error("--interface must be a non-loopback, bound local IPv4.");
        }

        if (BackoffMult < 1.0) return ValidationResult.Error("--backoff-mult must be >= 1.0");
        if (JitterPct is < 0.0 or > 1.0) return ValidationResult.Error("--jitter-pct must be between 0 and 1");
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

    [CommandOption("-d|--delay-ms <MS>")]
    [Description("Base delay between ping attempts. Default: 100")]
    public int DelayMs { get; set; } = 100;

    [CommandOption("--backoff-mult <X>")]
    [Description("Backoff multiplier for gaps between ping attempts (e.g., 1.0=no backoff, 1.5=exponential). Default: 1.5")]
    public double BackoffMult { get; set; } = 1.5;

    [CommandOption("--jitter-pct <0-1>")]
    [Description("Jitter percentage applied to inter-attempt delays (0..1). Default: 0.2")]
    public double JitterPct { get; set; } = 0.2;

    public override ValidationResult Validate()
    {
        var vr = base.Validate();
        if (!vr.Successful) return vr;

        if (TimeoutMs < 1) return ValidationResult.Error("--timeout-ms must be >= 1.");
        if (Count < 1) return ValidationResult.Error("--count must be >= 1.");
        if (Parallelism < 1) return ValidationResult.Error("--parallelism must be >= 1.");
        if (DelayMs < 0) return ValidationResult.Error("--delay-ms must be >= 0.");
        if (BackoffMult < 1.0) return ValidationResult.Error("--backoff-mult must be >= 1.0");
        if (JitterPct is < 0.0 or > 1.0) return ValidationResult.Error("--jitter-pct must be between 0 and 1");
        return ValidationResult.Success();
    }
}

// New: Preflight settings
public sealed class PreflightSettings : CommonSettings
{
    [CommandOption("--fail-on-warn")]
    [Description("Return non-zero exit code if warnings are present (in addition to errors).")]
    public bool FailOnWarning { get; set; } = false;

    [CommandOption("--show-ok")]
    [Description("Also list OK/clean entries (by default only findings are printed).")]
    public bool ShowOk { get; set; } = false;

    [CommandOption("--env-checks")]
    [Description("Run environment checks (arp/ip tools, OS support) and report issues. Default: true")]
    public bool EnvChecks { get; set; } = true;

    // NEW: Broadcast heuristics options
    [CommandOption("--assume-prefix <CIDR>")]
    [Description("CIDR prefix length used to group IPs into subnets for broadcast checks. Default: 24")]
    public int AssumePrefix { get; set; } = 24;

    [CommandOption("--planned-broadcast <IP>")]
    [Description("Broadcast address you plan to use at runtime (e.g., 192.168.10.255 or 255.255.255.255).")]
    public string? PlannedBroadcast { get; set; }

    [CommandOption("--strict-broadcast")]
    [Description("Treat broadcast coverage problems as errors instead of warnings.")]
    public bool StrictBroadcast { get; set; } = false;

    public override ValidationResult Validate()
    {
        var vr = base.Validate();
        if (!vr.Successful) return vr;

        if (AssumePrefix is < 8 or > 30)
            return ValidationResult.Error("--assume-prefix must be between 8 and 30.");

        if (!string.IsNullOrWhiteSpace(PlannedBroadcast) && !IPAddress.TryParse(PlannedBroadcast, out _))
            return ValidationResult.Error("Invalid --planned-broadcast IP address.");

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
        IPAddress? sourceIp = null;

        if (!string.IsNullOrWhiteSpace(settings.InterfaceIp))
            sourceIp = IPAddress.Parse(settings.InterfaceIp!);

        var (targets, problems) = ConfigLoader.Load(configFile);
        SpectreUi.PrintProblems(problems.Select(p => p.ToString()));

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
                await WolSender.SendAsync(t.Mac, broadcast, settings.Port, settings.Repeat, settings.IntervalMs, sourceIp, settings.BackoffMult, settings.JitterPct);
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
        SpectreUi.PrintProblems(problems.Select(p => p.ToString()));

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
                var isUp = await Pinger.PingAsync(t.Ip, settings.TimeoutMs, settings.Count, settings.DelayMs, settings.BackoffMult, settings.JitterPct);
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

// New: Preflight / Lint command
public sealed class PreflightCommand : AsyncCommand<PreflightSettings>
{
    public override async Task<int> ExecuteAsync(CommandContext context, PreflightSettings settings)
    {
        var configFile = new FileInfo(settings.ConfigPath);

        var (targets, parseProblems) = ConfigLoader.Load(configFile);

        var findings = new List<PreflightIssue>();

        foreach (var p in parseProblems)
        {
            findings.Add(new PreflightIssue(
                Severity.Error, p.LineNo, null, null, null,
                p.Message, Suggestion: "Fix or remove this line."));
        }

        findings.AddRange(ConfigValidator.Validate(targets));

        if (settings.EnvChecks)
        {
            findings.AddRange(await EnvironmentChecks.RunAsync());
        }

        // NEW: Broadcast heuristics
        IPAddress? planned = null;
        if (!string.IsNullOrWhiteSpace(settings.PlannedBroadcast))
            planned = IPAddress.Parse(settings.PlannedBroadcast!);

        findings.AddRange(BroadcastHeuristics.Analyze(
            targets,
            settings.AssumePrefix,
            planned,
            settings.StrictBroadcast));

        var errorCount = findings.Count(f => f.Severity == Severity.Error);
        var warnCount = findings.Count(f => f.Severity == Severity.Warning);
        var okRows = ConfigValidator.IdentifyOkRows(targets).ToList();

        SpectreUi.RenderPreflight(findings, okRows, settings.ShowOk, targets.Count);

        if (errorCount > 0) return 1;
        if (settings.FailOnWarning && warnCount > 0) return 1;
        return 0;
    }
}

internal static class BroadcastHeuristics
{
    public static IEnumerable<PreflightIssue> Analyze(
        IEnumerable<Target> targets,
        int prefixLen,
        IPAddress? plannedBroadcast,
        bool strict)
    {
        var list = new List<PreflightIssue>();

        var ipv4s = targets
            .Where(t => t.Ip is not null && t.Ip.AddressFamily == AddressFamily.InterNetwork)
            .Select(t => t.Ip!)
            .ToList();

        if (ipv4s.Count == 0)
        {
            list.Add(new PreflightIssue(
                Severity.Info, null, null, null, null,
                "No IPv4 addresses found in configuration for broadcast analysis.",
                "Add device IPs to enable broadcast coverage checks."));
            return list;
        }

        uint mask = prefixLen == 0 ? 0u : 0xFFFFFFFFu << (32 - prefixLen);
        var groups = ipv4s.GroupBy(ip => IpToUInt(ip) & mask)
                          .Select(g => new
                          {
                              Network = g.Key,
                              Count = g.Count()
                          })
                          .ToList();

        var recommendedBcasts = groups
            .Select(g => UIntToIp(g.Network | ~mask))
            .ToList();

        // Info row: show detected subnets and sizes
        var summary = string.Join(", ",
            groups.Select(g => $"{UIntToIp(g.Network)}/{prefixLen} ({g.Count} host{(g.Count == 1 ? "" : "s")})"));
        list.Add(new PreflightIssue(
            Severity.Info, null, null, null, null,
            $"Detected subnets (/{prefixLen}): {summary}",
            $"Recommended directed broadcasts: {string.Join(", ", recommendedBcasts.Select(ip => ip.ToString()))}"));

        if (groups.Count > 1)
        {
            list.Add(new PreflightIssue(
                Severity.Warning, null, null, null, null,
                $"Targets span multiple /{prefixLen} subnets ({groups.Count}).",
                $"Use per-VLAN directed broadcasts: {string.Join(", ", recommendedBcasts.Select(ip => ip.ToString()))} or run 'wake' once per subnet."));

            // Planned broadcast evaluation across multiple subnets
            if (plannedBroadcast is not null)
            {
                bool isGlobal = plannedBroadcast.Equals(IPAddress.Broadcast);
                bool matchesAny = recommendedBcasts.Any(bc => bc.Equals(plannedBroadcast));

                if (isGlobal)
                {
                    list.Add(new PreflightIssue(
                        strict ? Severity.Error : Severity.Warning, null, null, null, null,
                        "Planned broadcast is 255.255.255.255 while targets span multiple subnets.",
                        "Routers typically block limited broadcast across VLANs; use per-VLAN directed broadcasts."));
                }
                else if (!matchesAny)
                {
                    list.Add(new PreflightIssue(
                        strict ? Severity.Error : Severity.Warning, null, null, null, null,
                        $"Planned broadcast {plannedBroadcast} does not cover any detected /{prefixLen} subnet.",
                        $"Use one of: {string.Join(", ", recommendedBcasts.Select(ip => ip.ToString()))}"));
                }
                else
                {
                    list.Add(new PreflightIssue(
                        Severity.Warning, null, null, null, null,
                        $"Planned broadcast {plannedBroadcast} covers only one of {groups.Count} subnets.",
                        $"Also send to: {string.Join(", ", recommendedBcasts.Where(bc => !bc.Equals(plannedBroadcast)).Select(ip => ip.ToString()))}"));
                }
            }
        }
        else
        {
            // Single subnet guidance
            var onlyRec = recommendedBcasts[0];
            list.Add(new PreflightIssue(
                Severity.Info, null, null, null, null,
                $"All targets appear to be within one /{prefixLen} subnet.",
                $"Recommended directed broadcast: {onlyRec}"));

            if (plannedBroadcast is not null &&
                !plannedBroadcast.Equals(IPAddress.Broadcast) &&
                !plannedBroadcast.Equals(onlyRec))
            {
                list.Add(new PreflightIssue(
                    Severity.Warning, null, null, null, null,
                    $"Planned broadcast {plannedBroadcast} does not match the detected subnet’s broadcast {onlyRec}.",
                    $"Consider using {onlyRec} to avoid upstream filtering."));
            }
        }

        return list;
    }

    // ---------- helpers ----------
    private static uint IpToUInt(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        if (b.Length != 4) throw new ArgumentException("IPv4 address required.", nameof(ip));
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static IPAddress UIntToIp(uint v) =>
        new([
            (byte)((v >> 24) & 0xFF),
            (byte)((v >> 16) & 0xFF),
            (byte)((v >> 8) & 0xFF),
            (byte)(v & 0xFF)
        ]);
}



/* ============================= DOMAIN ============================= */

internal sealed class Target
{
    public int LineNo { get; }
    public string? Label { get; set; }
    public IPAddress? Ip { get; set; }
    public PhysicalAddress? Mac { get; set; }
    public string Raw { get; }

    public Target(int lineNo, string? label, IPAddress? ip, PhysicalAddress? mac, string raw)
    {
        LineNo = lineNo;
        Label = label;
        Ip = ip;
        Mac = mac;
        Raw = raw;
    }
}

internal sealed record ConfigProblem(int LineNo, string Raw, string Message)
{
    public override string ToString()
    {
        var prefix = LineNo > 0 ? $"Line {LineNo}: " : "";
        return $"{prefix}{Message}{(string.IsNullOrWhiteSpace(Raw) ? "" : $" — '{Raw}'")}";
    }
}

internal static class ConfigLoader
{
    private static readonly Regex MacRegex = new(@"(?i)\b([0-9A-F]{2}([-:])){5}[0-9A-F]{2}\b", RegexOptions.Compiled);

    public static (List<Target> targets, List<ConfigProblem> problems) Load(FileInfo path)
    {
        var targets = new List<Target>();
        var problems = new List<ConfigProblem>();

        if (!path.Exists)
        {
            problems.Add(new ConfigProblem(0, "", $"Config file not found: {path.FullName}"));
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

            foreach (var token in parts.Select(static p => p.Trim()))
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
                problems.Add(new ConfigProblem(lineNo, line, "No IP or MAC found; entry ignored."));
                continue;
            }

            targets.Add(new Target(lineNo, label, ip, mac, line));
        }

        return (targets, problems);
    }
}

/* ======================= VALIDATION (PREFLIGHT) ===================== */

internal enum Severity { Info, Warning, Error }

internal sealed record PreflightIssue(
    Severity Severity,
    int? LineNo,
    string? Label,
    IPAddress? Ip,
    PhysicalAddress? Mac,
    string Message,
    string? Suggestion = null);

internal static class ConfigValidator
{
    public static IEnumerable<PreflightIssue> Validate(IEnumerable<Target> targets)
    {
        var list = new List<PreflightIssue>();
        var tList = targets.ToList();

        // 1) Per-target checks
        foreach (var t in tList)
        {
            if (t.Ip is null && t.Mac is null)
            {
                list.Add(Issue(Severity.Error, t, "Entry has neither IP nor MAC.", "Add an IP and/or MAC or remove the line."));
                continue;
            }

            if (t.Mac is null)
                list.Add(Issue(Severity.Warning, t, "No MAC provided (Wake will be skipped).", "Add MAC to enable WOL for this device."));
            if (t.Ip is null)
                list.Add(Issue(Severity.Warning, t, "No IP provided (Query may be limited).", "Add IP to enable ping/query."));
            if (string.IsNullOrWhiteSpace(t.Label))
                list.Add(Issue(Severity.Warning, t, "No label provided.", "Add a human-friendly label for readability."));

            // IP sanity
            if (t.Ip is not null)
            {
                if (t.Ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    list.Add(Issue(Severity.Warning, t, "IPv6 address detected.", "Supply an IPv4 address for WOL/query reliability."));
                }
                else
                {
                    if (IsUnspecified(t.Ip))
                        list.Add(Issue(Severity.Error, t, "IP is 0.0.0.0 (unspecified).", "Replace with a valid host IPv4."));
                    if (IPAddress.IsLoopback(t.Ip))
                        list.Add(Issue(Severity.Warning, t, "Loopback address (127.0.0.0/8).", "Use a real host IPv4."));
                    if (IsLinkLocal169(t.Ip))
                        list.Add(Issue(Severity.Warning, t, "Link-local address (169.254.0.0/16).", "Use a DHCP/static IPv4 on your VLAN."));
                    if (IsMulticast(t.Ip))
                        list.Add(Issue(Severity.Warning, t, "Multicast address (224.0.0.0/4).", "Use a unicast host IPv4."));
                    if (t.Ip.Equals(IPAddress.Broadcast))
                        list.Add(Issue(Severity.Warning, t, "Broadcast address (255.255.255.255) used as a host IP.", "Replace with the device's IPv4."));
                }
            }

            // MAC sanity
            if (t.Mac is not null)
            {
                if (IsAllZeros(t.Mac))
                    list.Add(Issue(Severity.Error, t, "MAC address is all zeros.", "Use the device's real MAC."));
                else if (IsAllFFs(t.Mac))
                    list.Add(Issue(Severity.Error, t, "MAC address is ff:ff:ff:ff:ff:ff.", "Use the device's real MAC."));
                else if (IsMulticastMac(t.Mac))
                    list.Add(Issue(Severity.Warning, t, "MAC multicast/group bit set.", "Verify the MAC; it should be a unicast address."));
            }
        }

        // 2) Duplicate detection (MAC)
        var macGroups = tList.Where(t => t.Mac != null)
                             .GroupBy(t => NormalizeMac(t.Mac!))
                             .Where(g => g.Count() > 1);
        foreach (var g in macGroups)
        {
            var members = g.ToList();
            foreach (var t in members)
                list.Add(Issue(Severity.Error, t, $"Duplicate MAC appears {members.Count}×: {SpectreUi.FormatMac(t.Mac)}",
                    "Ensure each device has a unique MAC; remove duplicates."));
        }

        // 3) Duplicate detection (IP)
        var ipGroups = tList.Where(t => t.Ip != null)
                            .GroupBy(t => t.Ip!.ToString())
                            .Where(g => g.Count() > 1);
        foreach (var g in ipGroups)
        {
            var members = g.ToList();
            foreach (var t in members)
                list.Add(Issue(Severity.Warning, t, $"Duplicate IP appears {members.Count}×: {t.Ip}",
                    "Verify IP uniqueness or remove duplicates to avoid confusing results."));
        }

        // 4) Duplicate labels (case-insensitive)
        var labelGroups = tList.Where(t => !string.IsNullOrWhiteSpace(t.Label))
                               .GroupBy(t => t.Label!.Trim(), StringComparer.OrdinalIgnoreCase)
                               .Where(g => g.Count() > 1);
        foreach (var g in labelGroups)
        {
            var members = g.ToList();
            foreach (var t in members)
                list.Add(Issue(Severity.Warning, t, $"Duplicate label appears {members.Count}×: \"{t.Label}\"",
                    "Make labels unique to avoid operator confusion."));
        }

        // 5) Exact duplicate rows (same Label/IP/MAC)
        var rowGroups = tList.GroupBy(t => $"{t.Label}|{t.Ip}|{NormalizeMacOrNull(t.Mac)}")
                             .Where(g => g.Count() > 1);
        foreach (var g in rowGroups)
        {
            foreach (var t in g)
                list.Add(Issue(Severity.Warning, t, "Duplicate entry (same Label/IP/MAC).", "Remove the repeated line."));
        }

        return list;
    }

    public static IEnumerable<SpectreUi.OkRow> IdentifyOkRows(IEnumerable<Target> targets)
    {
        // Rows with both IP and MAC, and no duplicates -> OK
        var tList = targets.ToList();

        var dupMac = new HashSet<string>(tList.Where(t => t.Mac != null)
                                              .GroupBy(t => NormalizeMac(t.Mac!))
                                              .Where(g => g.Count() > 1)
                                              .Select(g => g.Key));
        var dupIp = new HashSet<string>(tList.Where(t => t.Ip != null)
                                             .GroupBy(t => t.Ip!.ToString())
                                             .Where(g => g.Count() > 1)
                                             .Select(g => g.Key));

        foreach (var t in tList)
        {
            var macKey = t.Mac is null ? null : NormalizeMac(t.Mac);
            var ipKey = t.Ip?.ToString();

            var ok = t.Mac != null && t.Ip != null &&
                     (macKey == null || !dupMac.Contains(macKey)) &&
                     (ipKey == null || !dupIp.Contains(ipKey));

            if (ok)
                yield return new SpectreUi.OkRow(t.LineNo, t.Label, t.Ip?.ToString(), SpectreUi.FormatMac(t.Mac));
        }
    }

    private static string NormalizeMac(PhysicalAddress mac) =>
        BitConverter.ToString(mac.GetAddressBytes()).Replace("-", "").ToUpperInvariant();

    private static string? NormalizeMacOrNull(PhysicalAddress? mac) =>
        mac is null ? null : NormalizeMac(mac);

    private static PreflightIssue Issue(Severity s, Target t, string msg, string? suggestion = null) =>
        new(s, t.LineNo, t.Label, t.Ip, t.Mac, msg, suggestion);

    // ----- helpers -----
    private static bool IsUnspecified(IPAddress ip) => ip.Equals(IPAddress.Any);
    private static bool IsLinkLocal169(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return b[0] == 169 && b[1] == 254;
    }
    private static bool IsMulticast(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return b[0] >= 224 && b[0] <= 239; // 224.0.0.0/4
    }
    private static bool IsAllZeros(PhysicalAddress mac) => mac.GetAddressBytes().All(b => b == 0x00);
    private static bool IsAllFFs(PhysicalAddress mac) => mac.GetAddressBytes().All(b => b == 0xFF);
    private static bool IsMulticastMac(PhysicalAddress mac)
    {
        var first = mac.GetAddressBytes()[0];
        return (first & 0x01) != 0; // group/multicast bit set
    }
}


/* ============================= NET HELPERS ============================= */

internal static class WolSender
{
    public static Task SendAsync(PhysicalAddress mac, IPAddress broadcast, int port, int repeat, int intervalMs)
        => SendAsync(mac, broadcast, port, repeat, intervalMs, sourceIp: null, backoffMult: 1.0, jitterPct: 0.0);

    public static Task SendAsync(PhysicalAddress mac, IPAddress broadcast, int port, int repeat, int intervalMs, IPAddress? sourceIp)
        => SendAsync(mac, broadcast, port, repeat, intervalMs, sourceIp, backoffMult: 1.0, jitterPct: 0.0);

    public static async Task SendAsync(PhysicalAddress mac, IPAddress broadcast, int port, int repeat, int intervalMs, IPAddress? sourceIp, double backoffMult, double jitterPct)
    {
        var packet = BuildMagicPacket(mac);
        UdpClient udp = sourceIp is null
            ? new UdpClient() { EnableBroadcast = true }
            : new UdpClient(new IPEndPoint(sourceIp, 0)) { EnableBroadcast = true };

        using (udp)
        {
            var endpoint = new IPEndPoint(broadcast, port);
            for (int i = 0; i < repeat; i++)
            {
                await udp.SendAsync(packet, packet.Length, endpoint);

                if (i + 1 < repeat && intervalMs > 0)
                {
                    var delay = Backoff.NextDelayMs(i, intervalMs, backoffMult, jitterPct);
                    if (delay > 0) await Task.Delay(delay);
                }
            }
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
    public static Task<bool> PingAsync(IPAddress ip, int timeoutMs, int count)
        => PingAsync(ip, timeoutMs, count, delayMs: 0, backoffMult: 1.0, jitterPct: 0.0);

    public static async Task<bool> PingAsync(IPAddress ip, int timeoutMs, int count, int delayMs, double backoffMult, double jitterPct)
    {
        using var p = new Ping();
        byte[] buffer = Encoding.ASCII.GetBytes("WOLPING");

        for (int i = 0; i < count; i++)
        {
            var reply = await p.SendPingAsync(ip, timeoutMs, buffer);
            if (reply.Status == IPStatus.Success) return true;

            if (i + 1 < count && delayMs > 0)
            {
                var pause = Backoff.NextDelayMs(i, delayMs, backoffMult, jitterPct);
                if (pause > 0) await Task.Delay(pause);
            }
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
            if (!ok) return [];
            return ParseArpWindows(output);
        }
        else if (OperatingSystem.IsLinux())
        {
            var (ok, output) = await Run("ip", "neigh show");
            if (ok) return ParseIpNeigh(output);

            (ok, output) = await Run("arp", "-an");
            if (ok) return ParseArpPosix(output);

            return [];
        }
        else // macOS and others
        {
            var (ok, output) = await Run("arp", "-an");
            if (!ok) return [];
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

    internal static async Task<(bool ok, string output)> Run(string fileName, string arguments)
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

/* ============================= ENV CHECKS ============================= */

internal static class EnvironmentChecks
{
    public static async Task<IEnumerable<PreflightIssue>> RunAsync()
    {
        var list = new List<PreflightIssue>();

        // 1) Neighbor tooling availability
        if (OperatingSystem.IsWindows())
        {
            var (ok, _) = await ArpHelper.Run("arp", "-a");
            if (!ok)
                list.Add(new PreflightIssue(
                    Severity.Warning, null, null, null, null,
                    "Could not execute 'arp -a' on Windows.",
                    "Ensure 'arp.exe' is available (PATH) to enable ARP/neighbor discovery."));
        }
        else if (OperatingSystem.IsLinux())
        {
            var (okIp, _) = await ArpHelper.Run("ip", "neigh show");
            var (okArp, _) = await ArpHelper.Run("arp", "-an");
            if (!okIp && !okArp)
                list.Add(new PreflightIssue(
                    Severity.Warning, null, null, null, null,
                    "Neither 'ip neigh' nor 'arp -an' executed successfully.",
                    "Install iproute2 or net-tools to enable ARP/neighbor discovery."));
        }
        else if (OperatingSystem.IsMacOS())
        {
            var (ok, _) = await ArpHelper.Run("arp", "-an");
            if (!ok)
                list.Add(new PreflightIssue(
                    Severity.Warning, null, null, null, null,
                    "Could not execute 'arp -an' on macOS.",
                    "Ensure 'arp' is available to enable ARP/neighbor discovery."));
        }

        // 2) Active IPv4 interface check
        var upIfaces = NetworkInterface.GetAllNetworkInterfaces()
            .Where(nic =>
                nic.OperationalStatus == OperationalStatus.Up &&
                nic.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                nic.NetworkInterfaceType != NetworkInterfaceType.Tunnel &&
                nic.GetIPProperties().UnicastAddresses.Any(ua => ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork))
            .ToList();

        if (upIfaces.Count == 0)
        {
            list.Add(new PreflightIssue(
                Severity.Error, null, null, null, null,
                "No active IPv4 network interface found.",
                "Bring up a wired NIC on the correct VLAN before running wake/query."));
        }

        // 3) Ping capability sanity (raw socket permissions, firewalls)
        try
        {
            using var p = new Ping();
            var reply = await p.SendPingAsync(IPAddress.Loopback, 200, Encoding.ASCII.GetBytes("WOLPING"));
            // Even if it times out, the call path worked—no issue to report.
        }
        catch (PingException ex)
        {
            list.Add(new PreflightIssue(
                Severity.Warning, null, null, null, null,
                "Ping may be restricted by OS permissions (raw sockets).",
                $"If ICMP checks fail, run with elevated privileges or use ARP/TCP probes. Detail: {ex.GetType().Name}"));
        }
        catch (Exception ex)
        {
            list.Add(new PreflightIssue(
                Severity.Warning, null, null, null, null,
                "Ping feature threw an unexpected error.",
                $"ICMP probes may be unreliable. Detail: {ex.GetType().Name}"));
        }

        return list;
    }
}

internal static class Backoff
{
    private static readonly ThreadLocal<Random> Rng =
        new(() => new Random(unchecked(Environment.TickCount * 31 + Environment.CurrentManagedThreadId)));

    public static int NextDelayMs(int attemptIndex, int baseDelayMs, double mult, double jitterPct)
    {
        if (attemptIndex < 0) attemptIndex = 0;
        if (baseDelayMs < 0) baseDelayMs = 0;
        if (mult < 1.0) mult = 1.0;
        if (jitterPct < 0) jitterPct = 0;
        if (jitterPct > 1) jitterPct = 1;

        double ideal = baseDelayMs * Math.Pow(mult, attemptIndex);
        if (ideal <= 0) return 0;

        if (jitterPct == 0) return (int)Math.Round(Math.Min(ideal, int.MaxValue));

        // jitter in range [-jitterPct, +jitterPct]
        double delta = (Rng.Value!.NextDouble() * 2 - 1) * jitterPct;
        double jittered = ideal * (1.0 + delta);
        if (jittered < 0) jittered = 0;
        if (jittered > int.MaxValue) jittered = int.MaxValue;
        return (int)Math.Round(jittered);
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

    // For preflight OK listing
    public record OkRow(int LineNo, string? Label, string? Ip, string? MacFormatted);

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
            .BorderColor(Color.Grey)
            .AddColumn(new TableColumn("[bold]Status[/]").Centered())
            .AddColumn(new TableColumn("[bold]Label[/]"))
            .AddColumn(new TableColumn("[bold]IP[/]"))
            .AddColumn(new TableColumn("[bold]MAC[/]"))
            .AddColumn(new TableColumn("[bold]Time[/]").Centered())
            .AddColumn(new TableColumn("[bold]Message / Detail[/]"));

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

    public static void RenderPreflight(IEnumerable<PreflightIssue> findings, IEnumerable<OkRow> okRows, bool showOk, int totalTargets)
    {
        var errs = findings.Where(f => f.Severity == Severity.Error).ToList();
        var warns = findings.Where(f => f.Severity == Severity.Warning).ToList();
        var infos = findings.Where(f => f.Severity == Severity.Info).ToList();

        var rule = new Rule(" [bold]Preflight[/] ");
        rule.RuleStyle(Style.Parse("grey"));
        rule.Justification = Justify.Center;
        AnsiConsole.Write(rule);

        if (findings.Any())
        {
            var table = new Table()
                .Expand()
                .Border(TableBorder.Rounded)
                .BorderColor(Color.Grey)
                .AddColumn(new TableColumn("[bold]Severity[/]").Centered())
                .AddColumn(new TableColumn("[bold]Line[/]").Centered())
                .AddColumn(new TableColumn("[bold]Label[/]"))
                .AddColumn(new TableColumn("[bold]IP[/]"))
                .AddColumn(new TableColumn("[bold]MAC[/]"))
                .AddColumn(new TableColumn("[bold]Message[/]"))
                .AddColumn(new TableColumn("[bold]Suggestion[/]"));

            foreach (var f in findings.OrderByDescending(f => f.Severity).ThenBy(f => f.LineNo ?? int.MaxValue))
            {
                var sev = f.Severity switch
                {
                    Severity.Error => "[red]ERROR[/]",
                    Severity.Warning => "[yellow]WARN[/]",
                    _ => "[grey]INFO[/]"
                };

                table.AddRow(
                    sev,
                    f.LineNo?.ToString() ?? "-",
                    Markup.Escape(f.Label ?? "-"),
                    Markup.Escape(f.Ip?.ToString() ?? "-"),
                    Markup.Escape(FormatMac(f.Mac)),
                    Markup.Escape(f.Message),
                    Markup.Escape(f.Suggestion ?? "-")
                );
            }

            AnsiConsole.Write(table);
        }
        else
        {
            AnsiConsole.MarkupLine("[green]No issues found in configuration.[/]");
        }

        if (showOk && okRows.Any())
        {
            var okTable = new Table()
                .Expand()
                .Border(TableBorder.Ascii)
                .BorderColor(Color.Grey)
                .AddColumn(new TableColumn("[bold]OK Line[/]").Centered())
                .AddColumn(new TableColumn("[bold]Label[/]"))
                .AddColumn(new TableColumn("[bold]IP[/]"))
                .AddColumn(new TableColumn("[bold]MAC[/]"));

            foreach (var r in okRows.OrderBy(r => r.LineNo))
            {
                okTable.AddRow(r.LineNo.ToString(), Markup.Escape(r.Label ?? "-"),
                               Markup.Escape(r.Ip ?? "-"),
                               Markup.Escape(r.MacFormatted ?? "-"));
            }

            AnsiConsole.Write(new Rule(" Clean Entries ").RuleStyle(Style.Parse("grey")));
            AnsiConsole.Write(okTable);
        }

        var summary = $"Targets parsed: [bold]{totalTargets}[/]  |  " +
                      $"Errors: [red]{errs.Count}[/]  |  Warnings: [yellow]{warns.Count}[/]  |  Info: [grey]{infos.Count}[/]";
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

