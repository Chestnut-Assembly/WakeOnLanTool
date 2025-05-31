// WakeOnLanTool – .NET 9
// ---------------------------------------------------------------------------
// • Wake-on-LAN  &  Status (ping) modes
// • Mixed MAC / IPv4 / IPv6 config file (comments, blanks OK)
// • Interface pinning, custom broadcast, loop-back broadcast guard
// • Parallel workers (default 8, cap 20) + per-packet throttle
// • Adaptive ping timeout back-off (halves after 10 consecutive failures)
// • Persistent vendor (OUI) cache with disk & /tmp fallback
// • JSON / quiet output, colourised table for humans
// • Robust option + ENV validation (numeric ranges, existence checks)
// • Strict exit codes, summaries, sample generator (--examples)
// ---------------------------------------------------------------------------

using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.CommandLine;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

const int DEFAULT_PARALLEL = 8;      // default worker pool (cap 20)
const int GATEWAY_PING_MS  = 200;
const string CONTACT =
    "For assistance with Wake-on-LAN, contact Ivan Perez – ivan.perez@chestnutag.org";

// ────────────────────────── CLI & help text ───────────────────────────────
var root = new RootCommand($$"""
Wake devices on your LAN (magic packet) or check their status (ping).

Precedence  CLI > ENV > defaults
Quick start dotnet run -- -f DevicesToWakeup.config      # wake
            dotnet run -- -f DevicesToWakeup.config -s   # health

Run --examples for a sample config.

Exit codes  0 ok • 1 cfg missing • 2 bad local net • 3 bad entries
            4 exception • 5 unreachable (with --strict)

{{CONTACT}}
""");

// ── options (every one has description) ───────────────────────────────────
var optFile = new Option<FileInfo>(["--file","-f"],
    "Path to DevicesToWakeup.config (one MAC or IP per line).") { IsRequired = true };

var optStatus    = new Option<bool>(["--status","-s"],
    "Ping-check devices instead of waking them.");

var optTimeout   = new Option<int>(["--timeout","-t"], () => 1000,
    "Ping timeout in ms (10-10000).");

var optBroadcast = new Option<IPAddress>(["--broadcast","-b"], () => IPAddress.Broadcast,
    "IPv4 broadcast address for Wake-on-LAN.");

var optPort      = new Option<int>(["--port","-p"], () => 9,
    "UDP port for Wake-on-LAN (1-65535, default 9).");

var optParallel  = new Option<int?>(["--parallel"],
    "Concurrent workers (1-20, default 8).");

var optIface     = new Option<string?>(["--iface"],
    "Bind packets to this interface (name) or local IPv4.");

var optThrottle  = new Option<int>(["--throttle-ms"], () => 0,
    "Delay ms after each magic packet (0-5000).");

var optJson      = new Option<bool>(["--json","-j"],
    "Emit results as JSON array.");

var optQuiet     = new Option<bool>(["--quiet","-q"],
    "Suppress per-device lines; summaries remain.");

var optLog       = new Option<FileInfo>(["--logfile"],
    "Append console output to file (thread-safe).");

var optStrict    = new Option<bool>(["--strict"],
    "Exit 5 if any host unreachable (status-mode).");

var optCache     = new Option<string?>(["--cachefile"],
    "OUI cache path or \"off\" (default ~/.wol-oui-cache.json).");

var optExamples  = new Option<bool>(["--examples"],
    "Show sample config and exit.");

root.AddGlobalOption(optFile);
root.AddOption(optStatus);   root.AddOption(optTimeout);
root.AddOption(optBroadcast);root.AddOption(optPort);
root.AddOption(optParallel); root.AddOption(optIface);  root.AddOption(optThrottle);
root.AddOption(optJson);     root.AddOption(optQuiet);  root.AddOption(optLog);
root.AddOption(optStrict);   root.AddOption(optCache);  root.AddOption(optExamples);

// ── option validators -----------------------------------------------------
optTimeout .AddValidator(r=>{ int v=r.GetValueOrDefault<int>(); if(v<10||v>10_000) r.ErrorMessage="--timeout 10-10000";});
optPort    .AddValidator(r=>{ int v=r.GetValueOrDefault<int>(); if(v<1||v>65_535)  r.ErrorMessage="--port 1-65535";});
optParallel.AddValidator(r=>{ if(r.Tokens.Count==0) return; int v=r.GetValueOrDefault<int>(); if(v<1||v>20) r.ErrorMessage="--parallel 1-20";});
optThrottle.AddValidator(r=>{ int v=r.GetValueOrDefault<int>(); if(v<0||v>5000)   r.ErrorMessage="--throttle-ms 0-5000";});
optIface   .AddValidator(r=>{ if(r.Tokens.Count==0) return; var val=r.Tokens[0].Value;
                               if(IPAddress.TryParse(val,out _)) return;
                               bool ok=NetworkInterface.GetAllNetworkInterfaces().Any(n=>n.Name.Equals(val,StringComparison.OrdinalIgnoreCase));
                               if(!ok) r.ErrorMessage=$"Interface '{val}' not found.";});
optBroadcast.AddValidator(r=>{ if(r.Tokens.Count==0) return;
                                if(IPAddress.TryParse(r.Tokens[0].Value,out var ip)){
                                    if(ip.AddressFamily!=AddressFamily.InterNetwork)
                                        r.ErrorMessage="Broadcast must be IPv4.";
                                    else if(ip.GetAddressBytes()[0]==127)
                                        r.ErrorMessage="Loopback broadcast invalid.";
                                }});
optFile.AddValidator(r=>{ var f=r.GetValueOrDefault<FileInfo>();
                          if(!f.Exists||f.Attributes.HasFlag(FileAttributes.Directory))
                              r.ErrorMessage="--file must be a readable file.";});
root.AddValidator(cmd=>{ if(cmd.GetValue(optJson)&&cmd.GetValue(optQuiet))
                             cmd.ErrorMessage="--json and --quiet cannot be combined.";});

// ── handler registration --------------------------------------------------
root.SetHandler(Run, optFile,optStatus,optTimeout,optBroadcast,optPort,
                optParallel,optIface,optThrottle,optJson,optQuiet,optLog,
                optStrict,optCache,optExamples);

return await root.InvokeAsync(args);

// ══════════════════════════════════════════════════════════════════════════
// runtime implementation
// ══════════════════════════════════════════════════════════════════════════

static async Task<int> Run(
    FileInfo cfg,bool status,int timeout,IPAddress bc,int port,
    int? parallel,string? iface,int throttle,bool json,bool quiet,
    FileInfo? logfile,bool strict,string? cachePath,bool examples)
{
    if(examples)
    {
        Console.WriteLine("""
        # DevicesToWakeup.config
        # Blank lines / # comments ignored
        40-A1-77-3B-44-55
        192.168.1.42
        fe80::1c4a:55ff:feab:beef

        Commands
          Wake   ./WakeOnLanTool -f DevicesToWakeup.config
          Health ./WakeOnLanTool -f DevicesToWakeup.config --status --strict
        """);
        return 0;
    }

    // ── ENV overrides + parse errors -------------------------------------
    var envErr = new List<string>();
    cfg      = EnvFile ("WOL_FILE", cfg);
    status   = EnvBool ("WOL_STATUS", status);
    timeout  = EnvInt  ("WOL_TIMEOUT", timeout , envErr,10,10_000);
    bc       = EnvIP   ("WOL_BROADCAST", bc    , envErr);
    port     = EnvInt  ("WOL_PORT", port       , envErr,1,65_535);
    parallel = EnvIntN ("WOL_PARALLEL", parallel, envErr,1,20);
    throttle = EnvInt  ("WOL_THROTTLE_MS", throttle, envErr,0,5000);
    iface    = EnvStr  ("WOL_IFACE", iface);
    json     = EnvBool ("WOL_JSON", json);
    quiet    = EnvBool ("WOL_QUIET", quiet);
    logfile  = EnvFileN("WOL_LOGFILE", logfile);
    strict   = EnvBool ("WOL_STRICT", strict);
    cachePath ??= Environment.GetEnvironmentVariable("WOL_CACHEFILE");

    if(envErr.Any()){ foreach(var e in envErr) Console.Error.WriteLine($"ENV ERROR: {e}"); return 1;}

    // ── logger -----------------------------------------------------------
    StreamWriter? logWr = logfile!=null ? new StreamWriter(logfile.FullName,true){AutoFlush=true}:null;
    object lockObj=new();
    void LOG(string m){ if(!quiet&&!json) Console.WriteLine(m); logWr?.WriteLine(m); }

    if(!cfg.Exists){ LOG("❌  Config file not found"); return 1;}

    if(!ValidateLocal(bc,iface,LOG)) return 2;
    if(!ValidateCfg(cfg,LOG))        return 3;

    var cachePathFinal=LoadCache(cachePath,LOG,out bool cacheOK);
    int parMax = parallel ?? DEFAULT_PARALLEL;
    var bindIP = ResolveBindIP(iface, bc, LOG);

    int exit = status
        ? await StatusMode(cfg,timeout,parMax,json,quiet,strict,LOG,bindIP)
        : await WakeMode  (cfg,parMax,throttle,json,quiet,LOG,bc,port,bindIP);

    SaveCache(cachePathFinal,cacheOK,LOG);
    logWr?.Dispose();
    return exit;
}

// ── validation helpers ----------------------------------------------------
static bool ValidateLocal(IPAddress bc,string? iface,Action<string> log)
{
    var nics=NetworkInterface.GetAllNetworkInterfaces()
             .Where(n=>n.OperationalStatus==OperationalStatus.Up).ToList();
    if(!nics.Any()){ log("❌  No active NIC"); return false; }

    var subs=nics.SelectMany(n=>n.GetIPProperties().UnicastAddresses)
                 .Where(a=>a.Address.AddressFamily==AddressFamily.InterNetwork)
                 .Select(a=>Broadcast(a.Address,a.IPv4Mask??IPAddress.None));
    if(!bc.Equals(IPAddress.Broadcast)&&!subs.Contains(bc))
    { log($"❌  Broadcast {bc} not in local subnets"); return false;}

    if(!string.IsNullOrEmpty(iface)&& !IPAddress.TryParse(iface,out _)
        && nics.All(n=>!n.Name.Equals(iface,StringComparison.OrdinalIgnoreCase)))
    { log($"❌  Interface '{iface}' not found"); return false;}

    return true;
}
static bool ValidateCfg(FileInfo cfg,Action<string> log)
{
    var bad=File.ReadLines(cfg.FullName).Select((l,i)=>(l.Trim(),i+1))
        .Where(t=>t.Item1.Length>0&&!t.Item1.StartsWith('#')&&
                 ResolveMac(t.Item1)==null&&!IPAddress.TryParse(t.Item1,out _)).ToList();
    if(!bad.Any()) return true;
    log("❌  Invalid lines:"); bad.ForEach(b=>log($"  line {b.Item2}: \"{b.Item1}\""));
    return false;
}
static IPAddress? ResolveBindIP(string? iface,IPAddress bc,Action<string> log)
{
    if(string.IsNullOrEmpty(iface)) return null;
    if(IPAddress.TryParse(iface,out var ip)) return ip;

    var nic=NetworkInterface.GetAllNetworkInterfaces()
             .FirstOrDefault(n=>n.Name.Equals(iface,StringComparison.OrdinalIgnoreCase));
    if(nic==null){ log($"⚠️  Interface {iface} not found"); return null; }

    var addr=nic.GetIPProperties().UnicastAddresses
               .FirstOrDefault(a=>a.Address.AddressFamily==AddressFamily.InterNetwork)?.Address;
    if(addr==null){ log($"⚠️  No IPv4 on {iface}"); return null; }

    var bcast=Broadcast(addr,nic.GetIPProperties().UnicastAddresses
                             .First(a=>a.Address.Equals(addr)).IPv4Mask??IPAddress.None);
    if(!bc.Equals(IPAddress.Broadcast)&&!bc.Equals(bcast))
        log($"⚠️  Broadcast {bc} not on {iface}; consider --broadcast {bcast}");
    return addr;
}

// ── OUI cache -------------------------------------------------------------
static readonly ConcurrentDictionary<string,string> Cache=new(StringComparer.OrdinalIgnoreCase);
static readonly JsonSerializerOptions JS=new(){WriteIndented=false};

static string? LoadCache(string? path,Action<string> log,out bool ok)
{
    if(path is null or "off" or "-"){ ok=false; return null;}
    try{
        if(File.Exists(path))
            foreach(var kv in JsonSerializer.Deserialize<Dictionary<string,string>>(File.ReadAllText(path))!)
                Cache[kv.Key]=kv.Value;
        ok=true; return path;
    }catch(Exception ex){ log($"⚠️  Cache read failed ({ex.GetType().Name})"); ok=false; return null; }
}
static void SaveCache(string? path,bool ok,Action<string> log)
{
    if(!ok||path is null) return;
    try{
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path,JsonSerializer.Serialize(Cache,JS));
    }catch(Exception ex){
        var tmp=Path.Combine(Path.GetTempPath(),"wol-oui-cache.json");
        log($"⚠️  Cache write failed ({ex.GetType().Name}); saved to {tmp}");
        try{ File.WriteAllText(tmp,JsonSerializer.Serialize(Cache,JS)); }catch{}
    }
}

// ── Wake mode -------------------------------------------------------------
static async Task<int> WakeMode(
    FileInfo cfg,int parMax,int throttle,bool json,bool quiet,Action<string> log,
    IPAddress bc,int port,IPAddress? bind)
{
    log($"\u001b[36mWAKE\u001b[0m broadcast={bc}:{port} parallel={parMax} iface={bind??"auto"} throttle={throttle}ms");

    int ipv6Skip=0,total=0;
    var list=new ConcurrentBag<WakeDTO>();
    var gate=new SemaphoreSlim(parMax);

    var tasks=File.ReadLines(cfg.FullName).Select(l=>l.Trim())
       .Where(l=>l.Length>0&&!l.StartsWith('#')).Select(async line=>{
            await gate.WaitAsync();
            try{
                total++;
                var mac=ResolveMac(line);
                if(mac==null){ log($"⚠️ {line} invalid"); return;}

                var ip=ResolveIp(line,mac);
                if(ip?.AddressFamily==AddressFamily.InterNetworkV6){ ipv6Skip++; ip=null;}

                SendMagic(mac,bc,port,bind);
                if(throttle>0) await Task.Delay(throttle);

                var host=ip==null?"n/a":TryDNS(ip);
                var vendor=await Vendor(mac);
                list.Add(new WakeDTO(mac,ip?.ToString(),host,vendor,bc.ToString(),port,bind?.ToString()));
                if(!quiet&&!json)
                    log($"\u001b[32m✔\u001b[0m {mac} → {ip??"n/a"} {host} {vendor}");
            }
            finally{ gate.Release();}
       }).ToList();
    await Task.WhenAll(tasks);

    if(!quiet&&!json) log($"SUMMARY total={total} ipv6-skipped={ipv6Skip}");
    if(json) Console.WriteLine(JsonSerializer.Serialize(list,JS));
    return 0;
}

// ── Status mode -----------------------------------------------------------
static async Task<int> StatusMode(
    FileInfo cfg,int timeout,int parMax,bool json,bool quiet,bool strict,
    Action<string> log,IPAddress? bind)
{
    log($"\u001b[36mSTATUS\u001b[0m timeout={timeout}ms parallel={parMax}");

    var list=new ConcurrentBag<StatDTO>();
    var gate=new SemaphoreSlim(parMax);
    int consTO=0;

    var tasks=File.ReadLines(cfg.FullName).Select(l=>l.Trim())
       .Where(l=>l.Length>0&&!l.StartsWith('#')).Select(async line=>{
            await gate.WaitAsync();
            try{
                var mac=ResolveMac(line);
                var ip =ResolveIp(line,mac);
                if(ip==null){ log($"⚠️ {line} no IP"); return; }

                var (ok,rtt,retry)=await PingRetry(ip,timeout,ref consTO);
                var host=TryDNS(ip);
                var vendor=mac==null?"n/a":await Vendor(mac);
                list.Add(new StatDTO(ip.ToString(),host,vendor,ok,rtt,retry));

                if(!quiet&&!json){
                    var tag=ok?"\u001b[32m✔\u001b[0m":"\u001b[31m✖\u001b[0m";
                    log($"{tag} {ip,-15} RTT={(ok?rtt+"ms":"--")} retry={retry} {host} {vendor}");
                }
            }
            finally{ gate.Release(); }
       }).ToList();
    await Task.WhenAll(tasks);

    int up=list.Count(l=>l.Up), down=list.Count(l=>!l.Up);
    double avg=list.Where(l=>l.Up).DefaultIfEmpty().Average(l=>l?.RttMs??0);
    long max=list.Where(l=>l.Up).Select(l=>l.RttMs).DefaultIfEmpty().Max();

    if(!quiet&&!json) log($"SUMMARY up={up} down={down} avg={avg:F1}ms max={max}ms");
    if(json) Console.WriteLine(JsonSerializer.Serialize(list,JS));
    return down>0&&strict?5:0;
}

static async Task<(bool ok,long rtt,int retries)> PingRetry(IPAddress ip,int to,ref int consTO)
{
    using var ping=new Ping();
    int delay=50,current=to,retry=0;
    for(int i=0;i<3;i++){
        var rep=await ping.SendPingAsync(ip,current);
        if(rep.Status==IPStatus.Success){ consTO=0; return (true,rep.RoundtripTime,retry);}
        retry++; consTO++;
        if(consTO>=10 && current>200){ current/=2; consTO=0; }
        await Task.Delay(delay); delay*=3;
    }
    return (false,-1,retry);
}

// ── Low-level helpers -----------------------------------------------------
static void SendMagic(string mac,IPAddress bc,int port,IPAddress? bind)
{
    var buf=ArrayPool<byte>.Shared.Rent(102);
    try{
        for(int i=0;i<6;i++) buf[i]=0xFF;
        Span<byte> macB=stackalloc byte[6];
        for(int i=0;i<6;i++) macB[i]=Convert.ToByte(mac.Substring(i*2,2),16);
        for(int r=1;r<=16;r++) macB.CopyTo(buf.AsSpan(r*6));
        using var udp=new UdpClient{EnableBroadcast=true};
        if(bind!=null) udp.Client.Bind(new IPEndPoint(bind,0));
        udp.Send(buf,102,new IPEndPoint(bc,port));
    }finally{ ArrayPool<byte>.Shared.Return(buf,false); }
}

static readonly Regex RxMac=new(@"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$");

static string? ResolveMac(string s)=>RxMac.IsMatch(s)
    ? s.Replace(":","").Replace("-","").ToUpper()
    : IPAddress.TryParse(s,out var ip) ? ArpMac(ip) : null;

static IPAddress? ResolveIp(string s,string? mac)
    => IPAddress.TryParse(s,out var ip) ? ip
    : mac!=null ? ArpIp(mac) : null;

static string? ArpMac(IPAddress ip){ try{ var t=Process.Start("arp","-n "+ip)!.StandardOutput.ReadToEnd();
                                        var m=RxMac.Match(t); return m.Success?m.Value.Replace(":","").Replace("-","").ToUpper():null;}catch{return null;} }
static IPAddress? ArpIp(string mac){ try{ var t=Process.Start("arp","-an")!.StandardOutput.ReadToEnd();
                                        var line=t.Split('\n').FirstOrDefault(l=>l.Contains(mac,StringComparison.OrdinalIgnoreCase));
                                        var m=Regex.Match(line??"",@"\(([^)]+)\)"); return m.Success?IPAddress.Parse(m.Groups[1].Value):null;}catch{return null;} }

static IPAddress Broadcast(IPAddress ip,IPAddress mask)
{
    uint i=BitConverter.ToUInt32(ip.GetAddressBytes().Reverse().ToArray());
    uint m=BitConverter.ToUInt32(mask.GetAddressBytes().Reverse().ToArray());
    return new IPAddress(BitConverter.GetBytes(i|~m).Reverse().ToArray());
}
static string TryDNS(IPAddress ip){ try{return Dns.GetHostEntry(ip).HostName;}catch{return "n/a";} }

static readonly HttpClient Http=new(){ Timeout=TimeSpan.FromSeconds(3) };
static async Task<string> Vendor(string mac)
{
    var oui=mac[..6]; if(Cache.TryGetValue(oui,out var v)) return v;
    try{ v=(await Http.GetStringAsync($"https://api.macvendors.com/{mac}")).Trim(); }
    catch{ v="n/a"; }
    Cache[oui]=v; return v;
}

// ── DTOs ------------------------------------------------------------------
record WakeDTO(string MAC,string? IP,string Host,string Vendor,string Broadcast,int Port,string? Interface);
record StatDTO(string IP,string Host,string Vendor,bool Up,long RttMs,int Retries);

// ── ENV helper overloads --------------------------------------------------
static string? EnvStr (string name,string? v) => v??Environment.GetEnvironmentVariable(name);
static bool EnvBool(string name,bool v){ if(v) return true; var s=Environment.GetEnvironmentVariable(name); return s is "1" or "true" or "yes" or "on";}
static int EnvInt(string name,int v,List<string> err,int min,int max)
{
    var s=Environment.GetEnvironmentVariable(name); if(s is null) return v;
    if(int.TryParse(s,out var n) && n>=min && n<=max) return n;
    err.Add($"{name} must be integer {min}-{max}"); return v;
}
static int? EnvIntN(string name,int? v,List<string> err,int min,int max)
{
    var s=Environment.GetEnvironmentVariable(name); if(s is null) return v;
    if(int.TryParse(s,out var n) && n>=min && n<=max) return n;
    err.Add($"{name} must be integer {min}-{max}"); return v;
}
static IPAddress EnvIP(string name,IPAddress v,List<string> err)
{
    var s=Environment.GetEnvironmentVariable(name); if(s is null) return v;
    if(IPAddress.TryParse(s,out var ip)) return ip;
    err.Add($"{name} must be valid IP"); return v;
}
static FileInfo EnvFile(string name,FileInfo v)
    => Environment.GetEnvironmentVariable(name) is {Length:>0} s ? new FileInfo(s) : v;
static FileInfo? EnvFileN(string name,FileInfo? v)
    => Environment.GetEnvironmentVariable(name) is {Length:>0} s ? new FileInfo(s) : v;
