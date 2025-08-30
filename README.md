# WakeCLI

*A fast, scriptable Wake-on-LAN + online status checker for LG TVs, Macs, and any WOL-capable device. Built with .NET 9 and Spectre.Console.*

---

## ✨ Features

* **Two commands**:

  * `wake` — send WOL magic packets to devices from a config file
  * `query` — ping devices to see what’s online
* **Nice console UX** with Spectre.Console: colorized table, ✅/❌ indicators, per-item timing and totals
* **Flexible targets file**: each line can be `Label, IP, MAC` in any order (comments with `#`)
* **Parallel execution** for speed; configurable degree of parallelism
* **Best-effort ARP/neighbor discovery** to fill in missing IPs/MACs (optional)
* **Exit codes** suitable for scripts/automation

---

## 🚀 Quick Start

### Prerequisites

* [.NET 9 SDK](https://dotnet.microsoft.com/)
* OS: Windows, macOS, or Linux

### Build & Run

```bash
# clone your repo then:
dotnet restore
dotnet build -c Release

# show help
dotnet run -- --help

# wake devices listed in targets.txt (in repo root)
dotnet run -- wake -c ./targets.txt

# query devices' online status
dotnet run -- query -c ./targets.txt
```

### Optional: Publish a single binary

```bash
# Windows
dotnet publish -c Release -r win-x64 -p:PublishSingleFile=true --self-contained false

# macOS
dotnet publish -c Release -r osx-x64 -p:PublishSingleFile=true --self-contained false

# Linux
dotnet publish -c Release -r linux-x64 -p:PublishSingleFile=true --self-contained false
```

The executable will be under `./bin/Release/net9.0/<RID>/publish/`.

---

## 📄 Targets File

Place a `targets.txt` (or specify with `--config`) with one target per line. Commas are optional but recommended.

Examples:

```
# LABEL, IP, MAC (any order). Comments start with '#'.
Lobby TV, 192.168.10.51, 38:8C:50:AA:BB:01
Stage Left, 38:8C:50:AA:BB:02, 192.168.10.52
Youth Room, 192.168.10.53, 38:8C:50:AA:BB:03
Foyer TV, 192.168.10.54
GreenRoom, 38:8C:50:AA:BB:05
```

* You can provide **just IP** (useful for `query`) or **just MAC** (useful for `wake`).
* The app can **attempt ARP/neighbor discovery** (if `--try-arp`) to fill in the missing half if it’s present in your OS neighbor cache.

---

## 🧰 Usage

### Global

```
wakecli --help
wakecli <command> --help
```

### `wake` — send magic packets

```
wakecli wake [options]

Options:
  -c, --config <PATH>         Path to targets file (default: ./targets.txt)
  -b, --broadcast <IP>        Broadcast address (default: 255.255.255.255)
  -p, --port <PORT>           UDP port (7 or 9 are common). Default: 9
  -r, --repeat <COUNT>        Magic packets per target. Default: 3
  -i, --interval-ms <MS>      Delay between packets (ms). Default: 100
      --parallelism <N>       Max concurrency. Default: min(8, CPU)
      --try-arp               If target has only IP, try to resolve MAC first (default: true)
```

**Examples**

```bash
# Standard wake using global broadcast
wakecli wake -c targets.txt

# Wake across VLAN by using that VLAN’s directed broadcast
wakecli wake -c targets.txt --broadcast 192.168.50.255 --repeat 5

# Faster on bigger lists
wakecli wake -c targets.txt --parallelism 16
```

### `query` — check online status

```
wakecli query [options]

Options:
  -c, --config <PATH>         Path to targets file (default: ./targets.txt)
  -t, --timeout-ms <MS>       Ping timeout per attempt. Default: 600
  -n, --count <COUNT>         Pings per IP. Default: 1
      --parallelism <N>       Max concurrency. Default: min(16, CPU)
      --try-arp               If target has only MAC, try to discover IP (default: true)
```

**Examples**

```bash
# Simple reachability check
wakecli query -c targets.txt

# More thorough (two pings per host)
wakecli query -c targets.txt -n 2 --timeout-ms 750 --parallelism 32
```

---

## 🖥️ Sample Output

```
──────────── Wake Results ────────────

┌─────────┬────────────┬───────────────┬──────────────────┬─────────┬───────────────┐
│ Status  │ Label      │ IP            │ MAC              │ Time    │ Message       │
├─────────┼────────────┼───────────────┼──────────────────┼─────────┼───────────────┤
│ ✅      │ Lobby TV   │ 192.168.10.51 │ 38:8C:50:AA:…:01 │ 3 ms    │ Sent          │
│ ❌      │ Foyer TV   │ -             │ -                │ 0 ms    │ SKIP (no MAC) │
└─────────┴────────────┴───────────────┴──────────────────┴─────────┴───────────────┘
──────────────────────────────────────
OK=1, Failed=0, Skipped=1. Total 25 ms
```

---

## 🔌 Platform & Network Notes

* **LG TVs (webOS)**: enable WOL / “LG Connect Apps” in settings. Many models support WOL over wired Ethernet when in standby.
* **Mac computers**: enable *Wake for network access* (Energy Saver/Battery). Works reliably over **wired Ethernet** from **sleep** (not shutdown). USB/TB Ethernet dongle support varies by model/driver.
* **Same L2 domain recommended**: WOL packets are layer-2 broadcasts. For other VLANs, use `--broadcast <vlan-broadcast>` (e.g., `192.168.50.255`) or configure router support for **directed broadcasts**/helpers.
* **Ports**: WOL commonly uses UDP **7** or **9**; this tool defaults to **9**.
* **ARP discovery**: Filling missing IP/MAC depends on your OS’s neighbor cache. If the device hasn’t been seen recently, provide both IP and MAC in `targets.txt`.

---

## 🧪 Exit Codes

* `0` — all targets succeeded (for `wake`) or none were offline (for `query`)
* `1` — at least one failure/offline encountered
* `2` — command line parse/validation error

---

## 🏗️ Tech Stack

* **.NET 9**
* **Spectre.Console** + **Spectre.Console.Cli** for CLI & rich console rendering
* `System.Net.*` for UDP, Ping, and ARP/neighbor parsing via platform tools (`arp`, `ip neigh`)

Add packages:

```bash
dotnet add package Spectre.Console
dotnet add package Spectre.Console.Cli
```

---

## 🧭 Roadmap Ideas

* `wake --probe-after <seconds>` to confirm devices came online
* `discover` subnet scanner (write results to `targets.txt`)
* `--json` output for pipelines/Zabbix/Grafana ingestion
* Per-target overrides (custom broadcast/port/retries)
* Optional mDNS/hostname support

---

## ❓ Troubleshooting

* **Nothing wakes**

  * Confirm device supports WOL and it’s enabled, use **wired Ethernet**, and the NIC has link during sleep.
  * Try increasing `--repeat` and using the VLAN’s **directed broadcast**.
* **Query says offline, but device is up**

  * Increase `--timeout-ms` and `--count`; check host firewalls; some TVs don’t respond to ping.
* **ARP discovery doesn’t fill values**

  * The OS neighbor cache might not have entries. Provide both IP and MAC in `targets.txt`.

---

## 🤝 Contributing

PRs and issues are welcome! If you’re adding features, try to keep:

* Cross-platform behavior
* Clean Spectre.Console output
* Script-friendly exit codes

---

## 📜 License

MIT (or your preferred license). Add a `LICENSE` file to the repo.
