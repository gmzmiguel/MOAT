# MOAT — Mission Operations Access Triage Toolkit
**v1.3** | PowerShell | Windows 10/11 | Read-Only

---

## What is MOAT?

MOAT is a PowerShell-based endpoint network diagnostic utility that automates the first layer of connectivity triage on Windows systems. It collects live network state, runs active connectivity tests, applies rule-based fault detection, and produces operator-friendly output including a severity-rated HTML report, a structured JSON findings file, and a plain-text ticket summary ready to paste into a help desk or incident ticket.

The tool was built to answer four questions quickly:

- What is the current network path on this endpoint?
- What is failing and how severe is it?
- What evidence supports that conclusion?
- What should happen next?

---

## Why I Built It

Most network connectivity triage at the endpoint level involves the same 15-20 checks every time — is the adapter up, does it have an IP address, is the gateway reachable, is DNS resolving, can we reach the service on the right port? Doing those checks manually takes time and introduces inconsistency depending on who is running the triage.

I built MOAT to automate that entire first layer so an operator walks into a support conversation with structured data and a probable-cause assessment rather than starting from scratch. I also wanted a tool that could handle the reality of enterprise endpoints, where VPN tunnel adapters are almost always present and naive diagnostic tools produce false-positive escalations when they mistake a healthy VPN tunnel for a gateway failure.

The project was also designed to demonstrate practical network troubleshooting logic, PowerShell automation, and operator-focused output design — skills directly applicable to network operations, endpoint security, and IT support roles.

---

## What It Checks

| Category | Detail |
|---|---|
| Adapter state | All adapters — status, DHCP, link speed, interface metric, tunnel detection |
| IP configuration | IPv4/IPv6 addresses, default gateway, DNS servers per adapter |
| Path context | Detects Standard Wi-Fi / Public Hotspot / VPN Tunnel / Wired / Ambiguous |
| Route summary | Default route interface, gateway, metric, tunnel and ambiguity flags |
| Gateway reachability | ICMP test per adapter — skipped automatically for tunnel/virtual adapters |
| DNS resolution | Configurable test hostnames with resolved address or error captured |
| TCP connectivity | Configurable targets and ports with clean source/remote IP output |
| Firewall profiles | Domain / Private / Public profile enabled state |
| Route table | Top 60 alive IPv4 routes |
| ARP neighbors | Split into current-subnet / stale-off-subnet / multicast-broadcast |
| Event logs | Optional: recent DHCP/DNS/WLAN-related system events |

Rule-based fault detection covers **12+ failure patterns** with severity tiering:
`Critical` / `High` / `Medium` / `Low` / `Info`

---

## Key Features

### Path Context Detection
Automatically identifies the type of network path the endpoint is using — Standard Wi-Fi, Public Hotspot, VPN Tunnel, Wired Ethernet, or Mixed/Ambiguous — based on adapter descriptions, network profile categories, and interface metrics. Assigns a confidence level (High / Moderate / Limited) to reflect how reliable the analysis is given the current path state.

### VPN-Aware Gateway Logic
When a tunnel adapter (GlobalProtect, AnyConnect, WireGuard, TAP, vEthernet, etc.) is detected and DNS or TCP connectivity is succeeding through it, the tool correctly downgrades gateway reachability findings from High to Low rather than raising a false escalation. Local gateway ICMP failure is expected and normal when traffic is tunneled — a naive tool would flag this as a critical failure.

### Ticket Summary Output
Synthesizes all findings into a single paste-ready block that prints to the console at completion and saves as a plain-text file. Designed so an operator can run the tool and immediately paste the result into a ticket without manually interpreting raw data.

### Neighbor Table Split
Separates the ARP neighbor table into three sections — current-subnet neighbors, stale/off-subnet entries from previous networks, and multicast/broadcast protocol entries — so the relevant neighbors for the active path are immediately visible without noise from previous connections.

### Service Profiles
The `-Profile` parameter tailors TCP connectivity tests to specific service types:
- **Web** — tests port 443
- **Identity** — tests ports 53, 88, 389, 636, 443 (DNS, Kerberos, LDAP, LDAPS, HTTPS)
- **Custom** — uses manually specified targets and ports

---

## Outputs

| File | Contents |
|---|---|
| `output/triage-report.html` | Full operator report with path context, findings, all data sections |
| `output/triage-results.json` | Complete structured output for further processing or integration |
| `output/ticket-summary.txt` | Plain-text ticket summary, paste-ready |

---

## How to Run It

**Basic run:**
```powershell
powershell -ExecutionPolicy Bypass -File .\mission-triage.ps1
```

**With event logs:**
```powershell
powershell -ExecutionPolicy Bypass -File .\mission-triage.ps1 -IncludeEventLogs
```

**Identity Services profile:**
```powershell
powershell -ExecutionPolicy Bypass -File .\mission-triage.ps1 -Profile Identity
```

**Custom targets and ports:**
```powershell
powershell -ExecutionPolicy Bypass -File .\mission-triage.ps1 `
  -DnsTestNames   @("internal.corp.com", "github.com") `
  -TcpTestTargets @("vpn.corp.com", "8.8.8.8") `
  -TcpTestPorts   @(443, 80)
```

---

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-OutputDir` | `.\output` | Directory for output files |
| `-DnsTestNames` | microsoft.com, github.com | Hostnames to resolve during DNS tests |
| `-TcpTestTargets` | 1.1.1.1, microsoft.com | Targets for TCP connectivity tests |
| `-TcpTestPorts` | 443 | Ports to test (overridden by -Profile) |
| `-Profile` | Custom | `Web`, `Identity`, or `Custom` |
| `-IncludeEventLogs` | Off | Collect recent DHCP/DNS/WLAN system events |
| `-HoursBackForEvents` | 24 | How far back to search event logs |

---

## Folder Structure

```
mission-operations-access-triage/
  mission-triage.ps1        <- main script
  README.md
  output/
    triage-report.html      <- generated on run
    triage-results.json     <- generated on run
    ticket-summary.txt      <- generated on run
  samples/
    baseline-home-wifi/     <- sample output, healthy Wi-Fi path
    hotspot-public/         <- sample output, public hotspot path
    vpn-globalprotect/      <- sample output, VPN tunnel active
```

---

## Scenario Validation

MOAT was validated across three real network conditions to confirm correct path detection, accurate findings, and clean ticket output.

| Scenario | Path Context | DNS Path | Gateway Result | TCP 443 | Overall |
|---|---|---|---|---|---|
| Home Wi-Fi | Standard Local Wi-Fi | Local Network DNS | Reachable | Successful | Info |
| Mobile Hotspot | Public Wi-Fi / Hotspot | Gateway-Provided DNS | Reachable | Successful | Info |
| GlobalProtect VPN | VPN Tunnel Detected | Internal / VPN DNS | Skipped (tunnel) | Successful | Info |

**Key validation outcomes:**
- VPN scenario produced no false High findings despite local gateway being unreachable
- Hotspot scenario correctly updated DNS path label from Local to Gateway-Provided
- Stale ARP entries from previous networks correctly moved to off-subnet section in all scenarios

---

## How It Was Built

### Step 1 — Defined the problem
Identified the 15-20 checks a network analyst runs manually on every connectivity complaint and designed the tool to automate all of them in a single run.

### Step 2 — Chose PowerShell intentionally
PowerShell runs natively on Windows with no dependencies, has direct access to Windows networking cmdlets (`Get-NetAdapter`, `Test-NetConnection`, `Get-NetRoute`, `Get-NetFirewallProfile`), and is the standard scripting language for Windows endpoint administration.

### Step 3 — Built data collection with safe error handling
Each collection function (`Get-AdapterSnapshot`, `Get-RouteSnapshot`, `Get-NeighborSnapshot`, `Get-FirewallSnapshot`) uses an `Invoke-Safely` wrapper that catches exceptions and returns a safe default rather than crashing — critical for a diagnostic tool that runs in degraded or unusual environments.

### Step 4 — Built active connectivity tests
`Test-Gateways`, `Test-DnsResolution`, and `Test-TcpTargets` run live checks against the network. A specific issue was that `Test-NetConnection` returns `SourceAddress` as a typed Microsoft object that serializes as an object reference string on some Windows builds — this required explicit property inspection to extract a clean IP string.

### Step 5 — Built path context detection
`Get-PathContext` detects tunnel adapters by matching adapter names and descriptions against known VPN patterns, selects the primary interface by interface metric, classifies the network context, assigns a DNS path type, and assigns a confidence level.

### Step 6 — Built the rule-based analysis engine
`Get-Analysis` evaluates all collected data against 12+ detection rules in sequence. The most important design decision was the VPN-aware gateway logic — when a tunnel is active and DNS or TCP is succeeding, gateway ICMP failure is downgraded from High to Low to prevent false escalations.

### Step 7 — Built the neighbor table split
`Split-Neighbors` separates ARP entries into current-subnet, stale/off-subnet, and multicast/broadcast buckets using the primary IPv4 address as a reference point.

### Step 8 — Built the ticket summary and report
`Get-TicketSummary` synthesizes findings into a plain-text paste-ready block. `New-HtmlReport` generates a self-contained HTML report using `ConvertTo-Html` for table sections and custom HTML/CSS for layout, including a color-coded severity header, path context card, and split neighbor sections.

---

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later
- Standard Windows networking cmdlets (included in all modern Windows builds)
- No external dependencies or installations required

---

## Notes

- The tool is fully read-only and makes no changes to system state
- Event log collection may require elevated permissions on some configurations
- VPN detection covers: GlobalProtect, PANGP, Cisco AnyConnect, OpenVPN, WireGuard, Pulse, TAP adapters, vEthernet, ZeroTier

---

## Resume Description

Built MOAT (Mission Operations Access Triage Toolkit), a PowerShell-based diagnostic utility that automates endpoint network triage by collecting adapter state, IP configuration, DNS behavior, routing, firewall profiles, and gateway and TCP reachability data. Implemented rule-based fault detection across 12+ failure patterns with VPN-aware logic, path-context detection, and operator-friendly reporting validated across standard Wi-Fi, mobile hotspot, and GlobalProtect VPN scenarios.
