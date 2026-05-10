[CmdletBinding()]
param(
    [string]$OutputDir        = ".\output",
    [string[]]$DnsTestNames   = @("www.microsoft.com", "github.com"),
    [string[]]$TcpTestTargets = @("1.1.1.1", "www.microsoft.com"),
    [int[]]$TcpTestPorts      = @(443),
    [switch]$IncludeEventLogs,
    [int]$HoursBackForEvents  = 24,
    [ValidateSet("Web","Identity","Custom")]
    [string]$Profile          = "Custom"
)

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

# -- Profile expansion ---------------------------------------------------------

$ProfileLabel = switch ($Profile) {
    "Web"      { "Web Connectivity" }
    "Identity" { "Identity Services" }
    default    { "Custom Target Set" }
}

if ($Profile -eq "Web")      { $TcpTestPorts = @(443) }
if ($Profile -eq "Identity") { $TcpTestPorts = @(53, 88, 389, 636, 443) }

# -- Helpers -------------------------------------------------------------------

function Invoke-Safely {
    param([scriptblock]$Script, [object]$Default = $null)
    try { & $Script } catch { $Default }
}

function New-Finding {
    param([string]$Severity, [string]$Title, [string]$Detail, [string]$NextSteps)
    [pscustomobject]@{ Severity = $Severity; Title = $Title; Detail = $Detail; NextSteps = $NextSteps }
}

function Add-Finding {
    param(
        [System.Collections.Generic.List[object]]$List,
        [string]$Severity, [string]$Title, [string]$Detail, [string]$NextSteps
    )
    $List.Add((New-Finding -Severity $Severity -Title $Title -Detail $Detail -NextSteps $NextSteps))
}

function Test-IsTunnelAdapter {
    param([string]$Name, [string]$Desc)
    ($Name -match "PANGP|GlobalProtect|AnyConnect|VPN|TAP|OpenVPN|WireGuard|Cisco|Pulse|Virtual|vEthernet|ZeroTier") -or
    ($Desc -match "PANGP|GlobalProtect|AnyConnect|VPN|TAP|OpenVPN|WireGuard|Cisco|Pulse|Virtual|vEthernet|ZeroTier")
}

function Get-SubnetPrefix {
    param([string]$IPAddress)
    if ([string]::IsNullOrWhiteSpace($IPAddress)) { return $null }
    $ip = ($IPAddress -split ",")[0].Trim()
    $parts = $ip -split "\."
    if ($parts.Count -ge 3) { return "$($parts[0]).$($parts[1]).$($parts[2])" }
    return $null
}

function Get-CleanIPString {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    $s = ""
    try {
        if ($Value -is [string]) {
            $s = $Value.Trim()
        } elseif ($Value.IPAddress) {
            $s = [string]$Value.IPAddress
        } elseif ($Value.IPAddressToString) {
            $s = [string]$Value.IPAddressToString
        } else {
            $s = [string]$Value
        }
    } catch { $s = [string]$Value }
    # Strip MSFT object noise if it sneaks through
    if ($s -match "^MSFT_") { return "" }
    return $s.Trim()
}

# -- Data collection -----------------------------------------------------------

function Get-AdapterSnapshot {
    $active   = @()
    $inactive = @()
    $adapters = Invoke-Safely { Get-NetAdapter | Sort-Object Status, Name } @()

    foreach ($adapter in @($adapters)) {
        $ipConfig = Invoke-Safely { Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex } $null
        $ipIf     = Invoke-Safely { Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 | Select-Object -First 1 } $null
        $profile  = Invoke-Safely { Get-NetConnectionProfile -InterfaceIndex $adapter.ifIndex } $null

        $ipv4 = if ($ipConfig -and $ipConfig.IPv4Address)        { @($ipConfig.IPv4Address        | ForEach-Object { $_.IPAddress }) } else { @() }
        $ipv6 = if ($ipConfig -and $ipConfig.IPv6Address)        { @($ipConfig.IPv6Address        | ForEach-Object { $_.IPAddress }) } else { @() }
        $gws  = if ($ipConfig -and $ipConfig.IPv4DefaultGateway) { @($ipConfig.IPv4DefaultGateway | ForEach-Object { $_.NextHop   }) } else { @() }
        $dns  = if ($ipConfig -and $ipConfig.DNSServer)          { @($ipConfig.DNSServer.ServerAddresses) }                           else { @() }
        $isTunnel = Test-IsTunnelAdapter -Name $adapter.Name -Desc $adapter.InterfaceDescription

        $obj = [pscustomobject]@{
            Name            = [string]$adapter.Name
            InterfaceIndex  = [int]$adapter.ifIndex
            Status          = [string]$adapter.Status
            MacAddress      = [string]$adapter.MacAddress
            LinkSpeed       = [string]$adapter.LinkSpeed
            InterfaceDesc   = [string]$adapter.InterfaceDescription
            DHCP            = if ($ipIf)    { [string]$ipIf.Dhcp }               else { "Unknown" }
            InterfaceMetric = if ($ipIf)    { [int]$ipIf.InterfaceMetric }        else { 0 }
            NetworkCategory = if ($profile) { [string]$profile.NetworkCategory }  else { "Unknown" }
            IPv4Addresses   = ($ipv4 -join ", ")
            IPv6Addresses   = ($ipv6 -join ", ")
            DefaultGateway  = ($gws  -join ", ")
            DnsServers      = ($dns  -join ", ")
            IsTunnel        = $isTunnel
        }

        if ($adapter.Status -eq "Up") { $active   += $obj }
        else                          { $inactive += $obj }
    }

    return [pscustomobject]@{
        Active   = $active
        Inactive = $inactive
        All      = $active + $inactive
    }
}

function Get-RouteSnapshot {
    $routes = Invoke-Safely {
        Get-NetRoute -AddressFamily IPv4 |
            Where-Object { $_.State -eq "Alive" } |
            Sort-Object InterfaceIndex, RouteMetric, DestinationPrefix |
            Select-Object -First 60 InterfaceIndex, DestinationPrefix, NextHop, RouteMetric, Publish, Protocol
    } @()
    return @($routes)
}

function Get-RouteSummary {
    param([object[]]$Routes, [object[]]$Adapters)
    $defaultRoutes = @($Routes | Where-Object { $_.DestinationPrefix -eq "0.0.0.0/0" } | Sort-Object RouteMetric)
    $primary = $defaultRoutes | Select-Object -First 1

    $ifName = "Unknown"
    $hasTunnelRoute = $false
    if ($primary) {
        $match = $Adapters | Where-Object { $_.InterfaceIndex -eq $primary.InterfaceIndex } | Select-Object -First 1
        if ($match) { $ifName = $match.Name }
        $hasTunnelRoute = ($Adapters | Where-Object {
            $_.InterfaceIndex -eq $primary.InterfaceIndex -and $_.IsTunnel
        }).Count -gt 0
    }

    return [pscustomobject]@{
        DefaultRouteInterface = $ifName
        DefaultGateway        = if ($primary) { [string]$primary.NextHop } else { "None" }
        LowestRouteMetric     = if ($primary) { [string]$primary.RouteMetric } else { "N/A" }
        DefaultRouteCount     = $defaultRoutes.Count
        TunnelRouteActive     = $hasTunnelRoute
        RouteAmbiguity        = ($defaultRoutes.Count -gt 1)
    }
}

function Get-NeighborSnapshot {
    $neighbors = Invoke-Safely {
        Get-NetNeighbor -AddressFamily IPv4 |
            Sort-Object InterfaceIndex, IPAddress |
            Select-Object -First 100 InterfaceIndex, IPAddress, LinkLayerAddress, State
    } @()
    return @($neighbors)
}

function Split-Neighbors {
    param([object[]]$Neighbors, [object]$PathContext)

    $currentSubnet = Get-SubnetPrefix -IPAddress $PathContext.PrimaryIPv4
    $current   = @()
    $stale     = @()
    $multicast = @()

    foreach ($n in @($Neighbors)) {
        $ip = [string]$n.IPAddress
        if ($ip -match "^(224\.|239\.|255\.255\.255\.255)") {
            $multicast += $n
        } elseif ($currentSubnet -and (Get-SubnetPrefix -IPAddress $ip) -eq $currentSubnet) {
            $current += $n
        } else {
            $stale += $n
        }
    }

    return [pscustomobject]@{
        CurrentSubnetNeighbors = $current
        StaleNeighbors         = $stale
        MulticastBroadcast     = $multicast
    }
}

function Get-FirewallSnapshot {
    $profiles = Invoke-Safely {
        Get-NetFirewallProfile |
            Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction,
                          AllowInboundRules, AllowLocalFirewallRules
    } @()
    return @($profiles)
}

# -- Path context --------------------------------------------------------------

function Get-PathContext {
    param([object[]]$Adapters, [object[]]$Routes)

    $activeAdapters   = @($Adapters | Where-Object { $_.Status -eq "Up" -and -not [string]::IsNullOrWhiteSpace($_.IPv4Addresses) })
    $tunnelAdapters   = @($activeAdapters | Where-Object { $_.IsTunnel -eq $true })
    $standardAdapters = @($activeAdapters | Where-Object { $_.IsTunnel -eq $false })
    $tunnelDetected   = ($tunnelAdapters.Count -gt 0)
    $routeAmbiguity   = ($activeAdapters.Count -gt 1)

    if ($activeAdapters.Count -eq 0) {
        return [pscustomobject]@{
            PrimaryInterface = "None"
            PrimaryIPv4      = ""
            DefaultGateway   = ""
            NetworkContext   = "No Active Path Detected"
            TunnelDetected   = $false
            RouteAmbiguity   = $false
            DnsPathType      = "Unknown DNS Path"
            Confidence       = "Limited"
        }
    }

    $primary = if ($tunnelDetected) {
        $tunnelAdapters   | Sort-Object InterfaceMetric | Select-Object -First 1
    } else {
        $standardAdapters | Sort-Object InterfaceMetric | Select-Object -First 1
    }

    # DNS path type - specific labels
    $dnsPathType = "Unknown DNS Path"
    if ($tunnelDetected) {
        $dnsPathType = "Internal / VPN DNS"
    } elseif ($activeAdapters.Count -gt 1) {
        $dnsPathType = "Mixed DNS Path"
    } elseif ($primary -and $primary.NetworkCategory -eq "Public") {
        $dnsPathType = "Gateway-Provided DNS"
    } elseif ($primary -and $primary.NetworkCategory -eq "Private") {
        $dnsPathType = "Local Network DNS"
    } elseif ($primary -and [string]::IsNullOrWhiteSpace($primary.DnsServers)) {
        $dnsPathType = "Unknown DNS Path"
    } else {
        $dnsPathType = "Local Network DNS"
    }

    # Network context
    $context = "Standard Local Wi-Fi Path"
    if ($tunnelDetected) {
        $context = "VPN Tunnel Path Detected"
    } elseif ($primary -and $primary.NetworkCategory -eq "Public") {
        $context = "Public Wi-Fi / Hotspot Path"
    } elseif ($routeAmbiguity) {
        $context = "Mixed / Ambiguous Path State"
    } elseif ($primary -and $primary.Name -match "^Ethernet") {
        $context = "Standard Wired Ethernet Path"
    }

    # Confidence
    $confidence = "High"
    if ($tunnelDetected -or $routeAmbiguity) { $confidence = "Moderate" }
    if ($activeAdapters.Count -eq 0)         { $confidence = "Limited" }

    return [pscustomobject]@{
        PrimaryInterface = if ($primary) { $primary.Name }           else { "Unknown" }
        PrimaryIPv4      = if ($primary) { $primary.IPv4Addresses }  else { "" }
        DefaultGateway   = if ($primary) { $primary.DefaultGateway } else { "" }
        NetworkContext   = $context
        TunnelDetected   = $tunnelDetected
        RouteAmbiguity   = $routeAmbiguity
        DnsPathType      = $dnsPathType
        Confidence       = $confidence
    }
}

# -- Connectivity tests --------------------------------------------------------

function Test-Gateways {
    param([object[]]$Adapters, [object]$PathContext)
    $tests = @()

    foreach ($adapter in @($Adapters | Where-Object { $_.Status -eq "Up" -and -not [string]::IsNullOrWhiteSpace($_.DefaultGateway) })) {
        $gateways = @($adapter.DefaultGateway -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne "0.0.0.0" })
        foreach ($gateway in $gateways) {
            if ($adapter.IsTunnel) {
                $tests += [pscustomobject]@{
                    Adapter   = $adapter.Name
                    Gateway   = $gateway
                    Reachable = "Skipped"
                    Note      = "Virtual/tunnel adapter - not tested"
                }
            } else {
                $reachable = Invoke-Safely { Test-Connection -ComputerName $gateway -Count 2 -Quiet } $false
                $tests += [pscustomobject]@{
                    Adapter   = $adapter.Name
                    Gateway   = $gateway
                    Reachable = if ([bool]$reachable) { "Yes" } else { "No" }
                    Note      = ""
                }
            }
        }
    }
    return $tests
}

function Test-DnsResolution {
    param([string[]]$Names)
    $tests = @()
    foreach ($name in $Names) {
        try {
            $resolved = Resolve-DnsName -Name $name -Type A -ErrorAction Stop |
                Where-Object { $_.Type -eq "A" } | Select-Object -ExpandProperty IPAddress
            $tests += [pscustomobject]@{
                Name            = $name
                Succeeded       = "Yes"
                ResolvedAddress = ($resolved -join ", ")
                Error           = ""
            }
        } catch {
            $tests += [pscustomobject]@{
                Name            = $name
                Succeeded       = "No"
                ResolvedAddress = ""
                Error           = $_.Exception.Message
            }
        }
    }
    return $tests
}

function Test-TcpTargets {
    param([string[]]$Targets, [int[]]$Ports)
    $tests = @()
    foreach ($target in $Targets) {
        foreach ($port in $Ports) {
            $result = Invoke-Safely {
                Test-NetConnection -ComputerName $target -Port $port -WarningAction SilentlyContinue
            } $null
            if ($result) {
                # Extract clean SourceAddress IP - avoids MSFT object serialization noise
                $srcIP = ""
                try {
                    if ($result.SourceAddress) {
                        $srcRaw = $result.SourceAddress
                        if ($srcRaw -is [string]) {
                            $srcIP = $srcRaw.Trim()
                        } elseif ($srcRaw.PSObject.Properties["IPAddress"]) {
                            $srcIP = [string]$srcRaw.IPAddress
                        } elseif ($srcRaw.PSObject.Properties["IPAddressToString"]) {
                            $srcIP = [string]$srcRaw.IPAddressToString
                        } else {
                            $srcIP = [string]$srcRaw
                            if ($srcIP -match "^MSFT_") { $srcIP = "" }
                        }
                    }
                } catch { $srcIP = "" }

                $remoteIP = ""
                try {
                    if ($result.RemoteAddress) {
                        $remoteIP = [string]$result.RemoteAddress
                        if ($remoteIP -match "^MSFT_") { $remoteIP = "" }
                    }
                } catch { $remoteIP = "" }

                $tests += [pscustomobject]@{
                    Target           = $target
                    Port             = $port
                    TcpSucceeded     = if ([bool]$result.TcpTestSucceeded) { "Yes" } else { "No" }
                    PingSucceeded    = if ([bool]$result.PingSucceeded)    { "Yes" } else { "No" }
                    RemoteAddress    = $remoteIP
                    SourceAddress    = $srcIP
                    InterfaceAlias   = if ($result.InterfaceAlias) { [string]$result.InterfaceAlias } else { "" }
                }
            }
        }
    }
    return $tests
}

function Get-NetworkEvents {
    param([int]$HoursBack = 24)
    $start      = (Get-Date).AddHours(-1 * $HoursBack)
    $events     = @()
    $logTargets = @(
        @{ LogName = "System";                                        MaxEvents = 200 },
        @{ LogName = "Microsoft-Windows-WLAN-AutoConfig/Operational"; MaxEvents = 100 }
    )
    foreach ($target in $logTargets) {
        $rows = Invoke-Safely {
            Get-WinEvent -LogName $target.LogName -MaxEvents $target.MaxEvents |
                Where-Object {
                    $_.TimeCreated -ge $start -and
                    $_.ProviderName -match "Dhcp|DNS|Tcpip|WLAN|NetBT|NetworkProfile|e1|Intel|Broadcom|Qualcomm|Wi-Fi"
                } | Select-Object -First 20 TimeCreated, ProviderName, Id, LevelDisplayName, Message
        } @()
        foreach ($row in @($rows)) {
            $events += [pscustomobject]@{
                TimeCreated      = $row.TimeCreated
                ProviderName     = $row.ProviderName
                Id               = $row.Id
                Level            = $row.LevelDisplayName
                Message          = ($row.Message -replace "\s+", " ").Trim()
            }
        }
    }
    return $events
}

# -- Analysis ------------------------------------------------------------------

function Get-Analysis {
    param(
        [object[]]$Adapters,
        [object[]]$GatewayTests,
        [object[]]$DnsTests,
        [object[]]$TcpTests,
        [object[]]$FirewallProfiles,
        [object[]]$Events,
        [object]$PathContext
    )

    $findings       = New-Object 'System.Collections.Generic.List[object]'
    $activeAdapters = @($Adapters | Where-Object { $_.Status -eq "Up" })
    $tunnelActive   = $PathContext.TunnelDetected

    if ($activeAdapters.Count -eq 0) {
        Add-Finding -List $findings -Severity "Critical" `
            -Title     "No active network adapters detected" `
            -Detail    "No adapter is currently in an Up state." `
            -NextSteps "Check cable/Wi-Fi state, NIC status, driver state, and local hardware."
        return $findings
    }

    foreach ($adapter in @($activeAdapters | Where-Object { -not $_.IsTunnel })) {
        if ([string]::IsNullOrWhiteSpace($adapter.IPv4Addresses)) {
            Add-Finding -List $findings -Severity "High" `
                -Title     "No IPv4 address on active adapter: $($adapter.Name)" `
                -Detail    "Adapter is Up but has no IPv4 address assigned." `
                -NextSteps "Check DHCP, 802.1X/NAC authentication, Wi-Fi association, or static IP configuration."
        }
        if ($adapter.IPv4Addresses -match "169\.254\.") {
            Add-Finding -List $findings -Severity "High" `
                -Title     "APIPA address detected on $($adapter.Name)" `
                -Detail    "Adapter self-assigned 169.254.x.x - DHCP server not responding." `
                -NextSteps "Check DHCP availability, VLAN/policy assignment, 802.1X/NAC state, or local adapter health."
        }
        if (-not [string]::IsNullOrWhiteSpace($adapter.IPv4Addresses) -and [string]::IsNullOrWhiteSpace($adapter.DefaultGateway)) {
            Add-Finding -List $findings -Severity "Medium" `
                -Title     "No default gateway on $($adapter.Name)" `
                -Detail    "Adapter has an IP address but no default gateway configured." `
                -NextSteps "Review DHCP scope options, static configuration, or upstream network assignment."
        }
        if ([string]::IsNullOrWhiteSpace($adapter.DnsServers)) {
            Add-Finding -List $findings -Severity "Medium" `
                -Title     "No DNS servers on $($adapter.Name)" `
                -Detail    "Adapter does not show any configured DNS servers." `
                -NextSteps "Review DHCP options, static DNS settings, or network profile configuration."
        }
    }

    if ($PathContext.RouteAmbiguity) {
        Add-Finding -List $findings -Severity "Low" `
            -Title     "Multiple active adapters detected" `
            -Detail    "More than one network adapter is Up with addresses - route/path ambiguity is possible." `
            -NextSteps "Check interface metrics, VPN adapter state, and whether only one active path is expected."
    }

    # Gateway analysis - tunnel-aware
    $realGwTests  = @($GatewayTests | Where-Object { $_.Reachable -ne "Skipped" })
    $gwFailed     = @($realGwTests  | Where-Object { $_.Reachable -eq "No" })
    $dnsOk        = (@($DnsTests | Where-Object { $_.Succeeded -eq "Yes" }).Count -gt 0)
    $tcpOk        = (@($TcpTests | Where-Object { $_.TcpSucceeded -eq "Yes" }).Count -gt 0)

    if ($realGwTests.Count -gt 0 -and $gwFailed.Count -eq $realGwTests.Count) {
        if ($tunnelActive -and ($dnsOk -or $tcpOk)) {
            Add-Finding -List $findings -Severity "Low" `
                -Title     "Local gateway unreachable - tunnel path active and functional" `
                -Detail    "Local gateway ICMP failed, but DNS and/or TCP are succeeding through the tunnel. This is expected VPN behavior. Local gateway testing is not authoritative while a tunnel path is active." `
                -NextSteps "No remediation needed for gateway. Evaluate tunnel policy or application behavior if issues persist."
        } else {
            Add-Finding -List $findings -Severity "High" `
                -Title     "All configured gateways are unreachable" `
                -Detail    "All tested default gateways failed ICMP reachability checks." `
                -NextSteps "Check local link state, VLAN/NAC auth, switch port state, or local firewall and VPN conflicts."
        }
    } elseif ($gwFailed.Count -gt 0) {
        Add-Finding -List $findings -Severity "Medium" `
            -Title     "One or more gateways are unreachable" `
            -Detail    "Some gateway tests failed while others succeeded." `
            -NextSteps "Check interface metrics, route selection, transient packet loss, or path instability."
    }

    if ($tunnelActive) {
        Add-Finding -List $findings -Severity "Info" `
            -Title     "VPN/tunnel adapter active - $($PathContext.PrimaryInterface)" `
            -Detail    "A virtual or VPN adapter is detected. Gateway tests on virtual interfaces are deprioritized. Local path reachability results may not reflect the true network path." `
            -NextSteps "Evaluate connectivity through the tunnel. Check tunnel policy, split-tunnel config, or application routing if issues persist."
    }

    $dnsSuccessCount = @($DnsTests | Where-Object { $_.Succeeded -eq "Yes" }).Count
    if (@($DnsTests).Count -gt 0 -and $dnsSuccessCount -eq 0) {
        Add-Finding -List $findings -Severity "High" `
            -Title     "DNS resolution failed for all test names" `
            -Detail    "No configured test hostname resolved successfully." `
            -NextSteps "Check DNS server config, upstream DNS reachability, local firewall, or split-DNS policy."
    } elseif (@($DnsTests).Count -gt 0 -and $dnsSuccessCount -lt @($DnsTests).Count) {
        Add-Finding -List $findings -Severity "Medium" `
            -Title     "Partial DNS resolution failure" `
            -Detail    "Some DNS lookups succeeded but at least one failed." `
            -NextSteps "Check resolver health, conditional forwarding, DNS filtering, or intermittent upstream issues."
    }

    $tcp443Tests   = @($TcpTests | Where-Object { $_.Port -eq 443 })
    $tcp443Success = @($tcp443Tests | Where-Object { $_.TcpSucceeded -eq "Yes" }).Count
    if ($dnsSuccessCount -gt 0 -and $tcp443Tests.Count -gt 0 -and $tcp443Success -eq 0) {
        Add-Finding -List $findings -Severity "Medium" `
            -Title     "DNS resolves but TCP 443 connectivity failed" `
            -Detail    "Name resolution succeeded but HTTPS port tests did not complete." `
            -NextSteps "Check upstream firewall policy, proxy requirements, VPN routing, or service path restrictions."
    }

    $disabledFW = @($FirewallProfiles | Where-Object { $_.Enabled -eq $false })
    if ($disabledFW.Count -gt 0) {
        Add-Finding -List $findings -Severity "Low" `
            -Title     "One or more Windows Firewall profiles are disabled" `
            -Detail    "At least one firewall profile is not active on this endpoint." `
            -NextSteps "Verify this is expected policy configuration and not a local security gap."
    }

    if (@($Events).Count -gt 0) {
        $errorEvents = @($Events | Where-Object { $_.Level -match "Error|Warning" })
        if ($errorEvents.Count -gt 0) {
            Add-Finding -List $findings -Severity "Low" `
                -Title     "Recent network-related warning/error events found" `
                -Detail    "DHCP, DNS, TCPIP, or WLAN-related error/warning events were found in the last collection window." `
                -NextSteps "Review the Events section for provider names and timestamps that correlate with current symptoms."
        }
    }

    if ($findings.Count -eq 0) {
        Add-Finding -List $findings -Severity "Info" `
            -Title     "No obvious local network issue detected" `
            -Detail    "Core local checks did not reveal a clear problem pattern." `
            -NextSteps "Investigate upstream policy, application-specific behavior, external dependencies, or consider a packet-level trace."
    }

    return $findings
}

function Get-OverallStatus {
    param([object[]]$Findings)
    $order = @{ "Critical" = 5; "High" = 4; "Medium" = 3; "Low" = 2; "Info" = 1 }
    $max = 0; $label = "Info"
    foreach ($f in $Findings) {
        if ($order[$f.Severity] -gt $max) { $max = $order[$f.Severity]; $label = $f.Severity }
    }
    return $label
}

# -- Ticket summary ------------------------------------------------------------

function Get-TicketSummary {
    param(
        [object]$PathContext,
        [object[]]$Findings,
        [object[]]$GatewayTests,
        [object[]]$DnsTests,
        [object[]]$TcpTests,
        [string]$GeneratedAt
    )

    $realGw     = @($GatewayTests | Where-Object { $_.Reachable -ne "Skipped" })
    $gwStatus   = if ($realGw.Count -eq 0) {
        "Not tested (tunnel/virtual adapter active)"
    } elseif (@($realGw | Where-Object { $_.Reachable -eq "Yes" }).Count -eq $realGw.Count) {
        "Reachable"
    } elseif (@($realGw | Where-Object { $_.Reachable -eq "Yes" }).Count -gt 0) {
        "Partial failure"
    } else { "Unreachable" }

    $dnsStatus  = if (@($DnsTests | Where-Object { $_.Succeeded -eq "Yes" }).Count -eq $DnsTests.Count -and $DnsTests.Count -gt 0) { "Successful" }
                  elseif (@($DnsTests | Where-Object { $_.Succeeded -eq "Yes" }).Count -gt 0) { "Partial failure" }
                  else { "Failed" }

    $tcp443     = @($TcpTests | Where-Object { $_.Port -eq 443 })
    $tcpStatus  = if ($tcp443.Count -eq 0) { "Not tested" }
                  elseif (@($tcp443 | Where-Object { $_.TcpSucceeded -eq "Yes" }).Count -eq $tcp443.Count) { "Successful" }
                  elseif (@($tcp443 | Where-Object { $_.TcpSucceeded -eq "Yes" }).Count -gt 0) { "Partial failure" }
                  else { "Failed" }

    $highCount  = @($Findings | Where-Object { $_.Severity -match "Critical|High" }).Count
    $likelyDomain = if ($highCount -eq 0 -and $PathContext.TunnelDetected) {
        "No obvious local path failure. Investigate tunnel policy, application behavior, or upstream dependency."
    } elseif ($highCount -eq 0) {
        "No obvious local network fault. Investigate application, policy, or upstream service."
    } elseif ($dnsStatus -eq "Failed" -and $gwStatus -eq "Unreachable") {
        "Complete path failure. Check adapter state, DHCP, gateway reachability, and DNS configuration simultaneously."
    } elseif ($dnsStatus -eq "Failed") {
        "DNS resolution failure. Check resolver configuration, upstream DNS reachability, split-DNS policy, or local firewall."
    } elseif ($tcpStatus -eq "Failed") {
        "Connectivity blocked at service layer. Check firewall policy, proxy requirements, or VPN path restrictions."
    } else {
        "Upstream or service-layer issue. Local path appears functional."
    }

    $tunnelLabel = if ($PathContext.TunnelDetected) { "Yes" } else { "No" }

    $lines = @(
        "MOAT Summary   [$GeneratedAt]",
        "----------------------------------------------",
        "Primary path:      $($PathContext.PrimaryInterface) ($($PathContext.NetworkContext))",
        "DNS path:          $($PathContext.DnsPathType)",
        "Tunnel detected:   $tunnelLabel",
        "Gateway:           $gwStatus",
        "DNS:               $dnsStatus",
        "TCP 443:           $tcpStatus",
        "Confidence:        $($PathContext.Confidence)",
        "----------------------------------------------",
        "Likely issue domain:",
        $likelyDomain
    )

    return [pscustomobject]@{
        SummaryLines = $lines
        PlainText    = ($lines -join "`n")
    }
}

# -- Report rendering ----------------------------------------------------------

function Convert-FragmentTable {
    param([object[]]$Data, [string]$EmptyMsg = "No relevant entries found.")
    $rows = @($Data)
    if ($rows.Count -eq 0) { return "<p class='empty'>$EmptyMsg</p>" }
    $fragment = ($rows | ConvertTo-Html -Fragment | Out-String)
    return ($fragment -replace "<table>", "<table class='report-table'>")
}

function Build-FindingsHtml {
    param([object[]]$Findings)
    $rows = @($Findings)
    if ($rows.Count -eq 0) { return "<p class='empty'>No findings generated.</p>" }
    $htmlRows = foreach ($f in $rows) {
        $sc = $f.Severity.ToLower()
        "<tr><td><span class='badge $sc'>$($f.Severity)</span></td>" +
        "<td><strong>$($f.Title)</strong><br><span class='detail'>$($f.Detail)</span></td>" +
        "<td class='nextsteps'>$($f.NextSteps)</td></tr>"
    }
    "<table class='report-table findings-table'>" +
    "<thead><tr><th width='90'>Severity</th><th>Finding</th><th width='35%'>Recommended Next Check</th></tr></thead>" +
    "<tbody>$($htmlRows -join '')</tbody></table>"
}

function Build-PathContextHtml {
    param([object]$PathContext)
    $tunnelBadge     = if ($PathContext.TunnelDetected)  { "<span class='badge high'>Yes</span>"   } else { "<span class='badge info'>No</span>"  }
    $routeBadge      = if ($PathContext.RouteAmbiguity)  { "<span class='badge medium'>Yes</span>" } else { "<span class='badge info'>No</span>"  }
    $confidenceBadge = switch ($PathContext.Confidence) {
        "High"    { "<span class='badge info'>High</span>" }
        "Moderate"{ "<span class='badge medium'>Moderate</span>" }
        default   { "<span class='badge high'>Limited</span>" }
    }
    "<table class='report-table path-table'>" +
    "<tr><th width='220'>Field</th><th>Value</th></tr>" +
    "<tr><td>Primary Interface</td><td><strong>$($PathContext.PrimaryInterface)</strong></td></tr>" +
    "<tr><td>Primary IPv4</td><td>$($PathContext.PrimaryIPv4)</td></tr>" +
    "<tr><td>Default Gateway</td><td>$($PathContext.DefaultGateway)</td></tr>" +
    "<tr><td>Network Context</td><td><strong>$($PathContext.NetworkContext)</strong></td></tr>" +
    "<tr><td>DNS Path Type</td><td>$($PathContext.DnsPathType)</td></tr>" +
    "<tr><td>Tunnel Detected</td><td>$tunnelBadge</td></tr>" +
    "<tr><td>Route Ambiguity</td><td>$routeBadge</td></tr>" +
    "<tr><td>Confidence</td><td>$confidenceBadge</td></tr>" +
    "</table>"
}

function Build-RouteSummaryHtml {
    param([object]$RouteSummary)
    $tunnelBadge = if ($RouteSummary.TunnelRouteActive) { "<span class='badge high'>Yes</span>" } else { "<span class='badge info'>No</span>" }
    $ambigBadge  = if ($RouteSummary.RouteAmbiguity)    { "<span class='badge medium'>Yes - $($RouteSummary.DefaultRouteCount) default routes</span>" } else { "<span class='badge info'>No</span>" }
    "<table class='report-table path-table'>" +
    "<tr><th width='220'>Field</th><th>Value</th></tr>" +
    "<tr><td>Default Route Interface</td><td><strong>$($RouteSummary.DefaultRouteInterface)</strong></td></tr>" +
    "<tr><td>Default Gateway (route)</td><td>$($RouteSummary.DefaultGateway)</td></tr>" +
    "<tr><td>Lowest Route Metric</td><td>$($RouteSummary.LowestRouteMetric)</td></tr>" +
    "<tr><td>Tunnel Route Active</td><td>$tunnelBadge</td></tr>" +
    "<tr><td>Route Ambiguity</td><td>$ambigBadge</td></tr>" +
    "</table>"
}

function Build-AdapterHtml {
    param([object[]]$Active, [object[]]$Inactive)
    $activeHtml   = Convert-FragmentTable -Data $Active   -EmptyMsg "No active adapters found."
    $inactiveHtml = Convert-FragmentTable -Data $Inactive -EmptyMsg "No inactive adapters found."
    "<div class='subsection-label'>Active Adapters</div>$activeHtml" +
    "<div class='subsection-label'>Inactive / Disconnected Adapters</div>$inactiveHtml"
}

function Build-TicketSummaryHtml {
    param([object]$TicketSummary)
    "<div class='ticket-box'><div class='ticket-label'>Copy/paste-ready ticket summary</div>" +
    "<pre class='ticket-pre'>$($TicketSummary.PlainText)</pre></div>"
}

function New-HtmlReport {
    param([hashtable]$Report, [string]$HtmlPath)

    $status         = $Report.Summary.OverallStatus
    $eventsHtml     = if ($Report.Metadata.EventLogsIncluded) {
        Convert-FragmentTable -Data $Report.Events -EmptyMsg "Event log collection enabled but no matching events found in the collection window."
    } else {
        "<p class='empty'>Event log collection was not enabled for this run. Use -IncludeEventLogs to collect recent DHCP/DNS/WLAN events.</p>"
    }

    $statusColors = @{
        "Critical" = "#b00020"; "High" = "#d35400"; "Medium" = "#e67e22"
        "Low"      = "#2980b9"; "Info" = "#27ae60"
    }
    $statusColor = $statusColors[$status]
    if (-not $statusColor) { $statusColor = "#999" }

    $head = @"
<style>
  *, *::before, *::after { box-sizing: border-box; }
  body            { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 24px 32px; color: #222; background: #f0f4f8; }
  h1              { color: #0d2b45; margin: 0 0 4px 0; font-size: 22px; }
  h2              { color: #133c55; font-size: 15px; margin: 0 0 10px 0; border-bottom: 2px solid #dde5ee; padding-bottom: 6px; }
  .header-card    { background: #fff; border-radius: 12px; padding: 18px 22px; margin-bottom: 20px;
                    border-left: 7px solid $statusColor; box-shadow: 0 2px 10px rgba(0,0,0,.07);
                    display: flex; align-items: flex-start; justify-content: space-between; }
  .header-left h1 small { font-size: 13px; color: #888; font-weight: 400; margin-left: 8px; }
  .header-meta    { font-size: 12px; color: #555; margin-top: 6px; line-height: 1.8; }
  .header-meta span { margin-right: 18px; }
  .status-pill    { display: inline-block; padding: 6px 16px; border-radius: 999px; font-size: 13px;
                    font-weight: 700; color: #fff; background: $statusColor; white-space: nowrap; margin-top: 4px; }
  .report-table   { width: 100%; border-collapse: collapse; margin-bottom: 16px; background: #fff;
                    border-radius: 8px; overflow: hidden; box-shadow: 0 1px 6px rgba(0,0,0,.06); }
  .report-table th, .report-table td { border: 1px solid #dfe6ee; padding: 8px 10px; vertical-align: top; font-size: 12px; }
  .report-table th  { background: #eef3f8; text-align: left; font-weight: 600; color: #2c4a6e; }
  .path-table td:first-child { font-weight: 600; color: #2c4a6e; background: #f8fafc; width: 220px; }
  .badge          { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 700; color: #fff; }
  .badge.critical { background: #b00020; }
  .badge.high     { background: #d35400; }
  .badge.medium   { background: #e67e22; }
  .badge.low      { background: #2980b9; }
  .badge.info     { background: #27ae60; }
  .detail         { color: #5a6a7e; font-size: 11px; display: block; margin-top: 3px; }
  .nextsteps      { color: #2c4a6e; font-size: 12px; }
  .section        { background: #fff; border-radius: 12px; padding: 18px 22px; margin-bottom: 18px;
                    box-shadow: 0 1px 6px rgba(0,0,0,.05); }
  .empty          { font-style: italic; color: #888; padding: 8px 0; margin: 0; }
  .ticket-box     { background: #0d2b45; border-radius: 10px; padding: 18px 22px; margin-bottom: 4px; }
  .ticket-label   { color: #7ec8e3; font-size: 10px; font-weight: 700; letter-spacing: .1em;
                    text-transform: uppercase; margin-bottom: 10px; }
  .ticket-pre     { color: #e8f4f8; font-family: Consolas, 'Courier New', monospace; font-size: 13px;
                    margin: 0; white-space: pre-wrap; line-height: 1.7; }
  .subsection-label { font-size: 12px; font-weight: 700; color: #2c4a6e; margin: 14px 0 6px 0;
                    text-transform: uppercase; letter-spacing: .06em; }
  .two-col        { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin-bottom: 18px; }
  .two-col .section { margin-bottom: 0; }
</style>
"@

    $body = @"
<div class='header-card'>
  <div class='header-left'>
    <h1>Mission Operations Access Triage Report <small>v1.3</small></h1>
    <div class='header-meta'>
      <span><strong>Generated:</strong> $($Report.Metadata.GeneratedAt)</span>
      <span><strong>Hostname:</strong> $($Report.Metadata.Hostname)</span>
      <span><strong>User:</strong> $($Report.Metadata.Username)</span><br>
      <span><strong>OS:</strong> $($Report.Metadata.OSCaption) $($Report.Metadata.OSVersion)</span>
      <span><strong>Profile:</strong> $($Report.Metadata.ProfileLabel)</span>
      <span><strong>Event Logs:</strong> $(if ($Report.Metadata.EventLogsIncluded) { "Included" } else { "Not collected" })</span>
    </div>
  </div>
  <div><span class='status-pill'>$status</span></div>
</div>

<div class='two-col'>
  <div class='section'>
    <h2>Path Context</h2>
    $(Build-PathContextHtml -PathContext $Report.PathContext)
  </div>
  <div class='section'>
    <h2>Route Summary</h2>
    $(Build-RouteSummaryHtml -RouteSummary $Report.RouteSummary)
  </div>
</div>

<div class='section'>
  <h2>Ticket Summary</h2>
  $(Build-TicketSummaryHtml -TicketSummary $Report.TicketSummary)
</div>

<div class='section'>
  <h2>Key Findings</h2>
  $(Build-FindingsHtml -Findings $Report.Findings)
</div>

<div class='section'>
  <h2>Adapter Snapshot</h2>
  $(Build-AdapterHtml -Active $Report.Adapters.Active -Inactive $Report.Adapters.Inactive)
</div>

<div class='section'>
  <h2>Gateway Reachability</h2>
  $(Convert-FragmentTable -Data $Report.Connectivity.GatewayTests -EmptyMsg "No gateways to test.")
</div>

<div class='section'>
  <h2>DNS Resolution Tests</h2>
  $(Convert-FragmentTable -Data $Report.Connectivity.DnsTests)
</div>

<div class='section'>
  <h2>TCP Connectivity Tests</h2>
  $(Convert-FragmentTable -Data $Report.Connectivity.TcpTests)
</div>

<div class='section'>
  <h2>Firewall Profiles</h2>
  $(Convert-FragmentTable -Data $Report.FirewallProfiles)
</div>

<div class='section'>
  <h2>Route Snapshot (Full Table)</h2>
  $(Convert-FragmentTable -Data $Report.Routes)
</div>

<div class='section'>
  <h2>Neighbor / ARP Table</h2>
  <div class='subsection-label'>Current-Subnet Neighbors</div>
  $(Convert-FragmentTable -Data $Report.Neighbors.CurrentSubnetNeighbors -EmptyMsg "No current-subnet neighbors found.")
  <div class='subsection-label'>Stale / Off-Subnet Host Entries</div>
  $(Convert-FragmentTable -Data $Report.Neighbors.StaleNeighbors -EmptyMsg "No stale entries found.")
  <div class='subsection-label'>Multicast / Broadcast Entries</div>
  $(Convert-FragmentTable -Data $Report.Neighbors.MulticastBroadcast -EmptyMsg "No multicast/broadcast entries found.")
</div>

<div class='section'>
  <h2>Recent Network-Related Events</h2>
  $eventsHtml
</div>
"@

    $html = ConvertTo-Html -Title "MOAT v1.3 - Mission Operations Access Triage Report" -Head $head -Body $body
    Set-Content -Path $HtmlPath -Value $html -Encoding UTF8
}

# -- Main ----------------------------------------------------------------------

Add-Type -AssemblyName System.Web
$null = New-Item -ItemType Directory -Path $OutputDir -Force
$osInfo = Invoke-Safely { Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version } $null

$report = [ordered]@{
    Metadata = [ordered]@{
        GeneratedAt        = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Hostname           = $env:COMPUTERNAME
        Username           = $env:USERNAME
        OSCaption          = if ($osInfo) { $osInfo.Caption } else { "Unknown" }
        OSVersion          = if ($osInfo) { $osInfo.Version } else { "Unknown" }
        Profile            = $Profile
        ProfileLabel       = $ProfileLabel
        EventLogsIncluded  = [bool]$IncludeEventLogs
    }
}

Write-Host ""
Write-Host "  MOAT v1.3 - Mission Operations Access Triage Toolkit" -ForegroundColor Cyan
Write-Host "  -------------------------------------------------------" -ForegroundColor DarkGray

Write-Host "  [1/9] Collecting adapter data..." -ForegroundColor Gray
$adapterData            = Get-AdapterSnapshot
$report.Adapters        = $adapterData

Write-Host "  [2/9] Collecting routes..." -ForegroundColor Gray
$report.Routes          = Get-RouteSnapshot
$report.RouteSummary    = Get-RouteSummary -Routes $report.Routes -Adapters $adapterData.All

Write-Host "  [3/9] Detecting path context..." -ForegroundColor Gray
$report.PathContext     = Get-PathContext -Adapters $adapterData.All -Routes $report.Routes

Write-Host "  [4/9] Collecting and splitting neighbors..." -ForegroundColor Gray
$rawNeighbors           = Get-NeighborSnapshot
$report.Neighbors       = Split-Neighbors -Neighbors $rawNeighbors -PathContext $report.PathContext

Write-Host "  [5/9] Collecting firewall profiles..." -ForegroundColor Gray
$report.FirewallProfiles = Get-FirewallSnapshot

Write-Host "  [6/9] Testing gateways..." -ForegroundColor Gray
$gwTests  = Test-Gateways -Adapters $adapterData.All -PathContext $report.PathContext

Write-Host "  [7/9] Testing DNS resolution..." -ForegroundColor Gray
$dnsTests = Test-DnsResolution -Names $DnsTestNames

Write-Host "  [8/9] Testing TCP connectivity (Profile: $ProfileLabel)..." -ForegroundColor Gray
$tcpTests = Test-TcpTargets -Targets $TcpTestTargets -Ports $TcpTestPorts

$report.Connectivity = [ordered]@{
    GatewayTests = $gwTests
    DnsTests     = $dnsTests
    TcpTests     = $tcpTests
}

if ($IncludeEventLogs) {
    Write-Host "  [9/9] Collecting event logs (last $HoursBackForEvents hrs)..." -ForegroundColor Gray
    $report.Events = Get-NetworkEvents -HoursBack $HoursBackForEvents
} else {
    Write-Host "  [9/9] Skipping event logs (use -IncludeEventLogs to enable)." -ForegroundColor DarkGray
    $report.Events = @()
}

$report.Findings = Get-Analysis `
    -Adapters         $adapterData.All `
    -GatewayTests     $gwTests `
    -DnsTests         $dnsTests `
    -TcpTests         $tcpTests `
    -FirewallProfiles $report.FirewallProfiles `
    -Events           $report.Events `
    -PathContext      $report.PathContext

$overall        = Get-OverallStatus -Findings $report.Findings
$report.Summary = [ordered]@{ OverallStatus = $overall; FindingCount = @($report.Findings).Count }

$report.TicketSummary = Get-TicketSummary `
    -PathContext  $report.PathContext `
    -Findings     $report.Findings `
    -GatewayTests $gwTests `
    -DnsTests     $dnsTests `
    -TcpTests     $tcpTests `
    -GeneratedAt  $report.Metadata.GeneratedAt

# Write outputs
$jsonPath   = Join-Path $OutputDir "triage-results.json"
$htmlPath   = Join-Path $OutputDir "triage-report.html"
$ticketPath = Join-Path $OutputDir "ticket-summary.txt"

$report | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath   -Encoding UTF8
New-HtmlReport -Report $report -HtmlPath $htmlPath
Set-Content -Path $ticketPath -Value $report.TicketSummary.PlainText -Encoding UTF8

Write-Host ""
Write-Host "  -------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  MOAT v1.3 complete." -ForegroundColor Green
Write-Host ""
Write-Host "  Overall Status  : $overall" -ForegroundColor $(if ($overall -match "Critical|High") { "Red" } elseif ($overall -eq "Medium") { "Yellow" } else { "Green" })
Write-Host "  Findings        : $(@($report.Findings).Count)"
Write-Host "  Network Context : $($report.PathContext.NetworkContext)"
Write-Host "  Confidence      : $($report.PathContext.Confidence)"
Write-Host ""
Write-Host $report.TicketSummary.PlainText
Write-Host ""
Write-Host "  HTML   : $htmlPath"
Write-Host "  JSON   : $jsonPath"
Write-Host "  Ticket : $ticketPath"
Write-Host ""
