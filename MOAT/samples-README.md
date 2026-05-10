# Sample Outputs

This folder contains saved HTML reports and ticket summaries from three validated
network scenarios. These demonstrate how MOAT behaves differently depending on the
active network path.

---

## Scenarios

### baseline-home-wifi/
**Path:** Standard Local Wi-Fi (Private network profile)
**DNS Path:** Local Network DNS
**Gateway:** Reachable
**TCP 443:** Successful
**Overall Status:** Info
**Notes:** Clean baseline run. No findings raised. Stale ARP entries from previous
networks correctly separated into off-subnet section.

---

### hotspot-public/
**Path:** Public Wi-Fi / Hotspot Path
**DNS Path:** Gateway-Provided DNS
**Gateway:** Reachable
**TCP 443:** Successful
**Overall Status:** Info
**Notes:** Tool correctly identified public network profile and updated DNS path
label from Local Network DNS to Gateway-Provided DNS. Previous home Wi-Fi ARP
entries moved to stale section.

---

### vpn-globalprotect/
**Path:** VPN Tunnel Detected
**DNS Path:** Internal / VPN DNS
**Gateway:** Skipped (virtual/tunnel adapter)
**TCP 443:** Successful through tunnel
**Overall Status:** Info
**Notes:** Tool detected GlobalProtect virtual adapter, skipped gateway ICMP test,
and produced no false High findings despite local gateway being unreachable.
Confidence set to Moderate due to tunnel path complexity.

---

## Key Takeaway

All three scenarios produced Info overall status with no false escalations.
The most important validation is the VPN scenario -- a naive diagnostic tool
would raise a High or Critical finding for gateway unreachable in that environment.
MOAT correctly recognizes the tunnel context and adjusts its analysis accordingly.
