# Kill switch

When the kill switch is enabled, traffic can leave the machine only through
the protected WireGuard tunnel. If the tunnel fails, traffic is dropped; it
does not fall back to the physical network.

## Enabling

The GUI's Kill switch window, or `killswitch.set`, requires the admin role.
Constraints:

- The protected tunnel needs a readable config in `/etc/wireguard`.
- It must be a full tunnel: a peer with `AllowedIPs` containing
  `0.0.0.0/0`. Split-tunnel protection is not supported yet.
- Hostname endpoints are resolved and pinned to addresses at enable time,
  while DNS still works. With the kill switch on, a hostname endpoint is not
  re-resolved. If the server's address changes, disable and re-enable the
  kill switch.
- Options:
  - **allow LAN**: RFC1918, link-local and ULA destinations are allowed.
  - **allow DHCP**: DHCPv4/v6 client traffic is allowed. On by default.

## Ruleset

WGM owns exactly one nftables table, `inet wgm_killswitch`, with two base
chains (`output`, `forward`) at `filter` priority and policy `drop`.

The output chain accepts:

1. loopback
2. the tunnel interface
3. UDP to each peer endpoint `addr:port`, only when the packet carries the
   WireGuard fwmark. Only the kernel WireGuard socket (or a process with
   `CAP_NET_ADMIN`) can set that mark, so ordinary applications cannot use
   the endpoint exception to reach the server directly.
4. IPv6 neighbour discovery (hop limit 255, link-local only)
5. DHCP, if enabled

DNS (TCP/UDP 53 and 853) outside the tunnel is always dropped, even to LAN
resolvers. LAN destinations are accepted only if *allow LAN* is on.
Everything else is dropped and counted. The final rule carries a marker
comment with a hash of the ruleset, which lets WGM detect stale or tampered
rules.

The forward chain applies the same rules to forwarded traffic, so
containers and VMs behind this host cannot leak around the tunnel.

Only egress is filtered. Inbound traffic is not changed.

### Coexistence with firewalld and other rules

- WGM never flushes the ruleset and never edits other tables.
- In nftables a packet must be accepted by **every** base chain on a hook.
  So WGM's drops apply whatever firewalld does, and WGM's accepts can never
  override another firewall's drops.
- If another firewall blocks the WireGuard endpoint, the tunnel will fail.
  That is the safe direction.
- `nftables.service` with `flush ruleset` (if enabled) would remove WGM's
  table. Both WGM units are ordered after `nftables.service` and
  `firewalld.service`, and the daemon reconciles every 5 seconds. Reloading
  firewalld or nftables at runtime can therefore open a window of up to 5
  seconds.

## Lifecycle and states

| State | Meaning |
|---|---|
| `disabled` | No WGM table is present |
| `installing` | Applying the ruleset |
| `enforced` | Table present and verified (marker hash and rule counts match) |
| `recovering` | Table missing or modified; re-applying |
| `error` | Applying failed; the reason is shown. WGM never removes protection because of an error |
| `unavailable` | `nft` is missing or nftables is unusable |

- **Persistent.** Rules live in the kernel. Stopping, restarting or
  crashing `wgmd` leaves them in place (fail closed).
- **Tunnel down.** When the protected tunnel is down, traffic is blocked.
  That is intended. Recovery still works because the endpoint exception
  allows the WireGuard handshake.
- **Boot.** While enforced, the ruleset is saved to
  `/var/lib/wgm/killswitch.nft`. Early in boot, before `network-pre.target`,
  `wgm-killswitch.service` runs `wgmd killswitch-restore`, so no packet
  leaves before the daemon starts. The file is validated before it is
  applied (root-owned, not group/other-writable, contains only the WGM
  table).
- **Unreadable policy.** If the policy file cannot be read, WGM keeps any
  existing protection rather than acting on defaults.
- **Disable.** An admin can disable the kill switch in the GUI. The other
  way is `sudo wgmd killswitch-disable`, which removes the table and the
  boot file.
- **Uninstall.** Erasing the RPM runs `wgmd killswitch-disable` so that
  removing WGM cannot leave the machine offline.

## Emergency recovery

If you are locked out of the network:

```sh
sudo wgmd killswitch-disable
# or, if wgmd itself is broken:
sudo nft delete table inet wgm_killswitch
sudo rm -f /var/lib/wgm/killswitch.nft
```

Then disable the kill switch in the policy (GUI, or set
`kill_switch.enabled` to `false` in `/etc/wgm/policy.json`). Otherwise the
daemon re-applies it within 5 seconds.

## How it was tested

`tests/netns` (run with `make test-root`) builds isolated network
namespaces with a real kernel WireGuard server and client. A leak is
detected on the far side with nft counters, not just by a failed ping. The
scenarios are:

- traffic to the physical network is blocked: IPv4, IPv6, the endpoint
  address on a wrong port or family, DNS to port 53, and unmarked traffic
  to the endpoint
- a network outage followed by automatic recovery, while the kill switch
  stays enforced
- interface removal: still blocked, and the managed tunnel is brought back
- daemon crash: rules persist without the daemon
- a deleted table is detected and reinstalled
- a competing accept-all nftables table does not override WGM's drop
- a route change sends unmarked traffic to the physical interface, where it
  is dropped
- a graceful stop keeps protection, and boot restore re-applies it
- disabling through the API restores connectivity
- a manual disconnect is not automatically reconnected
- `wgmd killswitch-disable` removes the table

The host's own firewall is never touched by the tests.
