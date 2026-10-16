# Known limitations and untested areas

These are the known gaps in the first release, listed so that users can
judge the risk for themselves.

## Not implemented

- **NetworkManager backend.** Tunnels owned by NetworkManager are detected
  and can only be monitored.
- **Split-tunnel kill switch.** The kill switch requires a full-tunnel IPv4
  config (`AllowedIPs` includes `0.0.0.0/0`).
- **Confined SELinux policy.** The daemon runs as `unconfined_service_t`.
- **System tray icon.** WGM is a normal window application.
- **Editing WireGuard configs.** WGM only reads `/etc/wireguard`.
- **Hostname endpoint re-resolution** while the kill switch is enforced.

## Not verified on real Fedora

Development and testing happened on Ubuntu (kernel WireGuard, nftables)
under real systemd. The following still need checking on Fedora KDE:

- an RPM build with `rpmbuild`/mock, and the spec's scriptlets
- SELinux behaviour, including `wg-quick` with `resolvconf` under the
  unit's capability bounding set
- interaction at boot with `firewalld` and `nftables.service`; a
  `flush ruleset` reload can remove the WGM table for up to 5 seconds
- the GUI on a real Plasma Wayland session, including notifications (it was
  rendered under Xvfb and with Fyne's test driver)

## Tested only in unit tests

- **Active probes over a live tunnel** (ICMP, TCP, DNS). The CI sandbox
  blocks userspace sockets inside network namespaces, so the end-to-end
  test uses a handshake-only health policy.

## Behaviour to be aware of

- If someone runs `wg-quick down` outside WGM on a *managed* tunnel with
  intent up, WGM treats it as a failure and brings the tunnel back up. Use
  WGM to disconnect, or set the tunnel to *monitored*.
- Members of `wgm` can connect and disconnect managed tunnels. Anyone in
  that group can do this from any program, not just the GUI.
- While the kill switch is enforced and the tunnel is down, the machine is
  offline. That is the intended behaviour.
