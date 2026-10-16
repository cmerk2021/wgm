# WGM — WireGuard Manager

WGM is a native Linux WireGuard manager. It has two parts:

- **`wgmd`** is a privileged daemon run by systemd. It discovers WireGuard
  configurations, evaluates tunnel health, recovers failed tunnels with
  bounded retries and manages an optional nftables kill switch. It keeps
  doing all of this when no one is logged in.
- **`wgm-ui`** is an unprivileged desktop application built with Fyne. It
  talks to the daemon over an authenticated Unix socket. It never runs as
  root and never asks for a password.

The guiding rule is that **an interface being up does not mean the VPN is
healthy**. WGM separates these states: *connecting*, *connected but
unverified*, *healthy*, *degraded*, *recovering*, *disconnected* and
*error*. Only evidence moves a tunnel to *healthy*: a recent handshake and,
when configured, passing probes through the tunnel.

WGM has no cloud components, accounts or telemetry. All data stays on the
machine.

## Features (first release)

| Feature | Status |
|---|---|
| Discovery of `/etc/wireguard/*.conf` (secrets never leave the daemon) | Working, unit tested |
| Ownership levels: discovered / monitored / managed | Working, unit tested |
| Connect / disconnect via `wg-quick` | Working, tested in network namespaces |
| Conflict detection (systemd `wg-quick@`, NetworkManager) | Working, unit tested |
| Health state machine (handshake age, counters, probes, hysteresis) | Working, unit tested + netns |
| Active probes: ICMP, TCP connect, DNS (bound to the tunnel interface) | Unit tested; not exercised live (see limitations) |
| Bounded recovery: backoff, jitter, attempt limit, restart budget, failure classification | Working, unit tested + netns |
| nftables kill switch (full tunnel, persistent, boot restore, fail-closed) | Working, leak-tested in network namespaces |
| Throughput graphs, peer details, handshake age | Working |
| Event history and metrics in SQLite with retention | Working, unit tested |
| Desktop notifications for important state changes | Working (headless tested) |
| Diagnostics view | Working |
| Fedora RPM spec, systemd units, sysusers | Units verified under systemd; RPM build not yet tested |
| NetworkManager backend | Not implemented (detected only, to avoid conflicts) |

## Quick start (Fedora KDE)

See [docs/INSTALL-FEDORA.md](docs/INSTALL-FEDORA.md) for the full guide.

```sh
sudo dnf install golang gcc make wireguard-tools nftables \
    mesa-libGL-devel libXcursor-devel libXrandr-devel libXinerama-devel \
    libXi-devel libXxf86vm-devel libxkbcommon-devel wayland-devel
make build
sudo make install
sudo systemd-sysusers            # creates the "wgm" group
sudo usermod -aG wgm "$USER"     # log out and back in afterwards
sudo systemctl daemon-reload
sudo systemctl enable --now wgmd.service
wgm-ui
```

Members of `wgm` can view tunnels and connect or disconnect them.
Kill-switch, monitoring and ownership changes require `root` or a member
of `wheel`.

## Building and testing

Use Go 1.24 or newer. Dependencies are pinned in `go.mod`/`go.sum`.

```sh
make build        # bin/wgmd, bin/wgm-ui
make test         # all unit tests, no root needed, no GUI session needed
make vet fmt-check
make test-root    # uses sudo: real WireGuard + nftables tests in network namespaces
```

`make test-root` creates temporary network namespaces and never changes the
host's firewall or routing. See [docs/TESTING.md](docs/TESTING.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [IPC protocol](docs/IPC.md)
- [Security model](docs/SECURITY.md)
- [Kill switch](docs/KILLSWITCH.md)
- [Configuration](docs/CONFIGURATION.md)
- [Installing on Fedora](docs/INSTALL-FEDORA.md)
- [Testing](docs/TESTING.md)
- [Known limitations](docs/LIMITATIONS.md)

## Emergency: restoring network access

If the kill switch blocks traffic and the UI is unavailable:

```sh
sudo wgmd killswitch-disable
```

This removes only WGM's nftables table and the boot-restore file.

## License

MIT; see [LICENSE](LICENSE).
