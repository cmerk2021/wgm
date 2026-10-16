# Installing on Fedora (KDE Plasma)

These steps target a currently supported Fedora release on x86_64 or
aarch64. Fedora KDE runs Wayland by default, and Fyne supports both Wayland
and X11. They have not yet been verified on a real Fedora machine (see
LIMITATIONS.md); please report problems.

## 1. Dependencies

```sh
# runtime
sudo dnf install wireguard-tools nftables iproute
# build
sudo dnf install golang gcc make pkgconf-pkg-config \
    mesa-libGL-devel libXcursor-devel libXrandr-devel libXinerama-devel \
    libXi-devel libXxf86vm-devel libxkbcommon-devel wayland-devel
```

Go 1.24 or newer is required (`go version`). Module versions are pinned in
`go.sum`.

## 2. Build and install from source

```sh
git clone https://github.com/cmerk2021/wgm.git && cd wgm
make build              # as your user
sudo make install       # copies bin/, units, sysusers, desktop file into /usr
sudo systemd-sysusers   # creates group "wgm"
sudo usermod -aG wgm "$USER"
sudo systemctl daemon-reload
sudo systemctl enable --now wgmd.service
sudo systemctl enable wgm-killswitch.service   # boot-time kill switch restore
```

Log out and back in so that your session picks up the `wgm` group. Then
start **WGM** from the application menu, or run `wgm-ui`.

To try the daemon without installing it:

```sh
sudo ./bin/wgmd --log-level debug   # Ctrl+C to stop
./bin/wgm-ui
```

## 3. Build an RPM

```sh
sudo dnf install rpm-build systemd-rpm-macros
make vendor-tarball VERSION=0.1.0
cp packaging/fedora/wgm.sysusers .
rpmbuild -ba packaging/fedora/wgm.spec --define "_sourcedir $PWD"
sudo dnf install ~/rpmbuild/RPMS/$(uname -m)/wgm-*.rpm
```

The vendor tarball lets the RPM build offline (as in mock/Koji). The `wgm`
package contains the daemon and units; `wgm-ui` contains the GUI.

## 4. First use

1. Put tunnel configs in `/etc/wireguard/` (root-owned, 0600) as usual.
2. They appear in WGM as **discovered**. To let WGM control a tunnel, an
   admin (a `wheel` member) sets its ownership to **managed** in the
   tunnel's Policy dialog. Choose **monitored** to only watch a tunnel run
   by something else.
3. Add probes (for example ICMP to an address only reachable through the
   tunnel) so that *healthy* means real connectivity.
4. Optionally enable the kill switch (read KILLSWITCH.md first).

Tunnels run by `systemctl enable wg-quick@wg0` or by NetworkManager can be
monitored but not managed. Disable the other manager first if you want WGM
to control the tunnel.

## Upgrades

- `dnf upgrade` restarts `wgmd`. The kill switch stays enforced throughout,
  because the rules live in the kernel.
- The policy is migrated automatically. Newer files are never overwritten
  by older daemons.

## Uninstall

`sudo dnf remove wgm wgm-ui` disables the kill switch (`wgmd
killswitch-disable`) and stops the units. `/etc/wgm` and `/var/lib/wgm` are
kept; delete them manually if you no longer need them. Your WireGuard
configs are never touched.

For a source install: `sudo systemctl disable --now wgmd wgm-killswitch;
sudo wgmd killswitch-disable; sudo make uninstall`.

## Troubleshooting

| Symptom | Check |
|---|---|
| GUI says "daemon unavailable" | `systemctl status wgmd`; `journalctl -u wgmd` |
| GUI says permission denied | `id` must list `wgm`; log out/in after `usermod` |
| Connect button disabled | Tunnel is not *managed*, or another manager owns it (see the tunnel's reason) |
| Ownership/kill switch controls disabled | Requires root or `wheel` |
| No network after enabling kill switch | Tunnel down? See KILLSWITCH.md "Emergency recovery" |
| `wg-quick` errors about DNS | Install `openresolv` or `systemd-resolved` integration as for plain wg-quick |
| Policy changes refused ("read-only") | `sudo wgmd check-policy` shows why the file is rejected |
| SELinux denials | `sudo ausearch -m avc -ts recent`; please report them, do not disable SELinux |
