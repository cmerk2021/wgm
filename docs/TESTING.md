# Testing

| Command | Needs | Covers |
|---|---|---|
| `make test` (`go test ./...`) | Go, GUI build headers | All packages: config validation/migration, IPC framing, auth and limits, health state machine, recovery engine, ruleset rendering, kill switch manager (fake nft), discovery/parsing, metrics, event history, sysexec allowlist, daemon handlers with fakes, GUI with Fyne's headless test driver |
| `make vet fmt-check` | Go | Static checks |
| `make test-root` | root (via sudo), `wireguard-tools`, `nftables`, `iproute2`, kernel WireGuard | Real tunnels and the real kill switch in throwaway network namespaces (see KILLSWITCH.md) |

`make test-root` is skipped unless `WGM_NETNS_TESTS=1` is set and the
process runs as root. It creates the namespaces `wgmtestA`
(client, runs the daemon) and `wgmtestB` (WireGuard server), and deletes
them afterwards. It never modifies the host's firewall, routes or
WireGuard interfaces.

The daemon units can be checked with
`systemd-analyze verify systemd/*.service` (after installing the binary).
