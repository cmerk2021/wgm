# Configuration

WireGuard configurations stay where they are (`/etc/wireguard/<name>.conf`)
and are never rewritten by WGM. WGM's own policy lives in
`/etc/wgm/policy.json` (root, 0600). Edit it in the GUI, or as root with a
text editor: the daemon reloads changes within 5 seconds. Check a
hand-edited file with:

```sh
sudo wgmd check-policy            # validates /etc/wgm/policy.json
sudo wgmd check-policy --policy /path/to/file.json
```

## Schema (version 1)

```json
{
  "schema_version": 1,
  "revision": 12,
  "tunnels": {
    "wg0": {
      "ownership": "managed",
      "autostart": true,
      "health": {
        "interval_sec": 10,
        "handshake_stale_sec": 180,
        "failure_threshold": 3,
        "recovery_threshold": 2,
        "connect_grace_sec": 30,
        "probes": [
          {"type": "icmp", "target": "10.0.0.1"},
          {"type": "tcp",  "target": "10.0.0.1", "port": 443, "timeout_ms": 2000},
          {"type": "dns",  "target": "10.0.0.1", "query": "example.org"}
        ]
      },
      "recovery": {
        "enabled": true,
        "max_attempts": 5,
        "initial_backoff_sec": 5,
        "max_backoff_sec": 300,
        "multiplier": 2,
        "jitter_fraction": 0.2,
        "budget_max": 10,
        "budget_window_sec": 3600,
        "verify_timeout_sec": 45,
        "reconnect_after_manual_disconnect": false
      }
    }
  },
  "kill_switch": {"enabled": false, "tunnel": "", "mode": "full", "allow_lan": false, "allow_dhcp": true},
  "monitoring": {"sample_interval_sec": 1, "persist_history": true, "metrics_retention_days": 7, "event_retention_days": 30}
}
```

Tunnels without an entry use the defaults shown above, except that their
ownership defaults to `discovered` with no probes.

## Fields and ranges

| Field | Range | Notes |
|---|---|---|
| `ownership` | `discovered`, `monitored`, `managed` | Changing it requires admin |
| `autostart` | bool | Only for `managed`; requires admin; brings the tunnel up when the daemon starts, unless the user last disconnected it manually |
| `health.interval_sec` | 2–3600 | Probe/evaluation interval |
| `health.handshake_stale_sec` | 30–86400 | WireGuard rekeys every ~2 min, so values under 150 cause false alarms |
| `health.failure_threshold` | 1–50 | Consecutive failed rounds before `error`/recovery |
| `health.recovery_threshold` | 1–50 | Consecutive good rounds before `healthy` |
| `health.connect_grace_sec` | 5–600 | Time to establish before failures count |
| `health.probes` | ≤ 8 | Targets must be IP literals (no loopback/multicast/unspecified) |
| probe `timeout_ms` | 100–10000 | Default 2000 |
| tcp `port` | 1–65535 | Required for tcp |
| dns `query` | hostname | DNS probes use port 53 on `target` |
| `recovery.max_attempts` | 1–50 | |
| `recovery.initial_backoff_sec` | 1–3600 | |
| `recovery.max_backoff_sec` | 1–86400, ≥ initial | |
| `recovery.multiplier` | 1–10 | |
| `recovery.jitter_fraction` | 0–0.5 | |
| `recovery.budget_max` / `budget_window_sec` | 1–1000 / 60–604800 | Maximum disruptive actions per window |
| `recovery.verify_timeout_sec` | 5–3600 | Time to become healthy after an action |
| `kill_switch.*` | see KILLSWITCH.md | Admin only |
| `monitoring.sample_interval_sec` | 1–60 | Admin only |
| `monitoring.metrics_retention_days` | 1–365 | Per-minute aggregates in SQLite |
| `monitoring.event_retention_days` | 1–3650 | |

Every probe runs on a socket bound to the tunnel interface
(`SO_BINDTODEVICE`), so a probe can never succeed over the physical
network.

## Revisions and conflicts

`revision` increments on every write. Clients send the revision they
edited, and a stale write is refused with `conflict`. Hand edits are picked
up by modification time.

## Invalid files and migrations

- The daemon never overwrites a policy file it cannot parse, or one with a
  newer `schema_version`. It logs the error, runs with in-memory defaults,
  refuses policy writes, and reports the reason in the `ping` result, which the GUI shows. If
  the file becomes invalid while the daemon is running, the last good
  policy stays in effect.
- Older schemas are migrated in memory on load. The migrated form is
  written on the next successful update. The first release defines
  migration 0 → 1 (unversioned pre-release files).

## Daemon flags

`wgmd --help` lists them all. The main ones:

| Flag | Default |
|---|---|
| `--policy` | `/etc/wgm/policy.json` |
| `--state-dir` | `/var/lib/wgm` |
| `--config-dir` | `/etc/wireguard` |
| `--socket` | `/run/wgmd/control.sock` |
| `--group` | `wgm` (operators; socket group) |
| `--admin-group` | `wheel` |
