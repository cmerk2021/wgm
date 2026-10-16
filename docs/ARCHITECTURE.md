# Architecture

```
 ┌──────────────┐  JSON over Unix socket   ┌────────────────────────────────┐
 │  wgm-ui      │  /run/wgmd/control.sock  │ wgmd (root, systemd)           │
 │  (user, Fyne)│ ───────────────────────► │  ipc ─ auth (SO_PEERCRED)      │
 └──────────────┘                          │  service (daemon loop)         │
                                           │   ├ tunnel   discovery + parse │
                                           │   ├ backend  wg-quick          │
                                           │   ├ metrics  wg dump, counters │
                                           │   ├ health   state machine     │
                                           │   ├ recovery bounded engine    │
                                           │   ├ firewall nftables killsw.  │
                                           │   ├ events   log + SQLite      │
                                           │   └ config   policy.json       │
                                           └────────────────────────────────┘
```

## Packages

| Package | Responsibility |
|---|---|
| `cmd/wgmd` | Daemon entry point, flags, `sd_notify`, subcommands (`version`, `check-policy`, `killswitch-restore`, `killswitch-disable`) |
| `cmd/wgm-ui` | GUI entry point |
| `internal/api` | Versioned wire types, operation names, error codes, size limits |
| `internal/ipc` | Socket server (peer credentials, limits, timeouts, panic isolation) and reconnecting client |
| `internal/auth` | Maps a peer's uid/gids to a role; per-operation role table |
| `internal/config` | Policy schema, defaults, validation, migrations, atomic store with revisions |
| `internal/tunnel` | Discovers and parses `/etc/wireguard/*.conf`; keeps keys inside the daemon |
| `internal/backend` | `wg-quick` backend; detects systemd `wg-quick@` units and NetworkManager profiles |
| `internal/metrics` | Reads `wg show <if> dump` and interface counters; computes rates |
| `internal/health` | Pure health evaluator and probes (ICMP/TCP/DNS bound to the tunnel interface) |
| `internal/recovery` | Pure recovery engine: classification, backoff, jitter, budget |
| `internal/firewall` | Kill switch rendering, apply/verify/reconcile, boot file |
| `internal/events` | In-memory event ring, SQLite history and metrics with retention |
| `internal/sysexec` | Allowlisted subprocess runner (no shell, trusted directories only, output limits, key redaction) |
| `internal/service` | Daemon loop and IPC handlers that tie everything together |
| `ui` | Fyne views: overview, detail, graphs, policy editor, kill switch, events, diagnostics |

`health` and `recovery` are pure: they take observations and a clock and
return decisions. Neither the GUI nor root privileges are needed to test
them.

## Health states

| State | Meaning |
|---|---|
| `disconnected` | Interface absent and no intent to run it |
| `connecting` | Activation in progress, or inside the connect grace period |
| `connected_unverified` | Interface up but no evidence yet (no handshake, probes not yet passed) |
| `healthy` | Recent handshake (< `handshake_stale_sec`) **and** every configured probe has passed `recovery_threshold` times in a row |
| `degraded` | Was healthy; handshake stale or probes failing, below `failure_threshold` |
| `recovering` | The recovery engine is acting on the tunnel |
| `error` | Failure threshold reached, or recovery gave up; the reason is shown |
| `unknown` | The daemon has no observations yet |

The thresholds give hysteresis, so one lost probe does not flip the state.
Every status carries a human-readable reason (for example "latest
handshake 4m12s ago (limit 3m0s)").

## Ownership and intent

- **discovered**: shown read-only. WGM never acts on it.
- **monitored**: health is evaluated and reported. WGM never brings the
  tunnel up or down.
- **managed**: WGM may connect, disconnect and recover. A managed tunnel
  needs a `wg-quick` config with no `SaveConfig = true`, and no other owner
  (systemd `wg-quick@` or NetworkManager).

For managed tunnels the daemon tracks the user's *intent*:

- Connect sets intent to up. Disconnect sets intent to down, which
  suppresses recovery.
- A managed tunnel already running when the daemon starts is adopted with
  intent up.
- If someone runs `wg-quick down` outside WGM on a managed tunnel, WGM sees
  the interface missing while intent is up, and brings it back. To stop a
  managed tunnel, use WGM, or change its ownership to *monitored*.

## Recovery

Recovery runs only for managed tunnels with intent up and recovery enabled.
Each failure is classified first:

| Class | Action |
|---|---|
| interface missing | `bring_up` |
| stale handshake / generic | `restart` (down + up) |
| probe-only failure (handshake fresh) | `recheck` (no disruption) |
| network outage (no underlay default route) | wait; does not use an attempt |
| unrecoverable (config missing/invalid, conflict) | give up immediately |

Attempts are spaced by exponential backoff with jitter
(`initial_backoff_sec`, `multiplier`, `max_backoff_sec`, `jitter_fraction`).
They stop after `max_attempts`. A rolling restart budget (`budget_max` per
`budget_window_sec`) stops restart storms. After an action, the tunnel must
become healthy within `verify_timeout_sec` or the attempt counts as failed.
Once recovery is exhausted the tunnel stays in `error` until the user
reconnects. The GUI shows the attempt number, last action, result and next
attempt time.

## Daemon loop

Every second the daemon samples counters. At each tunnel's
`interval_sec` it runs probes, evaluates health, and asks the recovery
engine for a decision. Slow operations (probes, wg-quick) run outside the
state lock. Every 5 seconds the kill switch is reconciled (re-applied if
it was removed or changed), and the policy file is reloaded if it changed
on disk. Discovery re-scans every 5 seconds and on request. External
ownership (systemd/NetworkManager) is re-checked every 30 seconds.

## Persistence

| Path | Content | Mode |
|---|---|---|
| `/etc/wgm/policy.json` | Policy (see CONFIGURATION.md) | 0600 root |
| `/var/lib/wgm/history.db` | SQLite events + metrics, retention-pruned | 0600 root |
| `/var/lib/wgm/killswitch.nft` | Ruleset for boot restore | 0600 root |
| `/run/wgmd/control.sock` | IPC socket | 0660 root:wgm |
| `/var/lib/wgm/state.json` | Tunnel intent (survives daemon restarts) | 0600 root |

If SQLite cannot be opened the daemon logs an error and keeps running with
in-memory history only.
