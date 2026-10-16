# IPC protocol (version 1)

The GUI and daemon talk over a Unix stream socket at
`/run/wgmd/control.sock`. The socket is mode `0660`, owner `root`, group
`wgm`, and sits in `/run/wgmd` (mode `0755`). Wire types are defined in
`internal/api/api.go`.

## Framing

Each message is one JSON object followed by `\n`. A connection may carry
many requests in sequence; each request gets exactly one response with the
same `id`.

Request:

```json
{"version": 1, "id": 7, "op": "tunnels.connect", "params": {"name": "wg0"}}
```

Response:

```json
{"version": 1, "id": 7, "ok": true, "result": { ... }}
{"version": 1, "id": 7, "ok": false, "error": {"code": "forbidden", "message": "..."}}
```

Unknown fields in requests and params are rejected (`bad_request`). Clients
should ignore unknown fields in responses, so new fields can be added
without a version bump. A breaking change increments `version`. The daemon
answers any other version with `unsupported_version`.

## Limits

| Limit | Value |
|---|---|
| Request size | 64 KiB (larger requests are rejected and the connection closed) |
| Response size | 16 MiB |
| Concurrent connections | 32 (excess connections get `busy` and are closed) |
| Idle connection timeout | 10 minutes |
| Per-request timeout | 90 seconds |

A panic inside a handler is recovered and returned as `internal`. It never
crashes the daemon.

## Authentication and roles

The daemon reads the peer's uid, gid and pid with `SO_PEERCRED`. It then
looks up the uid's group memberships in the system user database (NSS).
Group changes therefore take effect for new connections without a re-login
on the daemon side, although the socket's file permissions still follow the
client process's groups. Roles:

- `none`: any user who can reach the socket.
- `operator`: members of the operator group (`wgm` by default).
- `admin`: uid 0 and members of the admin group (`wheel` by default).

The socket's file permissions already keep out users who are not in `wgm`.
The role check is a second, independent layer.

| Operation | Params | Minimum role |
|---|---|---|
| `ping` | — | none |
| `tunnels.list` | — | operator |
| `tunnels.get` | `{name}` | operator |
| `tunnels.connect` | `{name}` | operator (tunnel must be *managed*) |
| `tunnels.disconnect` | `{name}` | operator (tunnel must be *managed*) |
| `tunnels.rescan` | — | operator |
| `tunnels.set_policy` | `{name, policy, expected_revision?}` | operator; **admin** if ownership or autostart changes |
| `policy.get` | — | operator |
| `killswitch.get` | — | operator |
| `killswitch.set` | `{policy, expected_revision?}` | admin |
| `monitoring.set` | `{monitoring, expected_revision?}` | admin |
| `events.list` | `{tunnel?, since_id?, limit?}` (limit ≤ 2000, default 500) | operator |
| `metrics.get` | `{name, window_sec?, history_hours?}` | operator |
| `diagnostics.get` | — | operator |

`ping` returns the caller's uid and role, so the GUI can enable or disable
controls to match. The daemon enforces authorization on every request
regardless of what the GUI shows.

## Error codes

| Code | Meaning |
|---|---|
| `bad_request` | Malformed JSON, unknown fields, invalid params (the message lists every validation problem) |
| `unsupported_version` | Protocol version mismatch |
| `unknown_op` | Operation is not in the allowlist |
| `forbidden` | Caller's role is insufficient |
| `not_found` | Unknown tunnel |
| `conflict` | Stale `expected_revision`, or another manager owns the tunnel |
| `unavailable` | Backend or nftables not available |
| `timeout` | Request exceeded its deadline |
| `busy` | Connection limit reached |
| `internal` | Unexpected daemon error (details are only in the daemon log) |

## Optimistic concurrency

Policy writes accept `expected_revision`. If it is non-zero and does not
match the current `revision` (returned by `policy.get`), the write fails
with `conflict`. The GUI then reloads, which stops two editors from
silently overwriting each other.

## Secrets

Responses never contain private keys or preshared keys. Peers are
identified by public key. Peer status reports only whether a preshared key
is present.

## Trying it by hand

```sh
printf '{"version":1,"id":1,"op":"ping"}\n' | socat - UNIX-CONNECT:/run/wgmd/control.sock
```
