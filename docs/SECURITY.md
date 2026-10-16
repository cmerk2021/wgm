# Security model

`wgmd` runs as root and is a security boundary. Users of the GUI must not be
able to use it to gain root, read WireGuard secrets, or weaken the
firewall.

## Threat model

| Actor | May | Must not |
|---|---|---|
| Any local user | Nothing. The socket is not reachable outside group `wgm` | Connect to the socket, read configs |
| Operator (`wgm` group) | View status, events and metrics; connect/disconnect *managed* tunnels; edit health/recovery thresholds and probes | Change ownership, autostart, kill switch or monitoring; run commands; choose files or executables |
| Admin (root, `wheel`) | Everything above, plus ownership, autostart, kill switch, monitoring | Execute arbitrary commands through WGM |

Out of scope: a local root attacker, and a compromised kernel or
WireGuard implementation. Any process running as an operator user is
treated as that operator; the socket cannot tell the GUI apart from a
script.

## Measures

**Socket and authentication**

- `/run/wgmd/control.sock` is `0660 root:wgm`.
- Each connection is identified with `SO_PEERCRED`. The role is computed
  from the uid and the user database's group memberships (see IPC.md).

**Operation allowlist**

- The protocol has a fixed set of operations, and each has a minimum role.
- Unknown operations, unknown JSON fields and oversized requests are
  rejected.

**Input validation**

- Interface names match `[A-Za-z0-9_=+.-]{1,15}`; `.` and `..` are
  rejected.
- Tunnels are referenced by name only. Configuration paths are derived as
  `<config dir>/<name>.conf` and never taken from the client.
- Probe targets must be IP literals, which means no DNS lookups at
  configuration time. Unspecified, loopback, multicast and zoned addresses
  are refused. Ports, timeouts and every threshold are range-checked.

**No shell, no arbitrary executables**

- `internal/sysexec` runs only these utilities: `wg`, `wg-quick`, `ip`,
  `nft`, `nmcli` and `systemctl`.
- They are resolved only from `/usr/sbin`, `/usr/bin`, `/sbin` and `/bin`.
- Commands run with an argument vector, never through a shell.
- The environment is fixed (`PATH` limited to those directories,
  `LC_ALL=C`).
- Output size is capped and each command has a timeout.

**Secrets**

- Private keys and preshared keys are parsed only inside the daemon. They
  are never put into API responses.
- Subprocess output and error messages pass through key redaction before
  being logged or returned.

**nftables input**

- Every value written into a ruleset is validated first: interface names
  against the strict character set above, and addresses by parsing.
- WGM only creates, replaces or deletes its own table, `inet
  wgm_killswitch`.
- The boot-restore file is applied only if it meets all of these:
  - owned by root
  - not writable by group or others
  - a regular file
  - contains no statements outside the WGM table

**Files**

- Policy, state and the boot file are written atomically (temp file,
  fsync, rename) with mode 0600. History is a SQLite database.
- They live in directories with mode 0700.
- The policy file is size-limited. If it cannot be parsed, or comes from a
  newer schema, it is never overwritten.

**Robustness**

- Requests have deadlines.
- The connection count is bounded.
- Handler panics are contained.

## systemd hardening

`wgmd.service` uses the following settings:

- `ProtectSystem=true`, `ProtectHome=true`, `PrivateTmp=true` and
  `NoNewPrivileges=true`.
- `UMask=0077`.
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`.
- `CapabilityBoundingSet` limited to what `wg-quick`, `ip` and `nft` need.

`ProtectSystem=strict` is not used, because `wg-quick` may call
`resolvconf`, which writes under `/etc`.

## SELinux

WGM ships no custom SELinux module in the first release. On Fedora,
`/usr/bin/wgmd` is labelled `bin_t`, and systemd runs it as
`unconfined_service_t`. This is the same treatment as other unpackaged
services, so `wg-quick`, `ip` and `nft` behave as they would from a root
shell.

WGM never disables or relaxes SELinux. A confined policy module is planned
future work. This has **not** been verified on a real Fedora system yet;
see LIMITATIONS.md.

## Reporting vulnerabilities

Please report security issues privately through GitHub's "Report a
vulnerability" feature on the repository instead of opening a public issue.
