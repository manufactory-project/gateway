# `gatewayd` Architecture (v0.1)

## 1. Process Model

`gatewayd` separates host network privilege from the guest-facing data plane across four components:

1. **`gatewayd netsetup --config <path>` (root, one-shot via systemd `ExecStartPre=+`):**
   Removes any stale `dataplane.ready_file` first, generates and applies kernel sysctls, per-link
   `ip addr` / `ip rule` / `ip route` configuration, atomic `nft -f` ruleset (`table inet gw`),
   and the DHCP-only `dnsmasq` config from the single YAML config, and writes `dataplane.ready_file`
   last only after every step succeeds.
2. **`dnsmasq` (unprivileged DHCPv4 only, started after `netsetup`):**
   Runs with `--port=0 --dhcp-broadcast --no-ping --bind-interfaces --user=<dhcp.user>` and one
   `--interface` per sandbox link so it drops root and all network capabilities (`CAP_NET_ADMIN`,
   `CAP_NET_RAW`).
3. **`gatewayd --config <path>` (unprivileged, zero `CAP_NET_ADMIN`):**
   Verifies `dataplane.ready_file` and sysctls at startup (refusing to start on mismatch), loads
   the operator-supplied MITM CA, opens the fail-closed JSONL audit sink, and serves per-link
   explicit-bind DNS, HTTPS, and HTTP listeners plus the local Unix-socket Admin API (`0660`) and
   optional explicit-bind Prometheus `/metrics` listener.
4. **`gwctl` (operator CLI):**
   Talks to `gatewayd` over the local Unix domain socket (`status`, `reload`, `flows`, `revoke`,
   `grants`, `grant`, `grant revoke`) and provides offline `ca init` and root `dataplane check`.

## 2. Guest Packet and Request Path

```
Guest packet on sandbox interface (sbxN)
  -> nftables (table inet gw):
       raw_prerouting/raw_output: set per-link conntrack zone (ct zone set <ct_zone>)
       prerouting_guard: drop IPv6 from @sandbox_ifs; drop fib daddr type local from @sandbox_ifs
         except UDP 53/67 and TCP 53 to that link's gateway IP
       prerouting_nat: DNAT :53 (UDP and TCP), :443, and :80 to link_ip:{dns,https,http}_port
       input (policy accept): for @sandbox_ifs drop IPv6 and ct state invalid, accept ct status dnat
         and UDP 68->67, drop everything else
       forward (policy accept): drop iifname @sandbox_ifs and oifname @sandbox_ifs
       output (policy accept): drop IPv6 to @sandbox_ifs
  -> DNS (internal/dns, UDP+TCP on link_ip:dns_port):
       Never forwards upstream. Ignores+audits QR=1 response packets; returns REFUSED/NOTIMP for
       malformed/non-QUERY/non-IN packets; returns synthetic A from dns.fake_cidr (198.18.0.0/15)
       for allowlisted names, NODATA for AAAA/HTTPS/SVCB, REFUSED for all other qtypes/hosts.
  -> Proxy listener (internal/proxy, explicit-bind link_ip:https_port and link_ip:http_port):
       TLS ClientHello (getCertificate): rejects missing/IP/denied SNIs before minting or caching
         any leaf certificate; mints ECDSA P-256 leaves via RWMutex + singleflight LeafCache.
       HTTP request (serveHTTP) runs three linear stages:
         1. admit():   rejects CONNECT, non-origin/non-canonical paths, H2 explicit Host, Host/port
                       or SNI mismatch, non-WS upgrades, policy denies, WS with body, oversized
                       Content-Length.
         2. prepare(): copies end-to-end headers, substitutes bound secrets on HTTPS :443 only
                       (failing closed 403 before dial on unresolved secrets), unconditionally
                       sweeps Proxy-Authorization and remaining mf_ph_* (incl. decoded Basic Auth),
                       and forces Accept-Encoding: identity on bound hosts.
         3. relay():   registers flow in FlowRegistry, writes synchronous admission audit (503 on
                       error), then either upgrades WebSocket (bridgeWebSocket with egress cap) or
                       calls http.Transport.RoundTrip (no 3xx redirects), enforces identity-only
                       Content-Encoding and fail-closed redaction on bound hosts, strips
                       Content-Length on bound hosts, streams body+trailers, and writes completion
                       audit.
  -> Upstream dial (internal/netguard.Dialer):
       Dial-by-name only (refuses IP literals). Static `records` entries dial ONLY the exact pinned
       IP; all other names resolve via upstream DNS and validate every connect-time address in
       net.Dialer.Control (Unmap() -> IPv4 special/private deny list; IPv6 2000::/3 minus specials).
```

## 3. Lifecycle Ownership

- **Active flows and teardown:** A single `proxy.FlowRegistry` tracks every in-flight HTTP request,
  H2 stream, SSE stream, and WebSocket independently (never keyed by TCP connection). `teardown()`
  calls `reqCancel()` and `guestConn.Close()` for transport-managed flows (letting `http.Transport`
  abort dials/handshakes, send H2 `RST_STREAM`, and close stalled H1 sockets without pool races)
  and additionally closes `upConn` directly for WebSockets, where `gatewayd` owns the raw socket.
  Every teardown (explicit revoke, grant expiry, or config reload) increments
  `gatewayd_revocations_total`.
- **Live config reload:** `config.Store.Reload` (triggered by `SIGHUP` or `POST /v1/reload`)
  re-parses and validates YAML strictly (`KnownFields(true)`). Any change to restart-only sections
  (`ca`, `audit`, `admin`, `metrics`, `dns.fake_cidr`, `dataplane`, `http.max_header_bytes`,
  `links`/principals) is refused while keeping the prior snapshot and active grants intact. On
  success, the snapshot swaps atomically, all ephemeral TTL grants are wiped, and per-link
  `onConfigReload` callbacks tear down flows that are no longer allowed and WebSockets on hosts
  that gained a secret binding.
- **Grant TTL expiry & WebSocket grants:** One `config.Store.RunGrantPruner` goroutine owned by `cmd/gatewayd`
  periodically prunes expired grants and invokes all registered `SetOnGrantExpired` callbacks
  across links so expired grant flows tear down immediately. Ephemeral grants (`POST /v1/grants`)
  may carry `allow_websocket`, using the default egress cap (`http.ws_max_egress_bytes`, 64 MiB
  by default), and are refused on any host with a secret binding for that principal.
- **Audit sink:** One `audit.Writer` owned by `cmd/gatewayd` is shared across all link DNS/proxy
  servers and the Admin server, and closed last during graceful shutdown.

## 4. Package Graph and Dependency Rules

```
Leaf packages (zero internal imports):
  internal/config     YAML schema, validation, NormalizeHost, atomic Store & grants
  internal/audit      Synchronous JSONL writer, rotation, retention pruning, escaping
  internal/ca         MITM CA init/load, bounded RWMutex+singleflight LeafCache
  internal/metrics    Prometheus collector and explicit-bind /metrics HTTP server

Config-only packages (import only internal/config):
  internal/policy     Compiled per-principal matcher (specificity + deny-on-tie)
  internal/netguard   Dial-by-name + connect-time Control SSRF guard
  internal/netsetup   Pure nftables/sysctl/ip/dnsmasq renderer + root Apply
  internal/secret     File-only secret resolver, header substitution/sweep, streaming redactor

Service packages:
  internal/dns     -> audit, config, policy
  internal/admin   -> audit, config, metrics   (uses FlowManager interface; never imports proxy)
  internal/proxy   -> audit, ca, config, netguard, policy, secret   (uses OnRequest callback; never imports metrics)

Binaries:
  cmd/gwctl          -> admin, ca, config, netsetup
                        (lint-enforced: transitive deps must NEVER include proxy, secret, policy, netguard)
  cmd/gatewayd       -> wires all internal packages + adminFlowAdapter
  cmd/gatewayd-probe -> static stdlib-only guest probe (lint-enforced: stdlib-only, no proxy/secret/policy/netguard)
```

## 5. Fail-Closed Points

- **Startup:** Missing `dataplane.ready_file`, sysctl mismatch, invalid/unknown YAML fields,
  missing/mismatched CA keypair, or unwritable audit directory aborts startup.
- **DNS:** Unwritable audit sink returns `SERVFAIL` with 0 answers. Non-allowlisted names and
  disallowed qtypes return `REFUSED`; non-`QUERY` opcodes return `NOTIMP`; `QR=1` response packets
  are ignored and audited.
- **TLS:** Missing SNI, IP-literal SNI, or policy-denied SNI fails the TLS handshake without
  minting/caching a leaf. Untrusted upstream TLS certificates fail with `502` (never
  `InsecureSkipVerify`).
- **HTTP & Secrets:** Any request guard violation returns `403`/`400`/`413` before dialing.
  Unresolvable secret files on a matched binding fail `403` before dialing; `Proxy-Authorization`
  and remaining `mf_ph_*` are stripped unconditionally on every request including port `80`.
  Unwritable admission audit returns `503` before dialing. On bound hosts, any non-`identity`
  `Content-Encoding` token or unresolvable redaction secret returns `502` without forwarding an
  unscrubbed body. Upstream non-WebSocket `101` responses return `502`.
- **Connect-time SSRF:** `netguard.CheckAddr` inside `net.Dialer.Control` refuses all private,
  loopback, link-local, CGNAT, and IANA special-purpose IPv4/IPv6 destinations unless matched by an
  exact static `records` entry.

## 6. Audit Write Guarantee

`audit.Writer.WriteSync` sanitizes peer strings, strips query strings (preserving `has_query`),
never records header values, and writes each JSONL record synchronously under a mutex before
answering DNS queries or dialing upstream. Any write or rotation failure marks the sink unhealthy,
increments `gatewayd_audit_write_errors_total`, and returns an error so callers fail closed
(`SERVFAIL` / `503`). `WriteSync` does **not** call `fsync`, so the last OS-buffered records can
be lost on sudden power loss or kernel crash. Disk consumption is bounded by size and daily
rotation (`audit.max_file_bytes`) plus retention pruning (`audit.retain_days`). Operators inspect
audit logs with `tail -F <dir>/*.jsonl | jq` or ship stdout JSON (`audit.stdout_json: true`) to
Loki.

## 7. Deliberate Non-Features and Documented Deviations

- **No built-in audit query/follow API (`NOW.md:67` deviation, owner-approved):** `GET /v1/audit`
  and `gwctl audit` were deliberately cut. Use `tail -F <dir>/*.jsonl | jq` or Loki.
- **No per-stream HTTP/2 teardown:** Revoking a flow/grant cancels the request context and closes
  the guest connection; other streams multiplexed on the same guest H2 connection drop and
  reconnect, while separate guest connections remain untouched.
- **No `DeniedSNILimiter`:** Denied SNIs never mint a leaf certificate and are audited
  unconditionally alongside denied HTTP requests and DNS queries; disk usage from denial floods is
  bounded by audit rotation and retention.
- **Transport-managed upstream teardown (`NOW.md:64` deviation):** For `http.Transport`-managed
  HTTP/H2/SSE requests, teardown calls `reqCancel()` + `guestConn.Close()` instead of poking into
  `http.Transport`'s connection pool to close upstream sockets directly. Direct `upConn.Close()` is
  used only for WebSockets, where `gatewayd` owns the raw socket.

## 8. Deploying

Two minimal systemd units under `deploy/` run the data plane and DHCPv4 helper:

- **`deploy/gatewayd.service`:** `Type=simple` under `User=gatewayd` / `Group=gatewayd` with
  `ExecStartPre=+/usr/local/bin/gatewayd netsetup --config /etc/gatewayd/gatewayd.yaml` (privileged
  one-shot setup), `CapabilityBoundingSet=` and `AmbientCapabilities=` both empty,
  `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
  `RuntimeDirectory=gatewayd` (admin socket, `dataplane.ready`, and generated `dnsmasq.conf`), and
  `LogsDirectory=gatewayd/audit` (creating and granting write access to `/var/log/gatewayd/audit`
  only). When `gatewayd.service` stops, `RuntimeDirectory=gatewayd` deletes `/run/gatewayd`,
  including `dataplane.ready`.
- **`deploy/gatewayd-dhcp.service`:** Ordered `After=gatewayd.service` and
  `Requires=gatewayd.service`. Runs
  `/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/run/gatewayd/dnsmasq.conf` with no flags
  duplicated from the config `netsetup` generates. Starts as root (no `User=`, no empty
  `CapabilityBoundingSet=`) so `dnsmasq` can bind UDP `:67` and then drop privileges itself via
  `user=`.
- **Non-root / `CapEff` guarantee:** Once running, `gatewayd`'s `/proc/<pid>/status` shows a
  non-root `Uid` and `CapEff`, `CapPrm`, and `CapAmb` all `0000000000000000`. Because `netsetup`
  emits unconditional `dhcp-broadcast` and `no-ping`, `dnsmasq` is configured to drop to its
  non-root `user=` with `CapEff` and `CapPrm` both `0000000000000000` and open only UDP `:67`
  (zero `:53` sockets) *(zero `CapEff`/`CapPrm` for `dnsmasq` pending empirical confirmation in
  Step 2.3)*.
- **Stale-ready-file behaviour:** Under systemd, `ExecStartPre=+ gatewayd netsetup` always deletes
  any stale `dataplane.ready` first and only writes it back after `nft -f` and `CheckNftTable`
  succeed. Because unprivileged `gatewayd` has zero `CAP_NET_ADMIN`, it verifies
  `dataplane.ready` existence and sysctls at startup rather than reading `table inet gw` directly,
  whereas root `gwctl dataplane check` inspects `table inet gw` directly and fails if the table is
  missing. *(Observed direct-restart behaviour with a deleted table and stale `dataplane.ready`:
  pending Step 2.1 E2E run.)*
