# `gateway` Threat Model (v0.1)

`gateway` treats every connected guest as hostile. A guest may be steered by prompt injection,
untrusted repository content, or malicious code it executes, up to and including root inside the
guest. Containment does not depend on guest cooperation, agent discipline, or in-guest sandboxing;
the locked plain-Go wire suite is the living verification inventory.

## Hardening Goals

1. **Protect the LAN, host, and other guests — total across every protocol and address family.**
   By default, a guest cannot reach the host, management interfaces, LAN peers, cloud metadata
   endpoints, loopback, link-local, non-global IPv6, or other sandbox guests. Enforcement spans
   Linux `nftables` (per-link conntrack zones, IPv4-only sandbox links, `fib daddr type local`
   guards, default-`drop`), kernel sysctls (`ip_forward=0`, IPv6 forwarding off, `rp_filter=2`,
   ARP suppression), root-owned `/run/gateway-dataplane/` isolation for `dnsmasq.conf` and
   `dataplane.ready` (preventing unprivileged `gateway` from tampering with root-read dataplane
   files), fake-IP DNS (zero upstream query forwarding; malformed packets audited as
   `effect=deny, reason=malformed`), dial-by-name, and connect-time `Dialer.Control` checks
   (`Unmap()` before prefix matching). Explicit opt-in exceptions to private-IP unreachability come
   only from global static `records` entries (`host -> exact IP`), which are not scoped per
   principal or rule (see also the globally routed host/LAN residual below).

2. **Keep declared secrets out of the guest.**
   Declared API keys and credentials stay behind the host/gateway-container filesystem boundary
   through a `file`-only secret provider. Guests hold only inert `mf_ph_*` placeholders for
   declared secrets. `gateway` substitutes a secret only into the exact `(host, header, scheme)`
   declared by a Binding and only when admitted by that binding's owning rule, unconditionally
   strips `Proxy-Authorization` and any remaining `mf_ph_*` (including decoded Basic Auth) from
   every outbound request, forces `Accept-Encoding: identity` on bound hosts (failing closed `502`
   on compressed responses), and scrubs literal, URL-encoded, and JSON-escaped echoes of bound
   secrets from response headers, bodies, and trailers back to their placeholders. This goal carries
   the security weight because Goal 3 is open by design.

3. **Data leaving is bounded and attributable, not prevented.**
   Attribution is strictly per sandbox link (`link.principal`), never derived from the guest's
   source IP (`src_ip` is recorded in audit events for diagnostics only and is not trusted). Every
   DNS query and HTTP request is evaluated against an explicit default-deny allowlist per link
   principal and written to a fail-closed structured JSONL audit log (escaped paths with query
   strings stripped and `has_query` recorded; never header values). Active flows are tracked per
   request/stream and torn down immediately (`cancel()` + `conn.Close()`) on `gateway revoke`, TTL
   expiry, or `SIGHUP` rule/grant removal, recording explicit teardown reasons (`revoked`,
   `grant-expired`, `reload`, `client-canceled`) in completion audits, full grant scope (`methods`,
   `paths`, `allow_websocket`) on `grant-created`, target metadata (`principal`, `host`, `port`) on
   `grant-deleted`, and `revoked_flows` counts on `revoke`, `grant-deleted`, and `reload`.
   Per-guest resource bounds cap concurrent connections per link (`http.max_conns_per_link`,
   default `512`), upstream response header wait (`http.upstream_response_header_timeout`, default
   `10m`), WebSocket upgrade handshakes (`30s`), glob pattern complexity (at most one `**` per
   pattern and four `*` per segment), and total audit directory size (`audit.max_total_bytes`,
   default `10 GiB`).

## Accepted Residuals (By Design)

- **Guest-held subscription OAuth tokens and arbitrary vendor credentials:** Allowlisted LLM vendor
  APIs accept any credential the guest presents, so data can leave to an account the operator does
  not own. Subscription OAuth tokens (`claude`, `agy`, `codex`) live inside the guest by design so
  workers can use personal subscriptions under unmodified vendor CLIs.
- **Vendor account content pulled over allowed API hosts:** Any content a vendor serves on an
  allowlisted API host—such as `claude`'s organization skills and plugins on `api.anthropic.com`—can
  be fetched into the guest unless blocked by path rules. Path-scoped allow rules (as in
  `examples/workers.yaml`) are the control.
- **Vendor telemetry over allowed API hosts:** Telemetry endpoints hosted on the same allowlisted
  API domain (such as `claude`'s `/api/event_logging/v2/batch` on `api.anthropic.com`) can leave
  unless excluded by path-scoped rules, even when dedicated third-party telemetry hosts are denied.
- **Steady-state token refresh vs. interactive login grants:** Interactive login hostnames are
  granted only ephemerally (`gateway grant --ttl 5m`) and stay out of steady-state policy; OAuth
  token-refresh endpoints instead receive permanent exact-host, exact-path `POST` rules so workers
  can refresh tokens without keeping interactive login surfaces open.
- **CLI CA trust without env vars (unverified):** Phase 3 verified `claude`, `codex`, and `agy`
  through MITM with `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE` pointing at `/etc/ssl/certs/ca-certificates.crt`;
  whether each CLI trusts the system CA store with those environment variables unset is still
  unverified.
- **Exfiltration within a credential's scope and through allowed destinations:** A placeholder
  prevents the guest from reading the raw secret, but an agent can still exfiltrate any data the
  credential legitimately reaches (for example, pushing to a repository the token can write) or
  encode data into paths, query strings, headers, or bodies sent to an allowlisted host. Scoping
  credentials at their source and writing exact-host, method, and path rules bound the channel.
- **Cross-host secret reflection and compressed responses on bound hosts:** A secret stored
  upstream on bound host A and later served back from unbound host B is not scrubbed. On a bound
  host, an upstream API that ignores `Accept-Encoding: identity` and insists on returning a
  compressed `Content-Encoding` fails closed (`502`).
- **Non-scrubbed secret encodings:** Response redaction covers literal, URL-encoded, and
  JSON-escaped forms only. Base64, base64url, hex, case-changed, and HTML-entity echoes (including
  base64-encoded Basic Auth echoes) are not scrubbed.
- **DHCP parser attack surface:** `dnsmasq`'s DHCP parser is a second guest-facing process, holding
  no network capabilities.
- **Denial-flood audit volume:** Denied SNIs never mint a leaf certificate and are audited
  unconditionally alongside denied HTTP requests and DNS queries; disk usage from denial floods is
  bounded by total directory size pruning (`audit.max_total_bytes`, default `10 GiB`, deleting
  oldest closed segments first) plus daily retention pruning (`audit.retain_days`), with per-segment
  rotation at `audit.max_file_bytes`.
- **Per-link connection caps and shared kernel conntrack table:** `http.max_conns_per_link` caps
  accepted connections per link rather than globally across all links, and the Linux kernel
  conntrack table is shared across links (per-link conntrack zones isolate tuple collisions, not
  global conntrack table capacity).
- **Daemon startup trusts `dataplane.ready` rather than reading `table inet gw`:** Unprivileged
  `gateway run` has zero `CAP_NET_ADMIN` and checks sysctls plus `dataplane.ready` existence at
  startup rather than querying the live `nftables` ruleset (which requires root via
  `gateway dataplane check`). Isolation relies on systemd always running `ExecStartPre=+ gateway netsetup`
  first, root-owned `/run/gateway-dataplane/`, and `net.ipv4.ip_forward=0`.
- **Global `records` private-IP exceptions:** Private-address connect-time exceptions come only from
  global `records` entries (`host -> exact IP`), which are not scoped per principal or rule; any
  principal with an allow rule for that host can reach the mapped IP.
- **Non-global fake-IP DNS range (`198.18.0.0/15`):** `198.18.0.0/15` (RFC 2544 benchmarking space)
  is non-global, so a client library's own SSRF filter could refuse synthetic answers in that range
  (all three tested vendor CLIs worked through `198.18.0.0/15` in Phase 3).
- **DNS label leakage under wildcard rules:** Because `gateway` resolves allowlisted hostnames
  upstream when dialing, wildcard allow rules (`*.example.com`) let a guest leak guest-chosen
  labels to that zone's authoritative DNS servers via `gateway`'s upstream resolver. Prefer
  exact-host rules wherever possible (mandatory for multi-product subscription vendor domains).
- **Globally routed host and LAN addresses:** `gateway`'s connect-time guard denies loopback,
  link-local, RFC 1918, CGNAT, and IANA special-purpose ranges, and restricts IPv6 to global unicast
  `2000::/3` minus special ranges. Inside a gateway container, `gateway` cannot distinguish
  globally routed host or LAN unicast IPv4/IPv6 addresses from ordinary internet destinations by
  prefix alone, so an allowlisted domain resolving to such an address is reachable.
- **CA private key at rest:** The operator-supplied `ca_cert` is the trust anchor every guest
  accepts for any hostname, and `ca_key` is the private key that signs leaf certificates under it.
  `ca_key` sits behind the host/gateway-container filesystem boundary; anyone holding `ca_key` plus
  a network position between a guest and `gateway` can impersonate any TLS server to guests.
  `gateway` always verifies upstream TLS certificates against system roots, so `ca_key` alone
  confers no upstream interception. Because the CA carries no name constraints, guests cannot scope
  what they trust `gateway` to intercept.

## Policy Precedence & Reload Semantics

- **Rule precedence:** Evaluation is unified across host scope (DNS/SNI) and request scope and is
  most-specific-first: host (exact before wildcard, longer wildcard suffix before shorter), then
  path-scoped before host-wide (with more-specific paths winning at request scope), then
  method-scoped before method-agnostic; `deny` wins only on an exact rank tie. Consequently, a
  path-scoped `allow` rule or path-scoped ephemeral grant for an exact host outranks a host-wide
  `deny` for that same host at DNS, SNI, and request scope so the handshake succeeds and request
  evaluation enforces the allowed path(s). `DecideDNS` preserves explicit `rule-deny` decisions and
  their `RuleID` instead of collapsing them to `default-deny`. The emergency stop for any live
  session is `gateway revoke` or removing the matching `allow` rule and reloading.
- **Live reload semantics:** On `SIGHUP` or `gateway reload` (serialized under a reload mutex), all
  ephemeral grants are wiped, active flows that are no longer allowed (by host, port, method, or
  path) are torn down immediately via `cancel()` + `conn.Close()` (audited with `error="reload"`),
  and open WebSockets are torn down if a `Binding` is added to their host. Changes to
  `ws_max_egress_bytes`, `records`, or `bindings` otherwise apply only to new flows. Changes to
  `links`, principals, `dns.fake_cidr`, `ca`, `audit`, `admin`, `metrics`, `dataplane`,
  `http.max_header_bytes`, `http.max_conns_per_link`, or `http.upstream_response_header_timeout`
  require a daemon restart and are refused on reload.
