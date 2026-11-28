# Threat model

What `gateway` v0.1 protects against, and what it does not. For how it works, see [architecture](architecture.md).

## Assumptions

- **The guest is hostile**, including root inside it. It may be steered by prompt injection, untrusted repository content or code it runs. Nothing here depends on the guest cooperating.
- **The gateway host and the hypervisor or container runtime are trusted.**
- **Each guest is alone on its link.** `gateway` identifies a guest by the interface it connects through. Guests that share a network segment share a principal and can reach each other without passing through `gateway`.
- **The admin socket is full control.** Anyone who can open it can create grants and reload the config.

`gateway` controls connections that guests open. It forwards nothing, so nothing outside can open a connection into a guest through it.

## Goal 1: keep guests off the host, the LAN and each other

Protected, given the assumptions:

- A guest reaches the gateway only for DHCP, DNS, HTTP and HTTPS. Other traffic to the gateway, and all traffic through it, is dropped, including IPv6.
- Outbound connections are made by the gateway, by hostname, and only to hosts a rule or grant allows.
- Connections to loopback, link-local (including cloud metadata), private, carrier-grade NAT and other special-purpose addresses are refused, whatever name resolves to them.

Not protected:

- **Globally routed host or LAN addresses.** The gateway cannot tell them apart from the internet. An allowed name that resolves to one is reachable.
- **Addresses in a rule's `pins`.** These are deliberate exceptions to the private-address guard, open only to requests that rule decides. A pin can never be loopback, link-local, multicast, inside `dns.fake_cidr` or inside a link subnet.

## Goal 2: keep secrets out of the guest

Protected:

- The guest holds a placeholder. `gateway` puts the real value into one named header, only on HTTPS, and only when the rule that owns the binding allows the request.
- Placeholders left in request headers are removed before the request leaves.
- A host with any binding is a bound host for every principal. In its responses (headers, bodies and trailers), echoes of every secret bound to it are replaced with placeholders. Each character of the secret matches itself or any escape of it, in any mix: percent-encoding in either hex case (including a `+` for a space), JSON `\uXXXX` in either hex case (including `=` and surrogate pairs), and JSON one-character escapes such as `\/`. The `base64(user:secret)` that `gateway` sends for a Basic binding is matched the same way.
- The guest cannot choose where the placeholder sits: a bound header is substituted only when it is exactly `<Scheme> <placeholder>` (`raw`: exactly the placeholder; `basic`: `user:<placeholder>`). Any other use of the placeholder in that header is refused with `403`.
- A secret file must be a regular, private (not world-accessible) file of at most 64 KiB, and not a symlink; anything else is refused with `403`.
- So that a response can always be checked, bound hosts get no `Range` requests or compression, partial and compressed responses are refused, WebSockets are refused, and nothing is sent unless every secret for the host can be read.
- Once a request has been sent, a failure is recorded in the audit log as a category, not as the error text, which could quote the secret.

Not protected:

- **Use of the credential.** The guest can do anything the credential permits on the allowed methods and paths, such as pushing to a repository the token can write. Narrow the token at its issuer and narrow the rule.
- **Credentials the guest already holds**, such as a CLI's login token stored in the guest. `gateway` does not hide or restrict them.
- **Other echo encodings**: base64 (other than the Basic header `gateway` sent), base64url, hex, changed case and HTML entities.
- **Reflection through another host.** A secret that an upstream stores and later serves from a host without a binding for it is not replaced.

## Goal 3: limit and record what leaves

This goal is limited by design: **data can leave through any destination you allow.**

Provided:

- Default deny per principal, checked for each DNS lookup and each HTTP request.
- A JSONL record of each DNS and request decision, naming the principal. Paths are recorded; query strings, headers and bodies are not. If the record cannot be written before a lookup is answered or a request is sent, it is refused. Connections dropped at the connection limit are only counted in metrics. Work refused by a per-link rate or in-flight limit is counted in metrics too and is recorded as a summary record carrying a `count`, at most once per link and reason every 10 seconds, instead of one record per refusal.
- Limits per link, so one guest cannot slow another: concurrent connections (HTTP and HTTPS together, and DNS over TCP separately), requests in flight, DNS queries per second (UDP and TCP), denied TLS handshakes per second, new leaf certificates per second, HTTP/2 streams per connection, upstream connections per host, and idle time on a stalled request body, response or handshake. Also request body size, header size, bytes a guest sends on a WebSocket, and total audit log size.
- Every TLS handshake is a full one: the gateway issues no session tickets, so the SNI check, its audit record and the denied-handshake limit cannot be skipped by resuming a session.

Not prevented:

- **Data in allowed requests**: paths, query strings, headers and bodies.
- **Another account on an allowed host.** An allowed API accepts whatever credential the guest sends, so data can go to an account you do not own.
- **Anything an allowed host serves**, such as telemetry endpoints or downloadable plugins on the same domain as an API. Path rules narrow this.
- **DNS labels under a wildcard rule.** Names under `*.example.com` are resolved upstream, so the guest can send data to that zone's name servers.

## Accepted risks

| Risk | Effect | What you can do |
|---|---|---|
| `ca.key_path` is a trust anchor with no name constraints | Anyone with the key and a position between a guest and the gateway can impersonate any TLS server to that guest. It does not let them intercept the gateway's own upstream connections | Keep the key on the gateway, readable only by the `gateway` user |
| The daemon does not read the live nftables ruleset at startup | It checks sysctls and a marker file that `netsetup` writes. If the table is removed afterwards, the daemon does not notice | Start it through the shipped unit, which reruns `netsetup`. Run `gateway dataplane check` as root to monitor |
| `gateway dataplane check` checks that the table and chains exist | Altered rules inside a chain pass | Restrict who has root on the gateway |
| Removed links are blocked by interface name, only once `netsetup` has run | They are open between boot and `netsetup`, if it fails before loading rules, if another tool flushes the ruleset, or if the interface is renamed or added to a bridge or bond. A link removed before this record existed, or whose record is lost, is not blocked after a reboot | Detach removed guests; do not flush the ruleset |
| dnsmasq parses DHCP from guests | A second program exposed to guests. It drops root and network capabilities after starting | Keep dnsmasq updated |
| Connection limits are per link, and the kernel conntrack table is shared | Many guests together can use up shared capacity | Size the host for the number of links |
| Denied requests are logged | A guest can fill the audit log up to its limit and push out older records | Ship records elsewhere with `audit.stdout_json` |
| Audit writes are not `fsync`ed | A crash or power loss can lose the latest records | Ship records elsewhere |
| Guests receive addresses from `198.18.0.0/15` | A client that refuses every special-purpose address (Python `ipaddress.is_global`, `ipaddr.js` `unicast`-only filters) refuses them, and no special-purpose range avoids that | Set `dns.fake_cidr` to a globally routable range the guests never need to reach. `gateway` refuses to dial it either way. See [`dns`](configuration.md#dns) |

## Stopping access

Removing access needs a policy change: remove every allow rule and grant that covers it, then reload. A matching `deny` wins over every allow rule and grant, so adding one also works. `gateway revoke --flow` or `--principal` closes current connections, and the guest can open new ones. Stopping the guest always works. See [rule precedence](configuration.md#which-rule-wins) and [reload](configuration.md#reload).

## Verification

`task check` runs the unit and integration tests, including tests for the refusals above. [`e2e/run.sh`](../e2e/run.sh) builds a two-guest Incus setup and probes containment from inside the guests; CI does not run it.
