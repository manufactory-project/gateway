# Architecture

How `gateway` v0.1 works. For what it protects against, see the [threat model](threat-model.md); for settings, [configuration](configuration.md).

## Processes

```text
                   gateway host
 guest ──sbx0──▶ nftables ──▶ gateway run ──▶ upstream
         │                      ▲
         └─DHCP──▶ dnsmasq      └── gateway CLI (Unix socket)

 gateway netsetup (root, before start) sets up nftables, sysctls, addresses
 and routes, and writes the dnsmasq config
```

| Process | Runs as | Job |
|---|---|---|
| `gateway netsetup` | root, once, as `ExecStartPre=+` | Configure the kernel and links; write the dnsmasq config and a ready file |
| `gateway run` | `gateway`, no capabilities | DNS, HTTPS and HTTP listeners per link; admin API; metrics |
| `dnsmasq` | started as root, drops to `dhcp.user` | DHCP only; its DNS server is off |
| `gateway` CLI | operator | Talk to the daemon; `ca init` works offline and `dataplane check` needs root |

`netsetup` removes the old ready file first, records the interfaces it manages in `dataplane.state_file`, sets sysctls, loads the nftables table and checks that it exists, and only then brings up the links. Recorded interfaces that no link configures are blocked, and the addresses and routes it gave them are deleted. It writes the dnsmasq config and the ready file last, in `/run/gateway-dataplane/`, which only root can write.

`gateway run` refuses to start if a sysctl is wrong or the ready file is missing. It cannot read the nftables table without privileges.

`gateway-dhcp.service` starts after `gateway.service` and requires it.

## Packet path

All filtering is in one table, `inet gw`. All traffic on removed links is dropped. For configured links:

1. Each link gets its own conntrack zone.
2. IPv6 is dropped, as is anything addressed to the gateway itself except DNS and DHCP.
3. TCP and UDP port 53 to any address, and TCP ports 443 and 80, are redirected to the link's listeners.
4. The input chain accepts redirected and DHCP traffic and drops the rest.
5. The forward chain drops everything to or from a link. IP forwarding is also off.

Replies leave through the right link by a per-link routing table.

## Request path

**DNS.** The daemon never forwards a guest's query.

1. Check the name against the principal's rules and grants.
2. For an allowed `A` query, answer with an address from `dns.fake_cidr`, derived from the name.
3. For `AAAA`, `HTTPS` and `SVCB`, answer with no records. Refuse other types.

**HTTPS and HTTP.**

1. Accept the connection if the link is under its connection limit.
2. For HTTPS, check the TLS server name. Only an allowed name gets a certificate, signed by the gateway CA.
3. Check the request: no `CONNECT`, a canonical origin-form path, a `Host` that matches the port and the TLS server name, and no upgrade other than WebSocket.
4. Evaluate rules and grants for this request.
5. Build the outbound headers. For a bound host, read all its secrets first and remove range and compression requests. Substitute, then remove leftover placeholders.
6. Register the flow, and check the decision again if the config or grants changed meanwhile.
7. Write the admission audit record.
8. Connect by hostname. Unless `records` pins the address, resolve it and check every address at connect time.
9. Relay the response without following redirects. On a bound host, refuse compressed or partial responses and replace echoed secrets, holding back only bytes that could begin one.
10. Write the completion record.

A WebSocket follows the same steps without substitution, then is relayed until either side closes it or the guest reaches its byte limit.

## When something fails

| Condition | Result |
|---|---|
| Invalid config, wrong sysctl, missing ready file, bad CA pair or unwritable audit directory | The daemon does not start |
| Interface record unreadable or corrupt | `netsetup` fails; no ready file |
| Audit write fails before a lookup is answered or a request is sent | DNS answers `SERVFAIL`; HTTP answers `503` without connecting |
| Audit write fails after an admin action | The action stands; the API answers `503` (a new grant is withdrawn) |
| Name not allowed | DNS `REFUSED` |
| DNS opcode other than query | `NOTIMP` |
| DNS response packet sent by a guest | Ignored and recorded |
| TLS server name missing, an IP address or not allowed | Handshake fails; no certificate is created |
| Connection limit reached | Connection closed |
| Request fails a check or a rule | `403`; `400` for a WebSocket upgrade with a body; `413` for an oversized body |
| Any secret file for a bound host unreadable | `403`, nothing sent |
| Upstream certificate untrusted, or connection fails | `502` |
| Blocked destination address | `502` |
| Compressed or partial response from a bound host | `502` |
| Unexpected protocol upgrade from upstream | `502` |

## Flows, reloads and grants

The flow registry tracks each HTTP request, HTTP/2 stream and WebSocket. Closing a flow cancels its request and closes the guest connection, so other HTTP/2 streams on that connection drop too. For WebSockets, the upstream connection is closed directly.

A reload parses the whole file, refuses changes that need a restart, swaps the config in one step, drops all grants, closes flows that are no longer allowed or are now decided by a different rule, and closes idle upstream connections.

Grants are held in memory. A background task removes expired ones and closes their flows.

## Audit log

One writer serves every listener and the admin API. It writes records synchronously but does not `fsync`. DNS answers and request admissions are recorded before they go ahead. Completion records, reloads, revocations and grant removals are recorded afterwards. Files rotate daily and at a size limit, and old files are deleted by age and total size.

There is no audit query API. Read the files, or ship stdout records to a log system.

## Packages

| Package | Contents | Imports from this module |
|---|---|---|
| `internal/config` | Schema, validation, reload, grants | none |
| `internal/audit` | JSONL writer, rotation, pruning | none |
| `internal/ca` | CA creation and loading, certificate cache | none |
| `internal/connlimit` | Per-link connection cap | none |
| `internal/metrics` | Prometheus collector and listener | none |
| `internal/policy` | Rule and grant matching | `config` |
| `internal/netguard` | Connect-by-name and address checks | `config` |
| `internal/netsetup` | nftables, sysctls, `ip` and dnsmasq config | `config` |
| `internal/secret` | Secret files, substitution, redaction | `config` |
| `internal/dns` | DNS server | `audit`, `config`, `connlimit`, `policy` |
| `internal/admin` | Admin API and client | `audit`, `config`, `metrics` |
| `internal/proxy` | HTTP, TLS and WebSocket handling | `audit`, `ca`, `config`, `connlimit`, `netguard`, `policy`, `secret` |
| `cmd/gateway` | Daemon and CLI | wires the packages together |
| `cmd/gateway-probe` | Guest-side containment checks | none; standard library only |

`task lint` enforces that `internal/admin` does not depend on `proxy`, `secret`, `policy` or `netguard`.
