# Configuration

`gateway` reads one YAML file. The systemd units expect it at `/etc/gateway/gateway.yaml`. Start from [examples/two-links.yaml](../examples/two-links.yaml).

Parsing is strict: an unknown key, a second YAML document or an invalid value rejects the whole file. To check a file without applying anything:

```bash
gateway netsetup --config gateway.yaml --dry-run
```

This validates the file and prints the nftables ruleset, sysctls, `ip` commands and dnsmasq config. It does not read the CA or secret files.

## Links

A link is one network interface on the gateway, with one guest network behind it. The link's principal is the identity that rules and grants apply to. `gateway` takes it from the interface a connection arrives on, never from the guest's source address. At least one link is required.

```yaml
links:
  - name: sbx0
    interface: sbx0
    principal: guest0
    subnet: 10.200.0.0/28
    gateway_ip: 10.200.0.1
    ct_zone: 101
    route_table: 101
```

| Key | Required | Default | Value |
|---|---|---|---|
| `name` | yes | | Unique name. Letters, digits, `.`, `-`, `_`; up to 64 characters |
| `interface` | yes | | Existing interface. Up to 15 letters, digits, `-`, `_` (no `.`). Unique |
| `principal` | yes | | Same character set as `name` |
| `subnet` | yes | | IPv4, `/29` or larger. Must not overlap another link's |
| `gateway_ip` | yes | | The gateway's address inside `subnet`; not the network or broadcast address |
| `ct_zone` | yes | | Unique conntrack zone, 1 to 65535 |
| `route_table` | yes | | Unique routing table number above 0, other than 253, 254 or 255 |
| `route_pref` | no | 1000 plus the link's position (from 0) | Priority of the link's `ip rule` |
| `https_port` | no | 10443 | Local listener behind guest port 443 |
| `http_port` | no | 10080 | Local listener behind guest port 80 |
| `dns_port` | no | 10053 | Local listener behind guest port 53 |

The three listener ports must be distinct and at least 1024. DHCP hands out addresses from the larger free range on either side of `gateway_ip`.

### Removing a link

Remove the link and its rules, then run `systemctl restart gateway.service gateway-dhcp.service`. `netsetup` deletes the address, route and `ip rule` it added to the interface and drops all traffic to, from and through it, including after a reboot. It does not take the interface down.

The interface stays blocked until a link configures it again or you release it. Detach its guests before releasing, because `gateway` no longer filters a released interface:

```bash
gateway netsetup --config /etc/gateway/gateway.yaml --release sbx1
```

## Rules

Everything is denied unless a rule or a temporary grant allows it.

```yaml
rules:
  - id: guest0-api
    principal: guest0
    effect: allow
    hosts: [api.example.com]
    ports: [443]
    methods: [GET, POST]
    paths: ["/v1/**"]
```

| Key | Required | Default | Value |
|---|---|---|---|
| `id` | yes | | Unique. Appears in the audit log |
| `principal` | yes | | A principal declared by a link |
| `effect` | yes | | `allow` or `deny` |
| `hosts` | yes | | Exact hostnames, or `*.zone.tld`. No IP addresses |
| `ports` | no | `[443]` for `allow`, `[80, 443]` for `deny` | 80 and 443 only |
| `methods` | no | any method | HTTP methods |
| `paths` | no | any path | Path patterns |
| `allow_websocket` | no | `false` | Permit WebSocket upgrades |
| `ws_max_egress_bytes` | no | `http.ws_max_egress_bytes` | Bytes a guest may send on one WebSocket. 0 means the default |
| `bindings` | no | none | [Secrets](#secrets) |
| `pins` | no | none | [Pins](#pins) |

A guest can resolve a name only if some rule or grant allows that name on port 80 or 443, and no `deny` covers it.

A key that narrows a rule must not be empty: `hosts: []`, `ports: []`, `methods: []` and `paths: []` are errors, not "any". Leave the key out to get its default. A `deny` without `ports` therefore covers port 80 as well as 443.

### Hosts

`*.example.com` matches any name under `example.com`, at any depth, but not `example.com` itself. The part after `*.` needs at least two labels, and must not be a public suffix, so `*.com`, `*.co.uk` and `*.github.io` are rejected; name a registrable domain such as `*.example.co.uk`.

A wildcard lets a guest choose DNS labels that reach the zone's name servers, which can carry data out. Prefer exact names.

### Paths

A path pattern starts with `/`. `*` matches within one segment and `**` matches across segments. A pattern may hold one `**` and up to four `*` per segment. A pattern ending in `/**` also matches the path without it: `/v1/admin/**` matches `/v1/admin`. Patterns are matched against the decoded path; the query string is not matched. Matching is case-sensitive and exact: `/Admin` is not `/admin`, so deny every spelling your upstream treats alike, or allow only exact paths.

### Request validation

`gateway` refuses some requests with `403`, and records the reason in the audit log, before rules are consulted:

- `CONNECT`, `*` and absolute-URI targets, and `Upgrade` other than an allowed WebSocket.
- Paths with `..`, `//`, `/./`, a backslash, or an encoded `/` or `\` (`%2f`, `%5c`).
- Methods that are not already upper case (`get`, `Get`). A method is forwarded as sent, and rules match it upper-cased.
- Paths that are not valid UTF-8, hold a control byte (below `0x20`, or `0x7f`, including `%00`), or have a segment that starts or ends with a space (`/admin%20`). Servers strip or re-read these.
- Paths with a `;`, plain or encoded (`%3b`). Tomcat, Spring and Jetty drop `;params` from path segments, so `/v1/public/..;/admin` would reach `/admin` after the gateway matched it against `/v1/**`.
- Paths with double encoding: `%25` followed by two hex digits, such as `%252e`. A server that decodes twice turns `%252e%252e` into `..`. A `%25` followed by anything else (`/files/100%25`) is a literal percent sign and passes.

A `;` or an encoded escape in the query string is not refused. Rules match the path as the gateway received it, so an upstream that rewrites paths in other ways is outside what path rules can protect.

### Which rule wins

1. **A matching `deny` wins.** If any `deny` rule matches the request, it is refused, whatever `allow` rules or temporary grants also match and however specific they are. A `deny` is absolute.
2. Otherwise the most specific matching `allow` rule or grant decides. Compare in this order:
   1. Host: an exact name beats a wildcard, and a longer wildcard beats a shorter one.
   2. A rule with `paths` beats one without.
   3. Between path patterns, an exact path beats a pattern with `*`. Between patterns with `*`, more literal characters win.
   4. A rule with `methods` beats one without.

   If two are still tied, the earlier rule in the file wins, and a rule wins over a grant. The winner matters for [secrets](#secrets), [pins](#pins) and WebSockets, which apply only when the winning rule owns them.
3. If nothing matches, the request is refused.

A `deny` is not narrowed by a more specific `allow`. To allow only part of a host, narrow the `allow` and leave the host alone: allow `api.example.com` with `paths: ["/v1/**"]` and it refuses everything else by default. Use a `deny` for what must stay closed whatever else is added later, such as `methods: [DELETE]`.

A `deny` that lists `methods` or `paths` applies to HTTP requests only; it does not block the DNS lookup or the TLS handshake. A `deny` that lists neither blocks the name itself, on the ports it lists.

## Secrets

A binding keeps a credential on the gateway. The guest sends a placeholder, and `gateway` replaces it with the file's contents on the way out.

```yaml
rules:
  - id: guest0-api
    principal: guest0
    effect: allow
    hosts: [api.example.com]
    ports: [443]
    bindings:
      - name: api-token
        host: api.example.com
        header: Authorization
        scheme: bearer
        placeholder: mf_ph_api_token
        secret_file: /etc/gateway/secrets/api-token
```

| Key | Required | Value |
|---|---|---|
| `name` | yes | Unique within the rule. Appears in the audit log |
| `host` | yes | One exact hostname that is also listed in the rule's `hosts` |
| `methods`, `paths` | no | Narrow when the substitution happens |
| `header` | yes | Header to substitute into. Not `Host`, `Content-Length`, `Transfer-Encoding`, `Connection` or `Proxy-Authorization` |
| `scheme` | yes | `bearer`, `token`, `basic` or `raw` |
| `placeholder` | yes | Starts with `mf_ph_`, printable ASCII without spaces, unique across all rules |
| `secret_file` | yes | Absolute path |

Schemes:

- `bearer` and `token`: the header value starts with `Bearer ` or `token ` and contains the placeholder.
- `basic`: the placeholder is inside the base64-decoded Basic credentials.
- `raw`: the placeholder is anywhere in the header value.

Substitution happens only when all of these hold:

- the request is HTTPS on port 443 and not a WebSocket upgrade
- the rule that wins for the request is the one that owns the binding
- the binding's host, methods and paths match

If a more specific rule or a grant wins instead, nothing is substituted. After substitution, `gateway` drops `Proxy-Authorization` and every header that still contains `mf_ph_`, on every request. It does not search URLs or bodies.

Bindings are allowed only on `allow` rules that include port 443. WebSockets are not available on a host with a binding, for any principal: a config whose `allow_websocket` rule covers such a host, by name or wildcard, is rejected, and so is a WebSocket grant for it.

Create the file so that the `gateway` group can read it, then put the secret in it on a single line:

```bash
install -d -o root -g gateway -m 0750 /etc/gateway/secrets
install -o root -g gateway -m 0640 /dev/null /etc/gateway/secrets/api-token
nano /etc/gateway/secrets/api-token
```

The service cannot see files under `/home` or `/root`, and has its own `/tmp`. In the guest, use the placeholder where the secret would go, such as `Authorization: Bearer mf_ph_api_token`.

The file is read on each request, so you can replace it without a reload. One trailing newline is removed.

A host with a binding is a bound host for every principal. On each request to it:

- `gateway` first reads every secret bound to the host. If any file is unreadable, empty or has other line breaks, the request is refused with `403` and nothing is sent, even for a principal or request that needs no substitution.
- It removes `Range` and `If-Range` and asks for an uncompressed response. A compressed or partial (`206`) response is answered with `502`.
- It replaces echoed secrets in the response with their placeholders. The [threat model](threat-model.md#goal-2-keep-secrets-out-of-the-guest) lists what that misses.

## Pins

A rule may pin hosts it covers to an address. `gateway` then connects to that address without a DNS lookup, even if it is private. This is how a LAN service is reached without opening the private address space.

```yaml
rules:
  - id: guest0-forge
    principal: guest0
    effect: allow
    hosts: [forge.internal.example]
    pins:
      forge.internal.example: 10.0.0.20
```

A pin applies only to requests that its rule decides, for its principal. A request for the same host that a different rule or a grant decides is resolved normally and is refused if the name resolves to a private address. Pinned connections are never reused for another request, so every pinned request opens a new upstream connection.

A pin's host must be an exact name that one of the rule's `hosts` covers. The address must be unicast. These are refused: loopback, `0.0.0.0/8`, link-local (including `169.254.0.0/16`), multicast, anything inside `dns.fake_cidr`, anything inside a link's subnet (which includes every `gateway_ip`), and IPv6 outside global unicast `2000::/3` and unique local `fc00::/7`. Private RFC 1918, carrier-grade NAT (`100.64.0.0/10`) and unique local addresses are the intended use and are accepted.

A rule that pins grants no access by itself, and is subject to every `deny`. Upstream TLS certificates are always checked against the gateway's system roots. If the address uses a private CA, install that CA on the gateway.

## Other settings

### `ca`

| Key | Required | Value |
|---|---|---|
| `cert_path` | yes | CA certificate that guests trust |
| `key_path` | yes | Its private key |

`gateway ca init --cert PATH --key PATH` creates both, valid for ten years. It refuses to overwrite existing files and writes the key with mode `0600`, so give the `gateway` group read access afterwards.

### `audit`

| Key | Required | Default | Value |
|---|---|---|---|
| `dir` | yes | | Directory for the JSONL files |
| `retain_days` | no | 30 | Age at which files are deleted |
| `max_file_bytes` | no | 104857600 (100 MiB) | Size at which a new file starts |
| `max_total_bytes` | no | 10737418240 (10 GiB) | Size limit for the directory; oldest files go first |
| `stdout_json` | no | `false` | Also write records to stdout |

A value of 0 selects the default. `max_file_bytes` must not exceed `max_total_bytes`. Both limits are applied when a new file is opened, and the file being written is never deleted, so the directory can exceed the total limit between rotations.

### `admin` and `metrics`

| Key | Default | Value |
|---|---|---|
| `admin.socket` | none, which disables the admin API | Unix socket for the CLI. The CLI looks at `/run/gateway/admin.sock` unless given `--socket` |
| `admin.socket_group` | the daemon's group | Group that may use the socket (mode `0660`) |
| `metrics.listen` | none, which disables metrics | `IP:port` to serve Prometheus metrics. Wildcard addresses and hostnames are rejected |

Anyone who can open the admin socket can create grants and reload the config.

### `dataplane`

| Key | Required | Default | Value |
|---|---|---|---|
| `ready_file` | yes | | Marker that `netsetup` writes last; the daemon refuses to start without it |
| `state_file` | no | `/var/lib/gateway-dataplane/links.json` | Record of every interface `netsetup` has managed, used to [block removed ones](#removing-a-link) |
| `dhcp.user` | yes | | User dnsmasq runs as |
| `dhcp.lease_file` | yes | | DHCP lease file |
| `dhcp.config_path` | for the shipped units | | Where `netsetup` writes the dnsmasq config |
| `dhcp.lease_time` | no | `12h` | At least `1m`, or `infinite` |

`ready_file`, `state_file` and `config_path` must be outside the admin socket's directory. `netsetup` writes them only into a directory owned by root and not writable by group or others.

Keep `state_file` on storage that survives reboots. If you move or delete it and the host reboots before `netsetup` has run again, removed interfaces are forgotten. If it is unreadable or corrupt, `netsetup` fails. Restore it, or delete it and detach every removed interface.

### `dns`

| Key | Default | Value |
|---|---|---|
| `fake_cidr` | `198.18.0.0/15` | IPv4 range for the placeholder addresses guests receive, `/30` or larger. Must not overlap any link's `subnet` |
| `ttl_seconds` | 60 | TTL of those answers |

Guests connect to these addresses, and `gateway` redirects the connection, so the range never carries real traffic and `gateway` never dials an address inside it.

Some clients refuse to connect to special-purpose addresses before they ever reach the network. What the default meets:

- Python `ipaddress`: `198.18.0.0/15` is `is_private` and not `is_global`. `100.64.0.0/10` is neither private nor global.
- `ipaddr.js` and the Node filters built on it (`ssrf-req-filter`, `request-filtering-agent`) accept only the `unicast` range name. They refuse `198.18.0.0/15` (`reserved`) and `100.64.0.0/10` (`carrierGradeNat`).
- Go libraries that follow the IANA special-purpose registry, such as `code.dny.dev/ssrf`, refuse both. Filters built on `netip.Addr.IsPrivate` accept both.
- Gemini CLI's web fetch refuses `198.18.0.0/15` by name and every non-`unicast` `ipaddr.js` range.

No special-purpose range passes a strict filter, so no default can be accepted everywhere. The default stays `198.18.0.0/15`, which no real host uses and no guest can reach. If a client in your guests refuses it, set `fake_cidr` to a globally routable range that nothing in your guests needs to reach directly. That is safe here, because every guest connection on ports 80 and 443 goes to the gateway, but a name that really resolves into the range then cannot be reached.

### `http`

| Key | Default | Limit |
|---|---|---|
| `max_request_body_bytes` | 33554432 (32 MiB) | One request body |
| `ws_max_egress_bytes` | 67108864 (64 MiB) | Bytes a guest sends on one WebSocket |
| `max_header_bytes` | 32768 | Headers |
| `max_conns_per_link` | 512 | Concurrent connections per link. HTTP and HTTPS share one budget of this size, and DNS over TCP has its own. DNS over UDP is not limited |
| `upstream_response_header_timeout` | `10m` | Wait for an upstream's response headers |

The WebSocket upgrade handshake has a fixed 30 second limit.

## Reload

```bash
gateway reload
```

If the new file is invalid or changes a setting that needs a restart, the command reports the error and the old config stays active.

`systemctl reload gateway` only signals the daemon. It succeeds even when the reload is refused, so check `journalctl -u gateway` or use `gateway reload`.

| Applied on reload | Needs a restart |
|---|---|
| `rules` (including `pins`), `dns.ttl_seconds`, `http.max_request_body_bytes`, `http.ws_max_egress_bytes` | `links`, `ca`, `audit`, `admin`, `metrics`, `dataplane`, `dns.fake_cidr`, `http.max_header_bytes`, `http.max_conns_per_link`, `http.upstream_response_header_timeout` |

A successful reload:

- removes every temporary grant
- closes connections that relied on a grant, are no longer allowed, or are now decided by a different rule
- closes WebSockets that are no longer allowed, including on hosts that gained a binding

Other changes affect new requests only.

## Temporary grants

A grant allows one exact host for one principal until it expires. It exists only in memory.

```bash
gateway grant --principal guest0 --host example.com --ttl 5m
```

The port defaults to 443 and the TTL to `5m`; `--methods` and `--paths` take comma-separated lists. A grant competes with the `allow` rules under [the same precedence](#which-rule-wins), is overridden by any `deny`, and carries no secrets or pins.

The CLI cannot grant WebSocket access. Use the admin API, where `ttl` is required:

```bash
curl --unix-socket /run/gateway/admin.sock http://localhost/v1/grants \
  -d '{"principal":"guest0","host":"example.com","ttl":"5m","allow_websocket":true}'
```

`gateway grant revoke <id>` removes a grant and closes its connections. `gateway revoke --flow ID` or `--principal NAME [--host HOST]` only closes current connections; the guest can open new ones. To remove access that rules give, add a `deny` that covers it, or remove the allow rules, and reload. A `deny` wins over every allow rule and grant.

## Paths used by the systemd units

If you change one of these, change the units in [deploy/](../deploy/) to match.

| Path | Why it is fixed |
|---|---|
| `/usr/local/bin/gateway` | `ExecStartPre` and `ExecStart` |
| `/etc/gateway/gateway.yaml` | Passed as `--config` |
| `/var/log/gateway/audit` | The only log directory the daemon may write (`LogsDirectory`) |
| `/run/gateway` | Created for the admin socket (`RuntimeDirectory`) |
| `/run/gateway-dataplane/dnsmasq.conf` | Read by `gateway-dhcp.service` |
