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
| `ports` | no | `[443]` | 80 and 443 only |
| `methods` | no | any method | HTTP methods |
| `paths` | no | any path | Path patterns |
| `allow_websocket` | no | `false` | Permit WebSocket upgrades |
| `ws_max_egress_bytes` | no | `http.ws_max_egress_bytes` | Bytes a guest may send on one WebSocket. 0 means the default |
| `bindings` | no | none | [Secrets](#secrets) |

A guest can resolve a name only if some rule or grant allows that name on port 80 or 443.

### Hosts

`*.example.com` matches any name under `example.com`, at any depth, but not `example.com` itself. The part after `*.` needs at least two labels, so `*.com` is rejected.

A wildcard lets a guest choose DNS labels that reach the zone's name servers, which can carry data out. Prefer exact names.

### Paths

A path pattern starts with `/`. `*` matches within one segment and `**` matches across segments. A pattern may hold one `**` and up to four `*` per segment. Patterns are matched against the decoded path; the query string is not matched.

`gateway` also refuses some requests before rules are consulted, including paths with `..`, `//`, `/./`, a backslash, or an encoded `/` or `\`.

### Which rule wins

Among the rules and grants that match, the most specific one decides. Compare in this order:

1. Host: an exact name beats a wildcard, and a longer wildcard beats a shorter one.
2. A rule with `paths` beats one without.
3. Between path patterns, an exact path beats a pattern with `*`. Between patterns with `*`, more literal characters win.
4. A rule with `methods` beats one without.

If two are still tied, `deny` wins.

A narrow `allow` therefore beats a broad `deny`: with a `deny` for all of `api.example.com` and an `allow` for its `/v1/**`, requests under `/v1/` are allowed. A `deny` that lists `methods` or `paths` applies to HTTP requests only; it does not block the DNS lookup or the TLS handshake.

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

## Records

`records` maps an exact hostname to one IP address. `gateway` then connects to that address without a DNS lookup, even if it is private.

```yaml
records:
  forge.internal.example: 10.0.0.20
```

A record grants no access by itself: a rule must still allow the host. Records apply to every principal, so any principal allowed that host reaches the address.

Upstream TLS certificates are always checked against the gateway's system roots. If the address uses a private CA, install that CA on the gateway.

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

A value of 0 selects the default. Both limits are applied when a new file is opened, and the file being written is never deleted, so the directory can exceed the total limit between rotations.

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
| `fake_cidr` | `198.18.0.0/15` | IPv4 range for the placeholder addresses guests receive, `/30` or larger |
| `ttl_seconds` | 60 | TTL of those answers |

### `http`

| Key | Default | Limit |
|---|---|---|
| `max_request_body_bytes` | 33554432 (32 MiB) | One request body |
| `ws_max_egress_bytes` | 67108864 (64 MiB) | Bytes a guest sends on one WebSocket |
| `max_header_bytes` | 32768 | Headers |
| `max_conns_per_link` | 512 | Concurrent HTTP and HTTPS connections per link; DNS over TCP is not counted |
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
| `rules`, `records`, `dns.ttl_seconds`, `http.max_request_body_bytes`, `http.ws_max_egress_bytes` | `links`, `ca`, `audit`, `admin`, `metrics`, `dataplane`, `dns.fake_cidr`, `http.max_header_bytes`, `http.max_conns_per_link`, `http.upstream_response_header_timeout` |

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

The port defaults to 443 and the TTL to `5m`; `--methods` and `--paths` take comma-separated lists. A grant competes with rules under [the same precedence](#which-rule-wins) and carries no secrets.

The CLI cannot grant WebSocket access. Use the admin API, where `ttl` is required:

```bash
curl --unix-socket /run/gateway/admin.sock http://localhost/v1/grants \
  -d '{"principal":"guest0","host":"example.com","ttl":"5m","allow_websocket":true}'
```

`gateway grant revoke <id>` removes a grant and closes its connections. `gateway revoke --flow ID` or `--principal NAME [--host HOST]` only closes current connections; the guest can open new ones. To remove access that rules give, remove every allow rule that covers it and reload. A `deny` loses to a more specific `allow`.

## Paths used by the systemd units

If you change one of these, change the units in [deploy/](../deploy/) to match.

| Path | Why it is fixed |
|---|---|
| `/usr/local/bin/gateway` | `ExecStartPre` and `ExecStart` |
| `/etc/gateway/gateway.yaml` | Passed as `--config` |
| `/var/log/gateway/audit` | The only log directory the daemon may write (`LogsDirectory`) |
| `/run/gateway` | Created for the admin socket (`RuntimeDirectory`) |
| `/run/gateway-dataplane/dnsmasq.conf` | Read by `gateway-dhcp.service` |
