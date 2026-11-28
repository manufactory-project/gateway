# gateway

A network gateway that limits what sandboxed Linux guests can reach. It runs headless on Linux, and each guest connects to it over its own network link.

Treat the guest as hostile, including root inside it. `gateway` then:

- blocks the host, the LAN, cloud metadata endpoints and other guests by default
- allows only DNS, DHCP and HTTP/HTTPS (including permitted WebSockets) from a guest
- checks each HTTPS and HTTP request against a default-deny allowlist, per guest, by host, method and path (TLS is intercepted with a CA you generate)
- keeps declared API keys outside the guest, which holds a placeholder that `gateway` swaps for the secret on the way out
- writes a JSONL audit log, and refuses requests when it cannot write it

It does not stop data from leaving through destinations you allow. An agent can still send anything to an allowed host, or use a credential for everything that credential permits. Read the [threat model](docs/threat-model.md), including its accepted risks, before relying on `gateway`.

Status: v0.1, egress only: it controls connections that guests open. Handling ingress is a goal and is not built.

## Where it fits

`gateway` does not create sandboxes. It sits between a guest you already isolate and the network. The guest's only network interface must lead to the gateway; a second interface is a way around it.

| Guest | Status |
|---|---|
| Incus containers | Follow [Set up with Incus](#set-up-with-incus). The repository's end-to-end test uses Incus containers. CI does not run it. |
| Incus VMs and other VMs | Not tested. See [Other VMs and hosts](#other-vms-and-hosts). |
| Docker and Podman | Not supported. There is no image or setup for them, and installation assumes systemd and permission to change kernel network settings. |

## Set up with Incus

This creates a gateway container and two guests:

```text
guest0 ---[gw-sbx0]--- sbx0 [        ]
                            [   gw   ] eth0 ---[incusbr0]--- internet
guest1 ---[gw-sbx1]--- sbx1 [        ]
```

These steps were last tried with Incus 6.0 and Ubuntu 24.04 containers. CI does not run them.

Give `gateway` its own container or VM. Its setup turns off IPv4 and IPv6 forwarding for that whole system, which would break other networking on a shared host.

If Docker also runs on the Incus host, its firewall can drop Incus traffic. These rules let the containers reach the internet through `incusbr0`, and each guest reach the gateway. They do not survive a reboot:

```bash
sudo iptables -I DOCKER-USER -i incusbr0 -j ACCEPT
sudo iptables -I DOCKER-USER -o incusbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -I DOCKER-USER -i gw-sbx0 -o gw-sbx0 -j ACCEPT
sudo iptables -I DOCKER-USER -i gw-sbx1 -o gw-sbx1 -j ACCEPT
```

### 1. Create the networks and the gateway

Run on the Incus host. These commands assume your default profile gives instances an `eth0` on a network with internet access, such as `incusbr0`.

```bash
incus network create gw-sbx0 --type=bridge ipv4.address=none ipv6.address=none
incus network create gw-sbx1 --type=bridge ipv4.address=none ipv6.address=none

incus init images:ubuntu/24.04 gw
incus config device add gw sbx0 nic network=gw-sbx0 name=sbx0
incus config device add gw sbx1 nic network=gw-sbx1 name=sbx1
incus start gw
incus exec gw -- bash
```

### 2. Install gateway

Run the rest of this step as root inside `gw`.

Install the packages:

```bash
apt-get update
apt-get install -y nftables dnsmasq-base iproute2 ca-certificates curl git jq
```

Install Go 1.26.11 or later by following [go.dev/doc/install](https://go.dev/doc/install). Ubuntu 24.04's `golang-go` package is older. Then clone and build:

```bash
git clone https://github.com/manufactory-project/gateway.git
cd gateway
CGO_ENABLED=0 go build -o /usr/local/bin/gateway ./cmd/gateway
CGO_ENABLED=0 go build -o /usr/local/bin/gateway-probe ./cmd/gateway-probe
```

Create the users and directories:

```bash
getent group gateway >/dev/null || groupadd --system gateway
id -u gateway >/dev/null 2>&1 || useradd --system --gid gateway --no-create-home --shell /usr/sbin/nologin gateway
id -u dnsmasq >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin dnsmasq

install -d -o root -g gateway -m 0750 /etc/gateway /etc/gateway/ca
install -d -o dnsmasq -g "$(id -gn dnsmasq)" -m 0750 /var/lib/gateway
```

Add the config and create the CA. [examples/two-links.yaml](examples/two-links.yaml) expects interfaces `sbx0` and `sbx1` and lets both guests reach `httpbingo.org` on port 443.

```bash
install -o root -g gateway -m 0640 examples/two-links.yaml /etc/gateway/gateway.yaml

gateway ca init --cert /etc/gateway/ca/ca.crt --key /etc/gateway/ca/ca.key
chown root:gateway /etc/gateway/ca/ca.crt /etc/gateway/ca/ca.key
chmod 0644 /etc/gateway/ca/ca.crt
chmod 0640 /etc/gateway/ca/ca.key
```

Anyone who has `ca.key` and sits between a guest and the gateway can impersonate any TLS server to that guest. Keep it on the gateway.

Start the services and check them:

```bash
install -m 0644 deploy/gateway.service deploy/gateway-dhcp.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now gateway.service gateway-dhcp.service

gateway dataplane check --config /etc/gateway/gateway.yaml
gateway status
```

If `gateway status` reports `no such file or directory`, the daemon has not created its socket yet. Run it again.

Leave the container with `exit`.

### 3. Create the guests

On the Incus host:

```bash
incus init images:ubuntu/24.04 guest0 --network gw-sbx0
incus init images:ubuntu/24.04 guest1 --network gw-sbx1
incus start guest0 guest1
```

Check that each guest has exactly one network device, on its own `gw-sbx` network:

```bash
incus config show guest0 --expanded
incus config show guest1 --expanded
```

Copy the CA certificate (never the key) and the probe into both guests:

```bash
incus file pull gw/etc/gateway/ca/ca.crt ca.crt
incus file pull gw/usr/local/bin/gateway-probe gateway-probe
for g in guest0 guest1; do
  incus file push ca.crt "$g/usr/local/share/ca-certificates/gateway.crt"
  incus file push gateway-probe "$g/usr/local/bin/gateway-probe" --mode 0755
  incus exec "$g" -- update-ca-certificates
done
```

### 4. Check containment

Start a listener in `guest1`, so there is something `guest0` must fail to reach. It needs Python 3 in the guest. Leave it running in its own terminal:

```bash
incus exec guest1 -- python3 -m http.server 8080
```

Find the addresses of `guest1` and of the gateway's `eth0`:

```bash
incus list
```

Run the probe in `guest0`:

```bash
incus exec guest0 -- gateway-probe --allow-host httpbingo.org --link-ip 10.200.0.1 --lan-addr LAN_IP:PORT --mgmt-ip GATEWAY_MGMT_IP --peer-link-ip 10.200.0.17 --peer-guest-addr GUEST1_IP:8080
```

Replace `LAN_IP:PORT` with a LAN service that the gateway can reach and the guest must not. Use a port other than 53, 80 or 443: `gateway` intercepts those, so the result says nothing about the LAN. Replace `GATEWAY_MGMT_IP` and `GUEST1_IP` with the addresses you found.

The probe prints one JSON line per check and exits non-zero if any check fails. The "unreachable" checks also pass when an address is wrong or nothing is listening, so confirm each target answers from a machine that is allowed to reach it. The IPv6 and QUIC (UDP 443) checks cannot be confirmed this way: the probe has no allowed peer to compare them with.

To check `guest1`, swap the roles: listen in `guest0`, use `--link-ip 10.200.0.17` and `--peer-link-ip 10.200.0.1`, and give `guest0`'s address to `--peer-guest-addr`.

## Other VMs and hosts

Only Incus containers are covered by a test. The gateway needs systemd, `nftables`, `iproute2` and `dnsmasq-base`, and guest links use IPv4 only. Install it as in [step 2](#2-install-gateway), then provide:

1. A separate network segment for each guest, connecting its one interface to its own interface on the gateway. The gateway interface names must match `links[].interface` in the config. `gateway` configures those interfaces but does not create them.
2. A separate interface on the gateway for its connection to the internet.
3. No other route out of the guest, including through the virtualization host.
4. A guest default route to the link's `gateway_ip`, and a DNS server setting. DHCP provides both. With a static address, add the routes yourself; DNS requests on port 53 to any address are redirected to `gateway`.
5. The CA certificate (`/etc/gateway/ca/ca.crt`, never the key) in the guest's trust store.

Run `gateway-probe` inside each guest, as in [step 4](#4-check-containment), before trusting the setup.

## Configure

One YAML file, `/etc/gateway/gateway.yaml`, defines the links, the rules and any secrets. Each link names a principal, and rules apply to principals. Anything no rule allows is denied:

```yaml
rules:
  - id: guest0-test-upstream
    principal: guest0
    effect: allow
    hosts: [httpbingo.org]
    ports: [443]
    methods: [GET, POST]
    paths: ["/**"]
```

Check an edited file, then apply it:

```bash
gateway netsetup --config /etc/gateway/gateway.yaml --dry-run
gateway reload
```

A reload drops all temporary grants and closes connections that are no longer allowed. Changing links and some other settings needs a restart instead.

The [configuration reference](docs/configuration.md) covers:

- [rules](docs/configuration.md#rules) and [which rule wins](docs/configuration.md#which-rule-wins)
- [secrets](docs/configuration.md#secrets): how to create the files; the guest sends a placeholder and `gateway` fills in the real value
- [links](docs/configuration.md#links), for adding a guest
- [what a reload applies](docs/configuration.md#reload)

A [removed link](docs/configuration.md#removing-a-link) stays blocked until you release it. To add a guest, attach a new network to the gateway, add a link and its rules, and run `systemctl restart gateway.service gateway-dhcp.service`. The restart drops open connections and temporary grants. Setup fails for the whole gateway if a configured interface is missing.

Examples:

- [examples/two-links.yaml](examples/two-links.yaml): two guests, one allowed host each
- [examples/gateway.yaml](examples/gateway.yaml): secrets, WebSockets and a static DNS record. It does not load until you replace `<forge-ip>`, and its binding needs a secret file at `/run/credentials/gateway/forgejo-token`, which nothing creates for you
- [examples/workers.yaml](examples/workers.yaml): path rules for three coding agent CLIs, with [notes](examples/workers.md)

## Operate

Run these inside the gateway, as root or a member of the `gateway` group:

```text
gateway status
gateway reload
gateway flows
gateway revoke (--flow ID | --grant ID | --principal NAME [--host HOST])
gateway grant --principal NAME --host HOST [--port 443|80] [--methods CSV] [--paths CSV] [--ttl 5m]
gateway grants
gateway grant revoke <id>
```

`grant` allows a host temporarily. Without `--methods` or `--paths`, it does not restrict them. The command cannot grant WebSocket access; that takes a request to the admin API.

`revoke` closes open connections. It does not stop new ones. To block a guest's access, remove the allow rule and run `gateway reload`, or stop the guest.

These commands talk to the daemon over `/run/gateway/admin.sock`. Put `--socket PATH` before the subcommand to use another socket. `--json` works anywhere on the command line.

The example configs serve Prometheus metrics at `http://127.0.0.1:9102/metrics`:

| Metric | Counts |
|---|---|
| `gateway_requests_total` | Requests, by principal, effect, status and reason |
| `gateway_dns_queries_total` | DNS queries, by principal and effect |
| `gateway_conns_rejected_total` | HTTP, HTTPS and DNS over TCP connections dropped at the link limit |
| `gateway_active_flows`, `gateway_active_grants` | Current flows and grants |
| `gateway_reloads_total` | Reload attempts, by result |
| `gateway_revocations_total` | Flows closed by revocation, grant expiry or reload |
| `gateway_audit_write_errors_total` | Failed audit writes |
| `gateway_audit_size_pruned_bytes_total` | Log bytes deleted to stay under the size limit |

## Audit log

Records are written to `audit.dir` (`/var/log/gateway/audit` in the examples). Header values are never recorded, and query strings are stripped.

Each record has a `kind`: `dns`, `request_admitted`, `request`, `websocket`, `grant`, `revoke` or `lifecycle`. `src_ip` comes from the guest and is not trusted; use `principal`. When `gateway` or the client cuts a connection short, the completion record's `error` says why: `revoked`, `grant-expired`, `reload` or `client-canceled`. Connection, DNS, certificate and blocked-address errors are recorded in full; other upstream failures only as `upstream-error`, sometimes with a category such as `timeout` or `tls`.

```bash
tail -F /var/log/gateway/audit/*.jsonl | jq .
```

To find out why something was blocked:

```bash
tail -F /var/log/gateway/audit/*.jsonl | jq 'select(.effect == "deny")'
```

With `audit.stdout_json: true`, as in the examples, records also go to stdout for journald or Loki.

Files are deleted by age (`retain_days`) and when the directory passes `max_total_bytes` (10 GiB by default). Writes are not `fsync`ed, so a power loss or kernel crash can lose the latest records.

## More

- [Configuration](docs/configuration.md): every setting, rule precedence, secrets and reload
- [Threat model](docs/threat-model.md): what is protected, what is not and accepted risks
- [Architecture](docs/architecture.md): processes, request path, failures and packages
- [Contributing](CONTRIBUTING.md): build, test and change the code
