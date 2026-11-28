# `gateway`

Linux-first, headless, egress-only network gateway for isolating sandboxed guests behind per-link `nftables`, fake-IP DNS, TLS MITM, default-deny HTTP/WebSocket policy, file-backed secret placeholder substitution, and fail-closed JSONL audit logging.

## Binaries

- **`cmd/gateway`** — single binary providing the daemon, root dataplane setup, and operator CLI:
  - `gateway run --config <path>`: unprivileged daemon (zero `CAP_NET_ADMIN`) serving per-link DNS, HTTPS, and HTTP listeners, Unix-socket Admin API (`/run/gateway/admin.sock`), and optional `/metrics`.
  - `gateway netsetup --config <path> [--dry-run]`: privileged one-shot setup applying kernel sysctls, per-link `ip` addresses/rules/routes, atomic `nftables` (`table inet gw`), DHCP-only `dnsmasq.conf`, and `dataplane.ready`. Interfaces removed from `links` stay blocked.
  - `gateway netsetup --config <path> --release <interface>`: stop blocking a removed interface (see [Removing a link](#removing-a-link)).
  - Operator subcommands (`--socket PATH` before the subcommand; `--json` before or after any subcommand):
    - `gateway status`
    - `gateway reload`
    - `gateway flows`
    - `gateway revoke (--flow ID | --grant ID | --principal NAME [--host HOST])`
    - `gateway grant --principal NAME --host HOST [--port 443|80] [--methods CSV] [--paths CSV] [--ttl 5m]` (note: `gateway grant` has no `--allow-websocket` flag; WebSocket grants are Admin-API only via `POST /v1/grants`)
    - `gateway grants`
    - `gateway grant revoke <id>`
    - `gateway ca init --cert <path> --key <path>`
    - `gateway dataplane check --config <path>` (read-only verification of `table inet gw` and sysctls)
- **`cmd/gateway-probe`** — static, stdlib-only guest binary that verifies containment and positive controls from inside a guest, printing one JSON line per check and exiting non-zero on failure.

## Quickstart (systemd)

Build static Linux binaries:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /usr/local/bin/gateway ./cmd/gateway
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /usr/local/bin/gateway-probe ./cmd/gateway-probe
```

Provision the `gateway` user, config, MITM CA, and the two units from `deploy/`:

```bash
groupadd --system gateway
useradd --system --gid gateway --no-create-home --shell /usr/sbin/nologin gateway
install -d -o root -g gateway -m 0750 /etc/gateway /etc/gateway/ca
install -d -o dnsmasq -g "$(id -gn dnsmasq)" -m 0750 /var/lib/gateway

# Copy and edit one of examples/gateway.yaml, examples/two-links.yaml, or examples/workers.yaml
install -o root -g gateway -m 0640 examples/gateway.yaml /etc/gateway/gateway.yaml

gateway ca init --cert /etc/gateway/ca/ca.crt --key /etc/gateway/ca/ca.key
chown root:gateway /etc/gateway/ca/ca.crt /etc/gateway/ca/ca.key
chmod 0644 /etc/gateway/ca/ca.crt
chmod 0640 /etc/gateway/ca/ca.key

install -m 0644 deploy/gateway.service /etc/systemd/system/gateway.service
install -m 0644 deploy/gateway-dhcp.service /etc/systemd/system/gateway-dhcp.service
systemctl daemon-reload
systemctl enable --now gateway.service gateway-dhcp.service
```

Install `/etc/gateway/ca/ca.crt` into each guest's system trust store (`update-ca-certificates`), verify the dataplane with `gateway dataplane check --config /etc/gateway/gateway.yaml`, and check daemon status with `gateway status`.

## Removing a link

Remove the link and its rules from the config, then run `systemctl restart gateway.service gateway-dhcp.service`. `netsetup` removes the address, route, and `ip rule` it added to the interface, and drops all traffic to, from, and through it, also after a reboot. It does not take the interface down.

The interface stays blocked until a link configures it again or you release it. Release it only after detaching its guests, because a released interface is filtered by whatever else the host has, not by `gateway`:

```bash
gateway netsetup --config /etc/gateway/gateway.yaml --release sbx1
```

`netsetup` records the interfaces it has managed in `dataplane.state_file` (default `/var/lib/gateway-dataplane/links.json`). Keep it on storage that survives reboots. If it is unreadable or corrupt, `netsetup` fails without changing anything; restore it, or delete it and detach every removed interface.

## Reading the Audit Log

Every DNS query, request admission/completion, WebSocket close, grant lifecycle event, revocation, and daemon lifecycle event is written synchronously as structured JSONL under `audit.dir` (default `/var/log/gateway/audit`). Header values are never recorded and query strings are stripped.

Follow logs locally with `jq`:

```bash
tail -F /var/log/gateway/audit/*.jsonl | jq .
```

When `audit.stdout_json: true` is enabled, `gateway run` mirrors the same JSONL records to stdout for collection by Loki or journald.

## Documentation

- [Architecture](docs/architecture.md) — process model, packet/request flow, package boundaries, fail-closed points, and deployment details.
- [Threat Model](docs/threat-model.md) — hardening goals, accepted residuals, and policy precedence/reload semantics.
