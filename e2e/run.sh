#!/usr/bin/env bash
set -euo pipefail

# Real Incus E2E harness for gatewayd (Phase 3 / Step 2).
# Runs against a throwaway Incus project whose name is passed in via --project.
# Refuses an existing project, prints exact Incus commands and asks for
# confirmation before creating anything, and destroys the project on exit
# (including failure) unless --keep is given.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PROJECT=""
REMOTE=""
IMAGE="images:ubuntu/24.04"
MGMT_NET="incusbr0"
STORAGE_POOL="default"
UPSTREAM_HOST="httpbingo.org"
LAN_ADDR=""
KEEP=0
PLAN_ONLY=0

DEFECT_DROP_FIB_LOCAL=0
DEFECT_DROP_CT_ZONE=0
DEFECT_DROP_DNS_DNAT=0

usage() {
  cat <<'EOF'
Usage: e2e/run.sh --project <name> [options]

Required:
  --project <name>          Throwaway Incus project name (must not already exist)

Options:
  --remote <name>           Incus remote prefix (empty = local default)
  --image <image>           Container image (default: images:ubuntu/24.04)
  --mgmt-network <name>     Management/upstream bridge for gw eth0 (default: incusbr0)
  --storage-pool <name>     Storage pool for project default profile (default: default)
  --upstream-host <host>    Allowlisted test upstream host (default: httpbingo.org)
  --lan-addr <ip:port>      LAN ip:port expected unreachable (default: gw upstream gateway:22)
  --keep                    Keep the throwaway Incus project on exit/failure
  --plan-only               Print planned Incus commands and exit without creating anything

Planted wiring defect flags (Step 2.6, restored after each):
  --defect-drop-fib-local   Remove fib daddr type local guard and verify probe goes red
  --defect-drop-ct-zone     Remove sbx1 conntrack zone and verify harness goes red
  --defect-drop-dns-dnat    Remove :53 DNAT rules and verify probe goes red
  --run-all-defects         Run all three planted wiring defects sequentially
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT="${2:?missing value for --project}"; shift 2 ;;
    --remote) REMOTE="${2:?missing value for --remote}"; shift 2 ;;
    --image) IMAGE="${2:?missing value for --image}"; shift 2 ;;
    --mgmt-network) MGMT_NET="${2:?missing value for --mgmt-network}"; shift 2 ;;
    --storage-pool) STORAGE_POOL="${2:?missing value for --storage-pool}"; shift 2 ;;
    --upstream-host) UPSTREAM_HOST="${2:?missing value for --upstream-host}"; shift 2 ;;
    --lan-addr) LAN_ADDR="${2:?missing value for --lan-addr}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --plan-only) PLAN_ONLY=1; shift ;;
    --defect-drop-fib-local) DEFECT_DROP_FIB_LOCAL=1; shift ;;
    --defect-drop-ct-zone) DEFECT_DROP_CT_ZONE=1; shift ;;
    --defect-drop-dns-dnat) DEFECT_DROP_DNS_DNAT=1; shift ;;
    --run-all-defects)
      DEFECT_DROP_FIB_LOCAL=1
      DEFECT_DROP_CT_ZONE=1
      DEFECT_DROP_DNS_DNAT=1
      shift
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown flag: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$PROJECT" ]]; then
  echo "error: --project is required" >&2
  usage >&2
  exit 2
fi

if [[ ! "$PROJECT" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*$ ]]; then
  echo "error: invalid project name '$PROJECT' (use alphanumeric and hyphens)" >&2
  exit 2
fi

RPREFIX=""
if [[ -n "$REMOTE" ]]; then
  RPREFIX="${REMOTE}:"
fi

# Derive <=15-char Linux bridge names deterministic per project.
PROJ_TAG="$(printf '%s' "$PROJECT" | sha256sum | cut -c1-6)"
NET0="sbx0-${PROJ_TAG}"
NET1="sbx1-${PROJ_TAG}"

GW_INST="${RPREFIX}gw"
G0_INST="${RPREFIX}guest0"
G1_INST="${RPREFIX}guest1"

# Exact Incus provisioning commands printed before confirmation.
print_plan() {
  cat <<EOF
Planned Incus commands (throwaway project '${PROJECT}', remote '${REMOTE:-local}'):
  incus project create ${RPREFIX}${PROJECT} -c features.images=false -c features.profiles=true -c features.networks=false -c features.storage.volumes=false
  incus profile device add ${RPREFIX}default root disk path=/ pool=${STORAGE_POOL} --project ${PROJECT}
  incus network create ${RPREFIX}${NET0} --type=bridge ipv4.address=none ipv6.address=none
  incus network create ${RPREFIX}${NET1} --type=bridge ipv4.address=none ipv6.address=none
  incus init ${IMAGE} ${GW_INST} --project ${PROJECT}
  incus config device add ${GW_INST} eth0 nic network=${MGMT_NET} name=eth0 --project ${PROJECT}
  incus config device add ${GW_INST} sbx0 nic network=${NET0} name=sbx0 --project ${PROJECT}
  incus config device add ${GW_INST} sbx1 nic network=${NET1} name=sbx1 --project ${PROJECT}
  incus start ${GW_INST} --project ${PROJECT}
  incus init ${IMAGE} ${G0_INST} --project ${PROJECT}
  incus config device add ${G0_INST} eth0 nic network=${NET0} name=eth0 --project ${PROJECT}
  incus start ${G0_INST} --project ${PROJECT}
  incus init ${IMAGE} ${G1_INST} --project ${PROJECT}
  incus config device add ${G1_INST} eth0 nic network=${NET1} name=eth0 --project ${PROJECT}
  incus start ${G1_INST} --project ${PROJECT}

Planned cleanup commands (unless --keep is given):
  incus delete --force ${G0_INST} ${G1_INST} ${GW_INST} --project ${PROJECT}
  incus network delete ${RPREFIX}${NET0}
  incus network delete ${RPREFIX}${NET1}
  incus project delete ${RPREFIX}${PROJECT}
EOF
}

print_plan
if [[ "$PLAN_ONLY" -eq 1 ]]; then
  exit 0
fi

# Refuse if the project or either bridge network already exists.
if incus project show "${RPREFIX}${PROJECT}" >/dev/null 2>&1; then
  echo "error: Incus project '${RPREFIX}${PROJECT}' already exists; refusing to touch it" >&2
  exit 1
fi
for net in "$NET0" "$NET1"; do
  if incus network show "${RPREFIX}${net}" >/dev/null 2>&1; then
    echo "error: Incus network '${RPREFIX}${net}' already exists; refusing to touch it" >&2
    exit 1
  fi
done

read -r -p "Create throwaway Incus project '${RPREFIX}${PROJECT}' and run E2E? [y/N] " reply
if [[ "$reply" != "y" && "$reply" != "Y" ]]; then
  echo "Aborted by user."
  exit 1
fi

CREATED_PROJECT=0
CREATED_NET0=0
CREATED_NET1=0
TMPDIR_WORK="$(mktemp -d)"

cleanup() {
  local rc=$?
  rm -rf "$TMPDIR_WORK"
  if [[ "$KEEP" -eq 1 ]]; then
    echo "[cleanup] --keep set; leaving Incus project '${RPREFIX}${PROJECT}' intact"
    return "$rc"
  fi
  set +e
  if [[ "$CREATED_PROJECT" -eq 1 ]]; then
    echo "[cleanup] destroying instances and project '${RPREFIX}${PROJECT}'"
    incus delete --force "$G0_INST" --project "$PROJECT" 2>/dev/null || true
    incus delete --force "$G1_INST" --project "$PROJECT" 2>/dev/null || true
    incus delete --force "$GW_INST" --project "$PROJECT" 2>/dev/null || true
  fi
  if [[ "$CREATED_NET0" -eq 1 ]]; then
    incus network delete "${RPREFIX}${NET0}" 2>/dev/null || true
  fi
  if [[ "$CREATED_NET1" -eq 1 ]]; then
    incus network delete "${RPREFIX}${NET1}" 2>/dev/null || true
  fi
  if [[ "$CREATED_PROJECT" -eq 1 ]]; then
    incus project delete "${RPREFIX}${PROJECT}" 2>/dev/null || true
    if incus project show "${RPREFIX}${PROJECT}" >/dev/null 2>&1; then
      echo "[cleanup] WARNING: project '${RPREFIX}${PROJECT}' still exists" >&2
    else
      echo "[cleanup] verified project '${RPREFIX}${PROJECT}' is gone"
    fi
  fi
  return "$rc"
}
trap cleanup EXIT

gw_exec() {
  incus exec "$GW_INST" --project "$PROJECT" -- "$@"
}

g0_exec() {
  incus exec "$G0_INST" --project "$PROJECT" -- "$@"
}

g1_exec() {
  incus exec "$G1_INST" --project "$PROJECT" -- "$@"
}

echo "==> Building static Linux binaries"
(
  cd "$REPO_ROOT"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$TMPDIR_WORK/gatewayd" ./cmd/gatewayd
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$TMPDIR_WORK/gwctl" ./cmd/gwctl
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$TMPDIR_WORK/gatewayd-probe" ./cmd/gatewayd-probe
)

echo "==> Creating throwaway Incus project, networks, and containers"
incus project create "${RPREFIX}${PROJECT}" \
  -c features.images=false \
  -c features.profiles=true \
  -c features.networks=false \
  -c features.storage.volumes=false
CREATED_PROJECT=1

incus profile device add "${RPREFIX}default" root disk path=/ "pool=${STORAGE_POOL}" --project "$PROJECT"

incus network create "${RPREFIX}${NET0}" --type=bridge ipv4.address=none ipv6.address=none
CREATED_NET0=1
incus network create "${RPREFIX}${NET1}" --type=bridge ipv4.address=none ipv6.address=none
CREATED_NET1=1

incus init "$IMAGE" "$GW_INST" --project "$PROJECT"
incus config device add "$GW_INST" eth0 nic "network=${MGMT_NET}" name=eth0 --project "$PROJECT"
incus config device add "$GW_INST" sbx0 nic "network=${NET0}" name=sbx0 --project "$PROJECT"
incus config device add "$GW_INST" sbx1 nic "network=${NET1}" name=sbx1 --project "$PROJECT"
incus start "$GW_INST" --project "$PROJECT"

incus init "$IMAGE" "$G0_INST" --project "$PROJECT"
incus config device add "$G0_INST" eth0 nic "network=${NET0}" name=eth0 --project "$PROJECT"
incus start "$G0_INST" --project "$PROJECT"

incus init "$IMAGE" "$G1_INST" --project "$PROJECT"
incus config device add "$G1_INST" eth0 nic "network=${NET1}" name=eth0 --project "$PROJECT"
incus start "$G1_INST" --project "$PROJECT"

echo "==> Waiting for systemd in containers"
for inst in "$GW_INST" "$G0_INST" "$G1_INST"; do
  for _ in $(seq 1 30); do
    if incus exec "$inst" --project "$PROJECT" -- systemctl is-system-running --wait >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
done

echo "==> Provisioning gateway container"
gw_exec bash -ceu '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq nftables dnsmasq-base conntrack iproute2 jq ca-certificates curl sudo >/dev/null
  id -u gatewayd >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin gatewayd
  id -u dnsmasq  >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin dnsmasq
  install -d -o root -g gatewayd -m 0750 /etc/gatewayd /etc/gatewayd/ca
  install -d -o gatewayd -g gatewayd -m 0750 /var/log/gatewayd/audit
  install -d -o dnsmasq -g dnsmasq -m 0750 /var/lib/gatewayd
'

sed "s|httpbingo\.org|${UPSTREAM_HOST}|g" "$REPO_ROOT/examples/two-links.yaml" > "$TMPDIR_WORK/gatewayd.yaml"

incus file push "$TMPDIR_WORK/gatewayd" "${GW_INST}/usr/local/bin/gatewayd" --project "$PROJECT" --mode 0755
incus file push "$TMPDIR_WORK/gwctl" "${GW_INST}/usr/local/bin/gwctl" --project "$PROJECT" --mode 0755
incus file push "$TMPDIR_WORK/gatewayd.yaml" "${GW_INST}/etc/gatewayd/gatewayd.yaml" --project "$PROJECT" --mode 0640
incus file push "$REPO_ROOT/deploy/gatewayd.service" "${GW_INST}/etc/systemd/system/gatewayd.service" --project "$PROJECT" --mode 0644
incus file push "$REPO_ROOT/deploy/gatewayd-dhcp.service" "${GW_INST}/etc/systemd/system/gatewayd-dhcp.service" --project "$PROJECT" --mode 0644

gw_exec bash -ceu '
  chown root:gatewayd /etc/gatewayd/gatewayd.yaml
  /usr/local/bin/gwctl ca init --cert /etc/gatewayd/ca/ca.crt --key /etc/gatewayd/ca/ca.key
  chown root:gatewayd /etc/gatewayd/ca/ca.crt /etc/gatewayd/ca/ca.key
  chmod 0644 /etc/gatewayd/ca/ca.crt
  chmod 0640 /etc/gatewayd/ca/ca.key
  systemctl daemon-reload
'

incus file pull "${GW_INST}/etc/gatewayd/ca/ca.crt" "$TMPDIR_WORK/ca.crt" --project "$PROJECT"

for ginst in "$G0_INST" "$G1_INST"; do
  incus file push "$TMPDIR_WORK/gatewayd-probe" "${ginst}/usr/local/bin/gatewayd-probe" --project "$PROJECT" --mode 0755
  incus file push "$TMPDIR_WORK/ca.crt" "${ginst}/usr/local/share/ca-certificates/gatewayd-mitm.crt" --project "$PROJECT" --mode 0644
  incus exec "$ginst" --project "$PROJECT" -- update-ca-certificates >/dev/null
done

GW_MGMT_IP="$(gw_exec ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)"
if [[ -z "$LAN_ADDR" ]]; then
  GW_UPSTREAM_GW="$(gw_exec ip -4 route show default dev eth0 | awk '{print $3}' | head -n1)"
  LAN_ADDR="${GW_UPSTREAM_GW}:22"
fi
echo "    gw mgmt IP: ${GW_MGMT_IP}, LAN test target: ${LAN_ADDR}"

echo "==> Step 2.1: Fail-closed startup"
gw_exec bash -ceu '
  nft delete table inet gw 2>/dev/null || true
  rm -f /run/gatewayd/dataplane.ready
'
if gw_exec sudo -u gatewayd /usr/local/bin/gatewayd --config /etc/gatewayd/gatewayd.yaml >/dev/null 2>&1; then
  echo "FAIL: gatewayd started without table inet gw or ready_file" >&2
  exit 1
fi
echo "    PASS: gatewayd exited non-zero without table inet gw or ready_file"

gw_exec systemctl start gatewayd.service
sleep 1
gw_exec systemctl is-active --quiet gatewayd.service

echo "    Deleting table inet gw while keeping ready_file..."
gw_exec nft delete table inet gw
if gw_exec /usr/local/bin/gwctl dataplane check --config /etc/gatewayd/gatewayd.yaml >/dev/null 2>&1; then
  echo "FAIL: gwctl dataplane check passed after deleting table inet gw" >&2
  exit 1
fi
echo "    PASS: gwctl dataplane check failed without table inet gw"

echo "    Recording direct gatewayd start with stale ready_file (without netsetup)..."
gw_exec bash -ceu '
  cp /run/gatewayd/dataplane.ready /tmp/stale.ready
  systemctl stop gatewayd.service
  install -d -o gatewayd -g gatewayd -m 0755 /run/gatewayd
  mv /tmp/stale.ready /run/gatewayd/dataplane.ready
  set +e
  timeout 2s sudo -u gatewayd /usr/local/bin/gatewayd --config /etc/gatewayd/gatewayd.yaml >/tmp/stale-start.out 2>/tmp/stale-start.err
  rc=$?
  echo "    stale-ready-file direct start exit code: $rc (124 = stayed running until timeout)"
  head -n 5 /tmp/stale-start.err || true
  rm -f /run/gatewayd/dataplane.ready /tmp/stale-start.out /tmp/stale-start.err
'

echo "==> Starting gatewayd.service and gatewayd-dhcp.service"
gw_exec systemctl start gatewayd.service gatewayd-dhcp.service
sleep 1
gw_exec systemctl is-active --quiet gatewayd.service
gw_exec systemctl is-active --quiet gatewayd-dhcp.service

echo "==> Step 2.2: Data plane and privileges"
gw_exec nft list table inet gw >/dev/null
gw_exec /usr/local/bin/gwctl dataplane check --config /etc/gatewayd/gatewayd.yaml

gw_exec bash -ceu '
  check_sysctl() {
    local k="$1" want="$2" got
    got="$(sysctl -n "$k")"
    if [[ "$got" != "$want" ]]; then
      echo "FAIL: sysctl $k=$got want $want" >&2
      exit 1
    fi
  }
  check_sysctl net.ipv4.ip_forward 0
  check_sysctl net.ipv6.conf.all.forwarding 0
  for iface in sbx0 sbx1; do
    check_sysctl "net.ipv4.conf.${iface}.rp_filter" 2
    check_sysctl "net.ipv4.conf.${iface}.arp_ignore" 1
    check_sysctl "net.ipv4.conf.${iface}.arp_filter" 1
    check_sysctl "net.ipv6.conf.${iface}.disable_ipv6" 1
  done

  gw_pid="$(systemctl show -p MainPID --value gatewayd.service)"
  grep -E "^(Uid|CapEff|CapPrm|CapAmb):" "/proc/${gw_pid}/status"
  uid="$(awk "/^Uid:/{print \$2}" "/proc/${gw_pid}/status")"
  [[ "$uid" != "0" ]] || { echo "FAIL: gatewayd running as root" >&2; exit 1; }
  for cap in CapEff CapPrm CapAmb; do
    val="$(awk -v c="${cap}:" "\$1==c{print \$2}" "/proc/${gw_pid}/status")"
    [[ "$val" == "0000000000000000" ]] || { echo "FAIL: gatewayd ${cap}=${val}" >&2; exit 1; }
  done

  ss_out="$(ss -ltnup)"
  echo "$ss_out"
  if echo "$ss_out" | grep gatewayd | grep -E "(\*|0\.0\.0\.0|\[::\]):"; then
    echo "FAIL: gatewayd has a wildcard listener" >&2
    exit 1
  fi
  if echo "$ss_out" | grep dnsmasq | grep -E ":53\b"; then
    echo "FAIL: dnsmasq is listening on :53" >&2
    exit 1
  fi
  echo "$ss_out" | grep dnsmasq | grep -qE ":67\b" || { echo "FAIL: dnsmasq not listening on :67" >&2; exit 1; }
'

echo "==> Step 2.3: DHCPv4 leases and dnsmasq privilege drop"
configure_guest_dhcp() {
  local ginst="$1"
  incus exec "$ginst" --project "$PROJECT" -- bash -ceu '
    cat >/etc/systemd/network/10-eth0.network <<NET
[Match]
Name=eth0

[Network]
DHCP=ipv4
LinkLocalAddressing=no
IPv6AcceptRA=no
NET
    systemctl enable --now systemd-networkd >/dev/null 2>&1 || true
    networkctl reconfigure eth0 >/dev/null 2>&1 || systemctl restart systemd-networkd
    for _ in $(seq 1 30); do
      if ip -4 addr show dev eth0 | grep -q "inet 10\.200\.0\."; then
        break
      fi
      sleep 1
    done
    # Ensure /etc/resolv.conf points at the DHCP-provided gateway IP.
    gw="$(ip -4 route show default dev eth0 | awk "{print \$3}" | head -n1)"
    [[ -n "$gw" ]] || { echo "FAIL: no default route via DHCP" >&2; exit 1; }
    printf "nameserver %s\n" "$gw" >/etc/resolv.conf
  '
}

configure_guest_dhcp "$G0_INST"
configure_guest_dhcp "$G1_INST"

G0_IP="$(g0_exec ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)"
G1_IP="$(g1_exec ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)"
G0_GW="$(g0_exec ip -4 route show default dev eth0 | awk '{print $3}' | head -n1)"
G1_GW="$(g1_exec ip -4 route show default dev eth0 | awk '{print $3}' | head -n1)"
echo "    guest0: ip=${G0_IP} gw=${G0_GW}"
echo "    guest1: ip=${G1_IP} gw=${G1_GW}"
[[ "$G0_GW" == "10.200.0.1" ]] || { echo "FAIL: guest0 gw=${G0_GW} want 10.200.0.1" >&2; exit 1; }
[[ "$G1_GW" == "10.200.0.17" ]] || { echo "FAIL: guest1 gw=${G1_GW} want 10.200.0.17" >&2; exit 1; }

gw_exec bash -ceu '
  dm_pid="$(systemctl show -p MainPID --value gatewayd-dhcp.service)"
  grep -E "^(Uid|CapEff|CapPrm):" "/proc/${dm_pid}/status"
  uid="$(awk "/^Uid:/{print \$2}" "/proc/${dm_pid}/status")"
  [[ "$uid" != "0" ]] || { echo "FAIL: dnsmasq running as root" >&2; exit 1; }
  for cap in CapEff CapPrm; do
    val="$(awk -v c="${cap}:" "\$1==c{print \$2}" "/proc/${dm_pid}/status")"
    [[ "$val" == "0000000000000000" ]] || { echo "FAIL: dnsmasq ${cap}=${val}" >&2; exit 1; }
  done
'

run_probe_guest0() {
  g0_exec /usr/local/bin/gatewayd-probe \
    --allow-host "$UPSTREAM_HOST" \
    --link-ip 10.200.0.1 \
    --https-port 10443 \
    --lan-addr "$LAN_ADDR" \
    --mgmt-ip "$GW_MGMT_IP" \
    --peer-link-ip 10.200.0.17 \
    --peer-guest-addr "${G1_IP}:8080"
}

run_probe_guest1() {
  g1_exec /usr/local/bin/gatewayd-probe \
    --allow-host "$UPSTREAM_HOST" \
    --link-ip 10.200.0.17 \
    --https-port 10443 \
    --lan-addr "$LAN_ADDR" \
    --mgmt-ip "$GW_MGMT_IP" \
    --peer-link-ip 10.200.0.1 \
    --peer-guest-addr "${G0_IP}:8080"
}

echo "==> Step 2.4: Running gatewayd-probe on both guests"
run_probe_guest0
run_probe_guest1

run_same_ip_step() {
  local expect_both_zones="${1:-1}"
  local static_ip="10.77.0.50"
  local src_port="45001"

  g0_exec bash -ceu "
    systemctl stop systemd-networkd 2>/dev/null || true
    ip addr flush dev eth0
    ip addr add ${static_ip}/32 dev eth0
    ip route replace 10.200.0.1/32 dev eth0 scope link
    ip route replace default via 10.200.0.1 dev eth0
  "
  g1_exec bash -ceu "
    systemctl stop systemd-networkd 2>/dev/null || true
    ip addr flush dev eth0
    ip addr add ${static_ip}/32 dev eth0
    ip route replace 10.200.0.17/32 dev eth0 scope link
    ip route replace default via 10.200.0.17 dev eth0
  "

  gw_exec conntrack -F >/dev/null 2>&1 || true

  local out0="$TMPDIR_WORK/same0.jsonl"
  local out1="$TMPDIR_WORK/same1.jsonl"
  g0_exec /usr/local/bin/gatewayd-probe \
    --same-ip --src-ip "$static_ip" --src-port "$src_port" --hold 6s \
    --allow-host "$UPSTREAM_HOST" >"$out0" &
  local pid0=$!
  g1_exec /usr/local/bin/gatewayd-probe \
    --same-ip --src-ip "$static_ip" --src-port "$src_port" --hold 6s \
    --allow-host "$UPSTREAM_HOST" >"$out1" &
  local pid1=$!

  sleep 2
  local ct_out
  ct_out="$(gw_exec conntrack -L 2>/dev/null | grep "src=${static_ip}" || true)"
  echo "$ct_out"

  local rc0=0 rc1=0
  wait "$pid0" || rc0=$?
  wait "$pid1" || rc1=$?
  cat "$out0" "$out1"

  local ok=1
  if [[ "$rc0" -ne 0 || "$rc1" -ne 0 ]]; then
    ok=0
  fi
  if ! echo "$ct_out" | grep -q "zone=101"; then
    echo "    missing conntrack zone=101"
    ok=0
  fi
  if ! echo "$ct_out" | grep -q "zone=102"; then
    echo "    missing conntrack zone=102"
    ok=0
  fi
  if [[ "$expect_both_zones" -eq 1 ]]; then
    gw_exec bash -ceu "
      grep -q '\"principal\":\"guest0\".*\"src_ip\":\"${static_ip}\"' /var/log/gatewayd/audit/*.jsonl
      grep -q '\"principal\":\"guest1\".*\"src_ip\":\"${static_ip}\"' /var/log/gatewayd/audit/*.jsonl
    " || ok=0
  fi

  # Restore DHCP on both guests.
  configure_guest_dhcp "$G0_INST"
  configure_guest_dhcp "$G1_INST"
  G0_IP="$(g0_exec ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)"
  G1_IP="$(g1_exec ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)"

  [[ "$ok" -eq 1 ]]
}

echo "==> Step 2.5: Same IP, same source port"
run_same_ip_step 1

restore_dataplane() {
  gw_exec /usr/local/bin/gatewayd netsetup --config /etc/gatewayd/gatewayd.yaml
}

if [[ "$DEFECT_DROP_FIB_LOCAL" -eq 1 ]]; then
  echo "==> Step 2.6 (defect): remove fib daddr type local guard"
  gw_exec bash -ceu '
    handle="$(nft -a list chain inet gw prerouting_guard | awk "/fib daddr type local drop/{print \$NF; exit}")"
    [[ -n "$handle" ]] || { echo "failed to find fib daddr type local drop handle" >&2; exit 1; }
    nft delete rule inet gw prerouting_guard handle "$handle"
  '
  if run_probe_guest0 >/dev/null 2>&1; then
    restore_dataplane
    echo "FAIL: probe still passed after removing fib daddr type local guard" >&2
    exit 1
  fi
  echo "    PASS: probe went red without fib daddr type local guard"
  restore_dataplane
fi

if [[ "$DEFECT_DROP_CT_ZONE" -eq 1 ]]; then
  echo "==> Step 2.6 (defect): remove sbx1 conntrack zone"
  gw_exec bash -ceu '
    h1="$(nft -a list chain inet gw raw_prerouting | awk "/ct zone set 102/{print \$NF; exit}")"
    h2="$(nft -a list chain inet gw raw_output     | awk "/ct zone set 102/{print \$NF; exit}")"
    [[ -n "$h1" && -n "$h2" ]] || { echo "failed to find zone 102 handles" >&2; exit 1; }
    nft delete rule inet gw raw_prerouting handle "$h1"
    nft delete rule inet gw raw_output handle "$h2"
  '
  if run_same_ip_step 0 >/dev/null 2>&1; then
    restore_dataplane
    echo "FAIL: same-IP check still passed after removing sbx1 conntrack zone" >&2
    exit 1
  fi
  echo "    PASS: harness went red without sbx1 conntrack zone"
  restore_dataplane
fi

if [[ "$DEFECT_DROP_DNS_DNAT" -eq 1 ]]; then
  echo "==> Step 2.6 (defect): remove :53 DNAT"
  gw_exec bash -ceu '
    for h in $(nft -a list chain inet gw prerouting_nat | awk "/dport 53 dnat/{print \$NF}"); do
      nft delete rule inet gw prerouting_nat handle "$h"
    done
  '
  if run_probe_guest0 >/dev/null 2>&1; then
    restore_dataplane
    echo "FAIL: probe still passed after removing :53 DNAT" >&2
    exit 1
  fi
  echo "    PASS: probe went red without :53 DNAT"
  restore_dataplane
fi

echo "==> E2E completed successfully"
