#!/usr/bin/env bash
set -euo pipefail

# Real Incus E2E harness for gateway (Phase 3 / Step 2).
# Runs against a throwaway Incus project whose name is passed in via --project.
# Refuses an existing project, prints exact Incus commands and asks for
# confirmation before creating anything, and destroys the project on exit
# (including failure) unless --keep is given.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PROJECT=""
REMOTE=""
IMAGE="images:ubuntu/24.04"
MGMT_NET="incusbr0"
MGMT_NET_EXPLICIT=0
CREATE_MGMT_NET=0
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
  --mgmt-network <name>     Existing management/upstream bridge for gw eth0 (default: incusbr0)
  --create-mgmt-network     Create a dedicated NAT bridge gwdm-<tag> for gw eth0 and delete on cleanup
  --storage-pool <name>     Storage pool for project default profile (default: default)
  --upstream-host <host>    Allowlisted test upstream host (default: httpbingo.org)
  --lan-addr <ip:port>      LAN ip:port expected unreachable (default: gw upstream gateway:22)
  --keep                    Keep the throwaway Incus project on exit/failure
  --plan-only               Print planned Incus commands and exit without creating anything

Planted wiring defect flags (Step 2.6, restored after each):
  --defect-drop-fib-local   Remove fib daddr type local guard and verify probe goes red
  --defect-drop-ct-zone     Put both links in one conntrack zone and verify functional collision
  --defect-drop-dns-dnat    Remove :53 DNAT rules and verify probe goes red
  --run-all-defects         Run all three planted wiring defects sequentially
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT="${2:?missing value for --project}"; shift 2 ;;
    --remote) REMOTE="${2:?missing value for --remote}"; shift 2 ;;
    --image) IMAGE="${2:?missing value for --image}"; shift 2 ;;
    --mgmt-network) MGMT_NET="${2:?missing value for --mgmt-network}"; MGMT_NET_EXPLICIT=1; shift 2 ;;
    --create-mgmt-network) CREATE_MGMT_NET=1; shift ;;
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

if [[ "$CREATE_MGMT_NET" -eq 1 ]]; then
  if [[ "$MGMT_NET_EXPLICIT" -eq 1 ]]; then
    echo "error: --create-mgmt-network cannot be combined with --mgmt-network" >&2
    exit 2
  fi
  MGMT_NET="gwdm-${PROJ_TAG}"
fi

GW_INST="${RPREFIX}gw"
G0_INST="${RPREFIX}guest0"
G1_INST="${RPREFIX}guest1"

# Exact Incus provisioning commands printed before confirmation.
print_plan() {
  echo "Planned Incus commands (throwaway project '${PROJECT}', remote '${REMOTE:-local}'):"
  echo "  incus project create ${RPREFIX}${PROJECT} -c features.images=false -c features.profiles=true -c features.networks=false -c features.storage.volumes=false"
  echo "  incus profile device add ${RPREFIX}default root disk path=/ pool=${STORAGE_POOL} --project ${PROJECT}"
  if [[ "$CREATE_MGMT_NET" -eq 1 ]]; then
    echo "  incus network create ${RPREFIX}${MGMT_NET} --type=bridge ipv4.address=auto ipv4.nat=true ipv6.address=none"
  fi
  echo "  incus network create ${RPREFIX}${NET0} --type=bridge ipv4.address=none ipv6.address=none"
  echo "  incus network create ${RPREFIX}${NET1} --type=bridge ipv4.address=none ipv6.address=none"
  echo "  incus init ${IMAGE} ${GW_INST} --project ${PROJECT}"
  echo "  incus config device add ${GW_INST} eth0 nic network=${MGMT_NET} name=eth0 --project ${PROJECT}"
  echo "  incus config device add ${GW_INST} sbx0 nic network=${NET0} name=sbx0 --project ${PROJECT}"
  echo "  incus config device add ${GW_INST} sbx1 nic network=${NET1} name=sbx1 --project ${PROJECT}"
  echo "  incus start ${GW_INST} --project ${PROJECT}"
  echo "  incus init ${IMAGE} ${G0_INST} --project ${PROJECT}"
  echo "  incus config device add ${G0_INST} eth0 nic network=${NET0} name=eth0 --project ${PROJECT}"
  echo "  incus start ${G0_INST} --project ${PROJECT}"
  echo "  incus init ${IMAGE} ${G1_INST} --project ${PROJECT}"
  echo "  incus config device add ${G1_INST} eth0 nic network=${NET1} name=eth0 --project ${PROJECT}"
  echo "  incus start ${G1_INST} --project ${PROJECT}"
  echo ""
  echo "Planned cleanup commands (unless --keep is given):"
  echo "  incus delete --force ${G0_INST} ${G1_INST} ${GW_INST} --project ${PROJECT}"
  echo "  incus network delete ${RPREFIX}${NET0}"
  echo "  incus network delete ${RPREFIX}${NET1}"
  if [[ "$CREATE_MGMT_NET" -eq 1 ]]; then
    echo "  incus network delete ${RPREFIX}${MGMT_NET}"
  fi
  echo "  incus project delete ${RPREFIX}${PROJECT}"
}

print_plan
if [[ "$PLAN_ONLY" -eq 1 ]]; then
  exit 0
fi

# Refuse clustered Incus altogether.
CLUSTER_LIST_CMD=(incus cluster list --format csv)
if [[ -n "$RPREFIX" ]]; then
  CLUSTER_LIST_CMD=(incus cluster list "$RPREFIX" --format csv)
fi
if cluster_members="$("${CLUSTER_LIST_CMD[@]}" 2>/dev/null)" && [[ -n "$cluster_members" ]]; then
  echo "clustered Incus is not supported; use a standalone Incus host" >&2
  exit 1
fi

# Refuse if the project or any managed bridge network already exists.
if incus project show "${RPREFIX}${PROJECT}" >/dev/null 2>&1; then
  echo "error: Incus project '${RPREFIX}${PROJECT}' already exists; refusing to touch it" >&2
  exit 1
fi
NETS_TO_CHECK=("$NET0" "$NET1")
if [[ "$CREATE_MGMT_NET" -eq 1 ]]; then
  NETS_TO_CHECK+=("$MGMT_NET")
fi
for net in "${NETS_TO_CHECK[@]}"; do
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
CREATED_MGMT_NET=0
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
  if [[ "$CREATED_MGMT_NET" -eq 1 ]]; then
    incus network delete "${RPREFIX}${MGMT_NET}" 2>/dev/null || true
    if incus network show "${RPREFIX}${MGMT_NET}" >/dev/null 2>&1; then
      echo "[cleanup] WARNING: management network '${RPREFIX}${MGMT_NET}' still exists" >&2
    else
      echo "[cleanup] verified management network '${RPREFIX}${MGMT_NET}' is gone"
    fi
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
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$TMPDIR_WORK/gateway" ./cmd/gateway
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$TMPDIR_WORK/gateway-probe" ./cmd/gateway-probe
)

echo "==> Creating throwaway Incus project, networks, and containers"
incus project create "${RPREFIX}${PROJECT}" \
  -c features.images=false \
  -c features.profiles=true \
  -c features.networks=false \
  -c features.storage.volumes=false
CREATED_PROJECT=1

incus profile device add "${RPREFIX}default" root disk path=/ "pool=${STORAGE_POOL}" --project "$PROJECT"

if [[ "$CREATE_MGMT_NET" -eq 1 ]]; then
  incus network create "${RPREFIX}${MGMT_NET}" --type=bridge ipv4.address=auto ipv4.nat=true ipv6.address=none
  CREATED_MGMT_NET=1
fi

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
  getent group gateway >/dev/null 2>&1 || groupadd --system gateway
  id -u gateway >/dev/null 2>&1 || useradd --system --gid gateway --no-create-home --shell /usr/sbin/nologin gateway
  id -u dnsmasq  >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin dnsmasq
  install -d -o root -g gateway -m 0750 /etc/gateway /etc/gateway/ca
  install -d -o dnsmasq -g "$(id -gn dnsmasq)" -m 0750 /var/lib/gateway
'

sed "s|httpbingo\.org|${UPSTREAM_HOST}|g" "$REPO_ROOT/examples/two-links.yaml" > "$TMPDIR_WORK/gateway.yaml"

incus file push "$TMPDIR_WORK/gateway" "${GW_INST}/usr/local/bin/gateway" --project "$PROJECT" --mode 0755
incus file push "$TMPDIR_WORK/gateway.yaml" "${GW_INST}/etc/gateway/gateway.yaml" --project "$PROJECT" --mode 0640
incus file push "$REPO_ROOT/deploy/gateway.service" "${GW_INST}/etc/systemd/system/gateway.service" --project "$PROJECT" --mode 0644
incus file push "$REPO_ROOT/deploy/gateway-dhcp.service" "${GW_INST}/etc/systemd/system/gateway-dhcp.service" --project "$PROJECT" --mode 0644

gw_exec bash -ceu '
  chown root:gateway /etc/gateway/gateway.yaml
  /usr/local/bin/gateway ca init --cert /etc/gateway/ca/ca.crt --key /etc/gateway/ca/ca.key
  chown root:gateway /etc/gateway/ca/ca.crt /etc/gateway/ca/ca.key
  chmod 0644 /etc/gateway/ca/ca.crt
  chmod 0640 /etc/gateway/ca/ca.key
  systemctl daemon-reload
'

incus file pull "${GW_INST}/etc/gateway/ca/ca.crt" "$TMPDIR_WORK/ca.crt" --project "$PROJECT"

for ginst in "$G0_INST" "$G1_INST"; do
  incus file push "$TMPDIR_WORK/gateway-probe" "${ginst}/usr/local/bin/gateway-probe" --project "$PROJECT" --mode 0755
  incus file push "$TMPDIR_WORK/ca.crt" "${ginst}/usr/local/share/ca-certificates/gateway-mitm.crt" --project "$PROJECT" --mode 0644
  incus exec "$ginst" --project "$PROJECT" -- update-ca-certificates >/dev/null
done

GW_MGMT_IP="$(gw_exec ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)"
if [[ -z "$LAN_ADDR" ]]; then
  GW_UPSTREAM_GW="$(gw_exec ip -4 route show default dev eth0 | awk '{print $3}' | head -n1)"
  LAN_ADDR="${GW_UPSTREAM_GW}:22"
fi
echo "    gw mgmt IP: ${GW_MGMT_IP}, LAN test target: ${LAN_ADDR}"

start_gateway_service() {
  if ! gw_exec systemctl start gateway.service; then
    gw_exec bash -ceu '
      status="$(systemctl show -p ExecMainStatus --value gateway.service || true)"
      result="$(systemctl show -p Result --value gateway.service || true)"
      journal="$(journalctl -u gateway.service -n 40 --no-pager || true)"
      if [[ "$status" == "226" ]] || echo "$journal" | grep -q "226/NAMESPACE"; then
        echo "FAIL: gateway.service failed with status=226/NAMESPACE (result=${result})" >&2
        echo "--- journalctl -u gateway.service ---" >&2
        echo "$journal" >&2
        echo "--- systemd-resolved state in gateway container ---" >&2
        systemctl is-active systemd-resolved 2>&1 || true
        exit 1
      fi
      echo "FAIL: gateway.service failed to start (ExecMainStatus=${status}, Result=${result})" >&2
      echo "$journal" >&2
      exit 1
    '
    exit 1
  fi
  sleep 1
  if ! gw_exec systemctl is-active --quiet gateway.service; then
    gw_exec bash -ceu '
      status="$(systemctl show -p ExecMainStatus --value gateway.service || true)"
      journal="$(journalctl -u gateway.service -n 40 --no-pager || true)"
      if [[ "$status" == "226" ]] || echo "$journal" | grep -q "226/NAMESPACE"; then
        echo "FAIL: gateway.service exited with status=226/NAMESPACE" >&2
        echo "--- journalctl -u gateway.service ---" >&2
        echo "$journal" >&2
        echo "--- systemd-resolved state in gateway container ---" >&2
        systemctl is-active systemd-resolved 2>&1 || true
        exit 1
      fi
      echo "FAIL: gateway.service is not active (ExecMainStatus=${status})" >&2
      echo "$journal" >&2
      exit 1
    '
    exit 1
  fi
}

echo "==> Step 2.1: Fail-closed startup"
gw_exec bash -ceu '
  nft delete table inet gw 2>/dev/null || true
  rm -f /run/gateway/dataplane.ready
'
gw_exec bash -eu <<'EOF'
  set +e
  timeout 5s sudo -u gateway /usr/local/bin/gateway run --config /etc/gateway/gateway.yaml >/tmp/fc-sysctl.out 2>/tmp/fc-sysctl.err
  rc=$?
  set -e
  err_msg="$(cat /tmp/fc-sysctl.err)"
  rm -f /tmp/fc-sysctl.out /tmp/fc-sysctl.err
  if [[ "$rc" -eq 0 ]]; then
    echo "FAIL: gateway exited 0 with unconfigured sysctls" >&2
    exit 1
  fi
  if [[ "$rc" -eq 124 ]]; then
    echo "FAIL: gateway stayed running (timeout 5s) with unconfigured sysctls" >&2
    exit 1
  fi
  if ! echo "$err_msg" | grep -q "sysctl"; then
    echo "FAIL: expected sysctl error on stderr, got: ${err_msg}" >&2
    exit 1
  fi
  echo "    PASS (sysctl): gateway exited non-zero (rc=${rc}): ${err_msg}"
EOF

gw_exec bash -eu <<'EOF'
  /usr/local/bin/gateway netsetup --config /etc/gateway/gateway.yaml
  nft delete table inet gw
  rm -f /run/gateway/dataplane.ready
  set +e
  timeout 5s sudo -u gateway /usr/local/bin/gateway run --config /etc/gateway/gateway.yaml >/tmp/fc-ready.out 2>/tmp/fc-ready.err
  rc=$?
  set -e
  err_msg="$(cat /tmp/fc-ready.err)"
  rm -f /tmp/fc-ready.out /tmp/fc-ready.err
  if [[ "$rc" -eq 0 ]]; then
    echo "FAIL: gateway exited 0 without table inet gw or ready_file (valid sysctls)" >&2
    exit 1
  fi
  if [[ "$rc" -eq 124 ]]; then
    echo "FAIL: gateway stayed running (timeout 5s) without table inet gw or ready_file (valid sysctls)" >&2
    exit 1
  fi
  if ! echo "$err_msg" | grep -q "ready_file"; then
    echo "FAIL: expected ready_file error on stderr, got: ${err_msg}" >&2
    exit 1
  fi
  echo "    PASS (ready_file): gateway exited non-zero (rc=${rc}): ${err_msg}"
EOF

start_gateway_service

echo "    Deleting table inet gw while keeping ready_file..."
gw_exec nft delete table inet gw
if gw_exec /usr/local/bin/gateway dataplane check --config /etc/gateway/gateway.yaml >/dev/null 2>&1; then
  echo "FAIL: gateway dataplane check passed after deleting table inet gw" >&2
  exit 1
fi
echo "    PASS: gateway dataplane check failed without table inet gw"

echo "    Recording direct gateway start with stale ready_file (without netsetup)..."
gw_exec bash -ceu '
  cp /run/gateway/dataplane.ready /tmp/stale.ready
  systemctl stop gateway.service
  install -d -o gateway -g gateway -m 0755 /run/gateway
  mv /tmp/stale.ready /run/gateway/dataplane.ready
  set +e
  timeout 2s sudo -u gateway /usr/local/bin/gateway run --config /etc/gateway/gateway.yaml >/tmp/stale-start.out 2>/tmp/stale-start.err
  rc=$?
  echo "    stale-ready-file direct start exit code: $rc (124 = stayed running until timeout)"
  head -n 5 /tmp/stale-start.err || true
  rm -f /run/gateway/dataplane.ready /tmp/stale-start.out /tmp/stale-start.err
'

echo "==> Starting gateway.service and gateway-dhcp.service"
start_gateway_service
gw_exec systemctl start gateway-dhcp.service
sleep 1
gw_exec systemctl is-active --quiet gateway.service
gw_exec systemctl is-active --quiet gateway-dhcp.service

echo "==> Step 2.2: Data plane and privileges"
gw_exec nft list table inet gw >/dev/null
gw_exec /usr/local/bin/gateway dataplane check --config /etc/gateway/gateway.yaml

gw_exec bash -eu <<'EOF'
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

  gw_pid="$(systemctl show -p MainPID --value gateway.service)"
  grep -E "^(Uid|CapEff|CapPrm|CapAmb):" "/proc/${gw_pid}/status"
  uid="$(awk '/^Uid:/{print $2}' "/proc/${gw_pid}/status")"
  [[ "$uid" != "0" ]] || { echo "FAIL: gateway running as root" >&2; exit 1; }
  for cap in CapEff CapPrm CapAmb; do
    val="$(awk -v c="${cap}:" '$1==c{print $2}' "/proc/${gw_pid}/status")"
    [[ "$val" == "0000000000000000" ]] || { echo "FAIL: gateway ${cap}=${val}" >&2; exit 1; }
  done

  ss_out="$(ss -ltnup)"
  echo "$ss_out"
  echo "$ss_out" | awk '
    /"gateway"/ {
      gw_count++
      addr = $5
      sub(/:[^:]+$/, "", addr)
      sub(/%.*$/, "", addr)
      if (addr == "0.0.0.0" || addr == "*" || addr == "[::]" || addr == "::") {
        printf "FAIL: gateway has wildcard local address: %s\n", $0 > "/dev/stderr"
        bad = 1
      }
    }
    /"dnsmasq"/ {
      dm_count++
      if ($5 ~ /:53$/) {
        printf "FAIL: dnsmasq is listening on :53: %s\n", $0 > "/dev/stderr"
        bad = 1
      }
      if ($1 != "udp" || $5 !~ /:67$/) {
        printf "FAIL: dnsmasq has socket other than UDP :67: %s\n", $0 > "/dev/stderr"
        bad = 1
      }
    }
    END {
      if (gw_count < 1) {
        print "FAIL: gateway has zero listeners in ss -ltnup" > "/dev/stderr"
        bad = 1
      }
      if (dm_count < 1) {
        print "FAIL: dnsmasq has zero listeners in ss -ltnup" > "/dev/stderr"
        bad = 1
      }
      if (bad) exit 1
    }
  '
EOF

echo "==> Step 2.3: DHCPv4 leases and dnsmasq privilege drop"
configure_guest_dhcp() {
  local ginst="$1"
  local want_gw="$2"
  local want_cidr="$3"
  incus exec "$ginst" --project "$PROJECT" -- bash -ceu "
    cat >/etc/systemd/network/10-eth0.network <<NET
[Match]
Name=eth0

[Network]
DHCP=ipv4
LinkLocalAddressing=no
IPv6AcceptRA=no
NET
    ip addr flush dev eth0
    ip route flush dev eth0 || true
    systemctl enable --now systemd-networkd >/dev/null 2>&1 || true
    networkctl reconfigure eth0 >/dev/null 2>&1 || systemctl restart systemd-networkd

    got_ip=''
    gw=''
    ready=0
    for _ in \$(seq 1 30); do
      got_ip=\"\$(ip -4 -o addr show dev eth0 | awk '{print \$4}' | cut -d/ -f1 | python3 -c '
import ipaddress, sys
net = ipaddress.ip_network(sys.argv[1])
for line in sys.stdin:
    s = line.strip()
    if not s:
        continue
    if ipaddress.ip_address(s) in net:
        print(s)
        break
' '${want_cidr}')\"
      gw=\"\$(ip -4 route show default dev eth0 | awk '{print \$3}' | head -n1)\"
      if [[ -n \"\$got_ip\" && \"\$gw\" == '${want_gw}' ]]; then
        ready=1
        break
      fi
      sleep 1
    done
    if [[ \"\$ready\" -ne 1 ]]; then
      echo \"FAIL: ${ginst} did not acquire DHCP IP in ${want_cidr} with gw=${want_gw} within 30s (got_ip='\${got_ip}', gw='\${gw}')\" >&2
      exit 1
    fi

    # Assert DHCP handed out link_IP as DNS BEFORE touching any resolver config.
    dhcp_dns=''
    if command -v resolvectl >/dev/null 2>&1; then
      dhcp_dns=\"\$(resolvectl dns eth0 2>/dev/null || true)\"
    fi
    lease_dns=\"\$(grep -h '^DNS=' /run/systemd/netif/leases/* 2>/dev/null || true)\"
    if ! echo \"\${dhcp_dns} \${lease_dns}\" | grep -qw '${want_gw}'; then
      echo \"FAIL: ${ginst} DHCP DNS did not hand out ${want_gw} (resolvectl='\${dhcp_dns}', lease='\${lease_dns}')\" >&2
      exit 1
    fi

    # Leave systemd-resolved in place if it already forwards eth0 to link_IP.
    if systemctl is-active --quiet systemd-resolved 2>/dev/null && echo \"\$dhcp_dns\" | grep -qw '${want_gw}'; then
      echo \"    PASS: ${ginst} systemd-resolved forwards DNS to DHCP server ${want_gw}\"
    else
      rm -f /etc/resolv.conf
      printf 'nameserver %s\n' '${want_gw}' >/etc/resolv.conf
      echo \"    PASS: ${ginst} wrote static /etc/resolv.conf with DHCP DNS ${want_gw}\"
    fi
  "
}

configure_guest_dhcp "$G0_INST" "10.200.0.1" "10.200.0.0/28"
configure_guest_dhcp "$G1_INST" "10.200.0.17" "10.200.0.16/28"

G0_IP="$(g0_exec ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)"
G1_IP="$(g1_exec ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)"
G0_GW="$(g0_exec ip -4 route show default dev eth0 | awk '{print $3}' | head -n1)"
G1_GW="$(g1_exec ip -4 route show default dev eth0 | awk '{print $3}' | head -n1)"
echo "    guest0: ip=${G0_IP} gw=${G0_GW}"
echo "    guest1: ip=${G1_IP} gw=${G1_GW}"
[[ "$G0_GW" == "10.200.0.1" ]] || { echo "FAIL: guest0 gw=${G0_GW} want 10.200.0.1" >&2; exit 1; }
[[ "$G1_GW" == "10.200.0.17" ]] || { echo "FAIL: guest1 gw=${G1_GW} want 10.200.0.17" >&2; exit 1; }

gw_exec bash -ceu '
  dm_pid="$(systemctl show -p MainPID --value gateway-dhcp.service)"
  grep -E "^(Uid|CapEff|CapPrm):" "/proc/${dm_pid}/status"
  uid="$(awk "/^Uid:/{print \$2}" "/proc/${dm_pid}/status")"
  [[ "$uid" != "0" ]] || { echo "FAIL: dnsmasq running as root" >&2; exit 1; }
  for cap in CapEff CapPrm; do
    val="$(awk -v c="${cap}:" "\$1==c{print \$2}" "/proc/${dm_pid}/status")"
    [[ "$val" == "0000000000000000" ]] || { echo "FAIL: dnsmasq ${cap}=${val}" >&2; exit 1; }
  done
'

run_probe_guest0() {
  g0_exec /usr/local/bin/gateway-probe \
    --allow-host "$UPSTREAM_HOST" \
    --link-ip 10.200.0.1 \
    --https-port 10443 \
    --lan-addr "$LAN_ADDR" \
    --mgmt-ip "$GW_MGMT_IP" \
    --peer-link-ip 10.200.0.17 \
    --peer-guest-addr "${G1_IP}:8080"
}

run_probe_guest1() {
  g1_exec /usr/local/bin/gateway-probe \
    --allow-host "$UPSTREAM_HOST" \
    --link-ip 10.200.0.17 \
    --https-port 10443 \
    --lan-addr "$LAN_ADDR" \
    --mgmt-ip "$GW_MGMT_IP" \
    --peer-link-ip 10.200.0.1 \
    --peer-guest-addr "${G0_IP}:8080"
}

start_guest_peer_listener() {
  local ginst="$1"
  local gip="$2"
  incus exec "$ginst" --project "$PROJECT" -- bash -ceu "
    systemctl stop gwd-peer-listen.service 2>/dev/null || true
    systemctl reset-failed gwd-peer-listen.service 2>/dev/null || true
    systemd-run --unit=gwd-peer-listen --quiet /usr/bin/python3 -m http.server 8080 --bind 0.0.0.0
    ok=0
    for _ in \$(seq 1 20); do
      if timeout 2s bash -c 'exec 3<>/dev/tcp/${gip}/8080' 2>/dev/null; then
        ok=1
        break
      fi
      sleep 0.25
    done
    if [[ \"\$ok\" -ne 1 ]]; then
      echo 'FAIL: peer listener control ${gip}:8080 did not become reachable inside ${ginst}' >&2
      exit 1
    fi
    echo '    PASS: peer listener control reachable inside ${ginst} at ${gip}:8080'
  "
}

# Run a guest probe, re-running up to 3 times ONLY if every failing check is in
# the public-upstream set AND gateway's audit proves gateway forwarded the
# request and the upstream returned 4xx/5xx. Containment failures never retry.
run_probe_with_upstream_retry() {
  local principal="$1"
  local probe_fn="$2"
  local quiet_on_pass="${3:-0}"
  local max_reruns=3
  local attempt=0

  while true; do
    attempt=$((attempt + 1))
    local audit_before
    audit_before="$(gw_exec bash -ceu 'cat /var/log/gateway/audit/*.jsonl 2>/dev/null | wc -l')"
    local out_file="$TMPDIR_WORK/probe-${principal}-try${attempt}.jsonl"
    local audit_file="$TMPDIR_WORK/audit-${principal}-try${attempt}.jsonl"

    local probe_rc=0
    "$probe_fn" >"$out_file" 2>&1 || probe_rc=$?
    if [[ "$probe_rc" -eq 0 ]]; then
      if [[ "$quiet_on_pass" -eq 0 ]]; then
        cat "$out_file"
      fi
      if [[ "$attempt" -gt 1 ]]; then
        echo "    PASS: ${principal} probe passed on re-run $((attempt - 1)) of ${max_reruns}"
      fi
      return 0
    fi

    gw_exec bash -ceu "cat /var/log/gateway/audit/*.jsonl 2>/dev/null | tail -n +$((audit_before + 1))" >"$audit_file"

    echo "    WARN: ${principal} probe attempt ${attempt} failed (rc=${probe_rc}); checking upstream audit evidence..."
    local retry_ok=0
    python3 - "$out_file" "$audit_file" "$principal" "$UPSTREAM_HOST" <<'PY' || retry_ok=$?
import json, sys

probe_path, audit_path, principal, upstream = sys.argv[1:5]
retryable = {
    "transfer_upload_gt64k": ("POST", "/post"),
    "transfer_download_gt64k": ("GET", "/bytes/70000"),
    "allowed_tcp_443_by_name_control": ("GET", "/get"),
    "sni_host_match_control": ("GET", "/get"),
    "direct_https_dial_by_name_control": ("GET", "/get"),
}

failed_rows = []
with open(probe_path, "r", encoding="utf-8") as fh:
    for raw in fh:
        s = raw.strip()
        if not s or not s.startswith("{"):
            continue
        obj = json.loads(s)
        if not obj.get("pass"):
            failed_rows.append((obj["check"], s))

if not failed_rows:
    sys.stderr.write("    NO RETRY: probe exited non-zero with zero JSONL failure lines\n")
    sys.exit(1)

for chk, raw in failed_rows:
    print(f"    failing check JSONL: {raw}")

non_retryable = [chk for chk, _ in failed_rows if chk not in retryable]
if non_retryable:
    sys.stderr.write(f"    NO RETRY: containment/non-upstream check(s) failed: {non_retryable}\n")
    sys.exit(1)

audit_rows = []
with open(audit_path, "r", encoding="utf-8") as fh:
    for raw in fh:
        s = raw.strip()
        if not s or not s.startswith("{"):
            continue
        audit_rows.append((json.loads(s), s))

for chk, _ in failed_rows:
    want_method, want_path = retryable[chk]
    matches = [
        raw for obj, raw in audit_rows
        if obj.get("kind") == "request"
        and obj.get("principal") == principal
        and obj.get("effect") == "allow"
        and obj.get("host") == upstream
        and obj.get("method") == want_method
        and obj.get("path") == want_path
        and 400 <= int(obj.get("status", 0)) <= 599
    ]
    if not matches:
        sys.stderr.write(
            f"    NO RETRY: no forwarded 4xx/5xx audit record for {chk} "
            f"({principal} {want_method} {upstream}{want_path})\n"
        )
        sys.exit(1)
    for m in matches:
        print(f"    matching upstream 4xx/5xx audit: {m}")
PY

    if [[ "$retry_ok" -ne 0 ]]; then
      cat "$out_file"
      return "$probe_rc"
    fi

    if [[ "$attempt" -gt "$max_reruns" ]]; then
      echo "    FAIL: ${principal} still failing after ${max_reruns} upstream re-runs" >&2
      cat "$out_file"
      return "$probe_rc"
    fi
    echo "    re-running ${principal} probe (re-run ${attempt} of ${max_reruns})..."
    sleep 2
  done
}

echo "==> Step 2.4: Verifying LAN control from gateway, guest :8080 controls, and running gateway-probe"
lan_host="${LAN_ADDR%:*}"
lan_port="${LAN_ADDR##*:}"
if ! gw_exec bash -ceu "timeout 5s bash -c 'exec 3<>/dev/tcp/${lan_host}/${lan_port}'"; then
  echo "FAIL: LAN control ${LAN_ADDR} did not accept TCP from gateway container (guest unreachable check would be vacuous)" >&2
  exit 1
fi
echo "    PASS: LAN control ${LAN_ADDR} accepts TCP from gateway container"
start_guest_peer_listener "$G0_INST" "$G0_IP"
start_guest_peer_listener "$G1_INST" "$G1_IP"
run_probe_with_upstream_retry guest0 run_probe_guest0 0
run_probe_with_upstream_retry guest1 run_probe_guest1 0

restore_guests_dhcp() {
  configure_guest_dhcp "$G0_INST" "10.200.0.1" "10.200.0.0/28"
  configure_guest_dhcp "$G1_INST" "10.200.0.17" "10.200.0.16/28"
  G0_IP="$(g0_exec ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)"
  G1_IP="$(g1_exec ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)"
  start_guest_peer_listener "$G0_INST" "$G0_IP"
  start_guest_peer_listener "$G1_INST" "$G1_IP"
}

assert_defect_checks() {
  local jsonl_file="$1"
  local required_any_csv="$2"
  local allowed_fail_csv="$3"
  python3 - "$jsonl_file" "$required_any_csv" "$allowed_fail_csv" <<'PY'
import json, sys

path, req_csv, allow_csv = sys.argv[1], sys.argv[2], sys.argv[3]
required_any = {c for c in req_csv.split(",") if c}
allowed_fail = {c for c in allow_csv.split(",") if c}

rows = []
with open(path, "r", encoding="utf-8") as fh:
    for line in fh:
        s = line.strip()
        if not s:
            continue
        if not s.startswith("{"):
            # Skip non-JSON stderr summary lines emitted by gateway-probe after JSONL output.
            if s.startswith("gateway-probe:"):
                continue
            sys.stderr.write(f"FAIL: unexpected non-JSON line in probe output: {s}\n")
            sys.exit(1)
        obj = json.loads(s)
        rows.append(obj)

if not rows:
    sys.stderr.write("FAIL: probe emitted zero JSONL check lines\n")
    sys.exit(1)

failed = [r["check"] for r in rows if not r.get("pass")]
if not failed:
    sys.stderr.write("FAIL: no checks failed during planted defect\n")
    sys.exit(1)

unexpected = [c for c in failed if c not in allowed_fail]
if unexpected:
    sys.stderr.write(f"FAIL: unexpected check(s) failed during defect: {unexpected} (failed={failed})\n")
    sys.exit(1)

matched = [c for c in failed if c in required_any]
if not matched:
    sys.stderr.write(f"FAIL: none of expected check(s) {sorted(required_any)} failed (failed={failed})\n")
    sys.exit(1)

print(f"    verified expected failure(s): {', '.join(failed)}")
PY
}

# run_same_ip_step <src_port> <normal|defect>
# Returns:
#   0 = all checks passed
#   1 = functional failure (probe exit non-zero, missing/wrong audit attribution, or missing zone in normal mode)
#   2 = setup/harness error (never treated as a defect going red)
# Caller must restore DHCP and dataplane at top level where set -e is active.
run_same_ip_step() {
  local src_port="${1:?missing source port}"
  local mode="${2:-normal}"
  local static_ip="10.77.0.50"

  g0_exec bash -ceu "
    systemctl stop systemd-networkd 2>/dev/null || true
    ip addr flush dev eth0
    ip addr add ${static_ip}/32 dev eth0
    ip route replace 10.200.0.1/32 dev eth0 scope link
    ip route replace default via 10.200.0.1 dev eth0
  " || return 2
  g1_exec bash -ceu "
    systemctl stop systemd-networkd 2>/dev/null || true
    ip addr flush dev eth0
    ip addr add ${static_ip}/32 dev eth0
    ip route replace 10.200.0.17/32 dev eth0 scope link
    ip route replace default via 10.200.0.17 dev eth0
  " || return 2

  gw_exec conntrack -F >/dev/null 2>&1 || return 2

  local audit_before
  audit_before="$(gw_exec bash -ceu 'cat /var/log/gateway/audit/*.jsonl 2>/dev/null | wc -l')" || return 2

  local out0="$TMPDIR_WORK/same0-${src_port}.jsonl"
  local out1="$TMPDIR_WORK/same1-${src_port}.jsonl"
  # Start guest0 slightly ahead with a longer hold so its conntrack entries are
  # established when guest1 sends the identical 4-tuple (10.77.0.50:<src_port>).
  g0_exec /usr/local/bin/gateway-probe \
    --same-ip --src-ip "$static_ip" --src-port "$src_port" --hold 8s \
    --allow-host "$UPSTREAM_HOST" >"$out0" 2>&1 &
  local pid0=$!
  [[ -n "$pid0" ]] || return 2
  sleep 1
  g1_exec /usr/local/bin/gateway-probe \
    --same-ip --src-ip "$static_ip" --src-port "$src_port" --hold 6s \
    --allow-host "$UPSTREAM_HOST" >"$out1" 2>&1 &
  local pid1=$!
  [[ -n "$pid1" ]] || return 2

  local ct_out=""
  if [[ "$mode" == "normal" ]]; then
    sleep 2
    ct_out="$(gw_exec conntrack -L 2>/dev/null | grep "src=${static_ip}" || true)" || return 2
    echo "$ct_out"
  fi

  local rc0=0 rc1=0
  wait "$pid0" || rc0=$?
  wait "$pid1" || rc1=$?
  echo "    guest0 (sport=${src_port}) exit=${rc0}:"
  cat "$out0"
  echo "    guest1 (sport=${src_port}) exit=${rc1}:"
  cat "$out1"

  # Ensure both probes actually executed (emitted at least one JSON check line).
  if ! grep -q '^\{' "$out0" || ! grep -q '^\{' "$out1"; then
    echo "    setup error: probe did not emit JSONL output (rc0=${rc0}, rc1=${rc1})" >&2
    return 2
  fi

  local audit_delta
  audit_delta="$(gw_exec bash -ceu "cat /var/log/gateway/audit/*.jsonl 2>/dev/null | tail -n +$((audit_before + 1))")" || return 2
  local g0_audited=0 g1_audited=0
  if echo "$audit_delta" | grep -q "\"principal\":\"guest0\".*\"src_ip\":\"${static_ip}\""; then
    g0_audited=1
  fi
  if echo "$audit_delta" | grep -q "\"principal\":\"guest1\".*\"src_ip\":\"${static_ip}\""; then
    g1_audited=1
  fi

  if [[ "$mode" == "defect" ]]; then
    # Defect mode must fail for a functional reason (probe non-zero exit or
    # wrong-link/missing principal attribution), never conntrack -L string grep.
    local reasons=()
    if [[ "$rc0" -ne 0 ]]; then
      reasons+=("guest0 probe exited non-zero (${rc0})")
    fi
    if [[ "$rc1" -ne 0 ]]; then
      reasons+=("guest1 probe exited non-zero (${rc1})")
    fi
    if [[ "$g0_audited" -ne 1 || "$g1_audited" -ne 1 ]]; then
      reasons+=("reply/request misrouted or missing link attribution (guest0_audited=${g0_audited}, guest1_audited=${g1_audited})")
    fi
    if [[ "${#reasons[@]}" -gt 0 ]]; then
      echo "    functional collision detected: ${reasons[*]}"
      return 1
    fi
    echo "    no functional failure observed in defect mode"
    return 0
  fi

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
  if [[ "$g0_audited" -ne 1 || "$g1_audited" -ne 1 ]]; then
    echo "    missing audit attribution (guest0_audited=${g0_audited}, guest1_audited=${g1_audited})"
    ok=0
  fi
  [[ "$ok" -eq 1 ]]
}

echo "==> Step 2.5: Same IP, same source port (sport=45001)"
run_same_ip_step 45001 normal
restore_guests_dhcp

restore_dataplane() {
  gw_exec /usr/local/bin/gateway netsetup --config /etc/gateway/gateway.yaml
}

if [[ "$DEFECT_DROP_FIB_LOCAL" -eq 1 ]]; then
  echo "==> Step 2.6 (defect): remove fib daddr type local guard"
  echo "    running green baseline (guest0 probe)..."
  run_probe_with_upstream_retry guest0 run_probe_guest0 1
  echo "    PASS: baseline green"
  gw_exec bash -ceu '
    deleted=0
    for h in $(nft -a list chain inet gw prerouting_guard | awk "/fib daddr type local drop/{print \$NF}"); do
      nft delete rule inet gw prerouting_guard handle "$h"
      deleted=$((deleted + 1))
    done
    if [[ "$deleted" -lt 1 ]]; then
      echo "FAIL: expected to delete >=1 fib daddr type local drop handle, deleted ${deleted}" >&2
      exit 1
    fi
    echo "    deleted ${deleted} fib daddr type local drop handle(s)"
  '
  fib_out="$TMPDIR_WORK/defect-fib.jsonl"
  fib_rc=0
  run_probe_guest0 >"$fib_out" 2>&1 || fib_rc=$?
  restore_dataplane
  if [[ "$fib_rc" -eq 0 ]]; then
    echo "FAIL: probe still passed after removing fib daddr type local guard" >&2
    exit 1
  fi
  assert_defect_checks \
    "$fib_out" \
    "unreachable_gateway_mgmt,peer_link_ip_unreachable" \
    "unreachable_gateway_mgmt,peer_link_ip_unreachable"
  echo "    verifying restore (guest0 probe)..."
  run_probe_with_upstream_retry guest0 run_probe_guest0 1
  echo "    PASS: fib-local defect detected and dataplane restored"
fi

if [[ "$DEFECT_DROP_CT_ZONE" -eq 1 ]]; then
  echo "==> Step 2.6 (defect): put both links in one conntrack zone (baseline sport=45003, defect sport=45002)"
  echo "    running green baseline (same-IP sport=45003)..."
  run_same_ip_step 45003 normal
  restore_guests_dhcp
  echo "    PASS: baseline green"
  gw_exec bash -ceu '
    deleted=0
    for chain in raw_prerouting raw_output; do
      for h in $(nft -a list chain inet gw "$chain" | awk "/ct zone set/{print \$NF}"); do
        nft delete rule inet gw "$chain" handle "$h"
        deleted=$((deleted + 1))
      done
    done
    if [[ "$deleted" -lt 4 ]]; then
      echo "FAIL: expected to delete >=4 conntrack zone handles, deleted ${deleted}" >&2
      exit 1
    fi
    echo "    deleted ${deleted} conntrack zone handles (both links now share zone 0)"
  '
  zone_rc=0
  run_same_ip_step 45002 defect || zone_rc=$?
  restore_dataplane
  restore_guests_dhcp
  if [[ "$zone_rc" -eq 2 ]]; then
    echo "FAIL: harness setup error (rc=2) during conntrack-zone defect" >&2
    exit 1
  fi
  if [[ "$zone_rc" -ne 1 ]]; then
    echo "FAIL: conntrack-zone defect did not cause a functional failure (rc=${zone_rc})" >&2
    exit 1
  fi
  echo "    PASS: conntrack-zone defect caused functional failure and dataplane restored"
fi

if [[ "$DEFECT_DROP_DNS_DNAT" -eq 1 ]]; then
  echo "==> Step 2.6 (defect): remove :53 DNAT"
  echo "    running green baseline (guest0 probe)..."
  run_probe_with_upstream_retry guest0 run_probe_guest0 1
  echo "    PASS: baseline green"
  gw_exec bash -ceu '
    deleted=0
    for h in $(nft -a list chain inet gw prerouting_nat | awk "/dport 53 dnat/{print \$NF}"); do
      nft delete rule inet gw prerouting_nat handle "$h"
      deleted=$((deleted + 1))
    done
    if [[ "$deleted" -lt 1 ]]; then
      echo "FAIL: expected to delete >=1 :53 DNAT handle, deleted ${deleted}" >&2
      exit 1
    fi
    echo "    deleted ${deleted} :53 DNAT handle(s)"
  '
  dns_out="$TMPDIR_WORK/defect-dns.jsonl"
  dns_rc=0
  run_probe_guest0 >"$dns_out" 2>&1 || dns_rc=$?
  restore_dataplane
  if [[ "$dns_rc" -eq 0 ]]; then
    echo "FAIL: probe still passed after removing :53 DNAT" >&2
    exit 1
  fi
  assert_defect_checks \
    "$dns_out" \
    "dns_redirect_udp_53,dns_redirect_tcp_53,dns_allow_a_control" \
    "dns_redirect_udp_53,dns_redirect_tcp_53,dns_allow_a_control,dns_refused_txt,dns_refused_mx,dns_refused_ns,dns_refused_srv,dns_refused_cname,dns_refused_non_allowlisted,dns_nodata_aaaa,dns_nodata_https,dns_nodata_svcb,allowed_tcp_443_by_name_control,transfer_upload_gt64k,transfer_download_gt64k"
  echo "    verifying restore (guest0 probe)..."
  run_probe_with_upstream_retry guest0 run_probe_guest0 1
  echo "    PASS: DNS DNAT defect detected and dataplane restored"
fi

echo "==> E2E completed successfully"
