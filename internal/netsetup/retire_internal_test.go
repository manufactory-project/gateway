package netsetup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manufactory-project/gateway/internal/config"
)

const (
	testLinkSbx0 = `  - {name: sbx0, interface: sbx0, principal: worker-a, subnet: 10.200.0.0/28, gateway_ip: 10.200.0.1, ct_zone: 101, route_table: 101}
`
	testLinkSbx1 = `  - {name: sbx1, interface: sbx1, principal: worker-b, subnet: 10.200.0.16/28, gateway_ip: 10.200.0.17, ct_zone: 102, route_table: 102}
`
	testLinkNoInterface = `  - {name: local, principal: worker-c, subnet: 10.200.0.32/28, gateway_ip: 10.200.0.33}
`
)

// fakeHost stands in for the kernel: fake nft and ip binaries log every call,
// and nft keeps the last ruleset it was given.
type fakeHost struct {
	t                              *testing.T
	dir, procRoot, stateFile       string
	readyFile, loaded, liveSets    string
	calls, stateAtLoad, ipFailures string
}

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	dir := t.TempDir()
	h := &fakeHost{
		t:           t,
		dir:         dir,
		procRoot:    filepath.Join(dir, "proc-sys"),
		stateFile:   filepath.Join(dir, "state", "links.json"),
		readyFile:   filepath.Join(dir, "run", "dataplane.ready"),
		loaded:      filepath.Join(dir, "loaded.nft"),
		liveSets:    filepath.Join(dir, "live-sets.json"),
		calls:       filepath.Join(dir, "calls.log"),
		stateAtLoad: filepath.Join(dir, "state-at-load.json"),
		ipFailures:  filepath.Join(dir, "ip-fails"),
	}
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	nftScript := fmt.Sprintf(`#!/bin/sh
printf 'nft %%s\n' "$*" >> %[1]q
case "$*" in
  "-j list sets inet")
    if [ -f %[2]q ]; then cat %[2]q; else echo '{"nftables": []}'; fi ;;
  "-f -")
    cat > %[3]q
    if [ -f %[4]q ]; then cp %[4]q %[5]q; fi ;;
  list*) cat %[3]q ;;
esac
`, h.calls, h.liveSets, h.loaded, h.stateFile, h.stateAtLoad)
	ipScript := fmt.Sprintf(`#!/bin/sh
printf 'ip %%s\n' "$*" >> %q
if [ -f %q ]; then exit 2; fi
`, h.calls, h.ipFailures)
	for name, script := range map[string]string{"nft": nftScript, "ip": ipScript} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	h.addInterface("sbx0")
	h.addInterface("sbx1")
	return h
}

// addInterface creates the /proc/sys entries a present interface would have.
func (h *fakeHost) addInterface(name string) {
	h.t.Helper()
	for _, rel := range []string{
		"net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding",
		"net/ipv4/conf/" + name + "/rp_filter", "net/ipv6/conf/" + name + "/disable_ipv6",
		"net/ipv4/conf/" + name + "/arp_ignore", "net/ipv4/conf/" + name + "/arp_filter",
	} {
		p := filepath.Join(h.procRoot, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			h.t.Fatalf("mkdir sysctl dir: %v", err)
		}
		if err := os.WriteFile(p, []byte("0\n"), 0o644); err != nil {
			h.t.Fatalf("seed sysctl: %v", err)
		}
	}
}

func (h *fakeHost) config(links ...string) *config.Config {
	h.t.Helper()
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
ca: {cert_path: /etc/gateway/ca/ca.crt, key_path: /etc/gateway/ca/ca.key}
audit: {dir: /var/log/gateway/audit}
dataplane:
  ready_file: %s
  state_file: %s
  dhcp: {user: dnsmasq, lease_file: /var/lib/gateway/dnsmasq.leases}
links:
%s`, h.readyFile, h.stateFile, strings.Join(links, ""))))
	if err != nil {
		h.t.Fatalf("Parse: %v", err)
	}
	return cfg
}

// apply runs netsetup with a fresh call log and no previously loaded ruleset.
func (h *fakeHost) apply(links ...string) error {
	h.t.Helper()
	h.remove(h.calls)
	h.remove(h.loaded)
	return applyWithPaths(context.Background(), h.config(links...), h.procRoot, uint32(os.Getuid()))
}

func (h *fakeHost) mustApply(links ...string) {
	h.t.Helper()
	if err := h.apply(links...); err != nil {
		h.t.Fatalf("applyWithPaths: %v", err)
	}
}

// reboot discards everything the kernel and /run would lose.
func (h *fakeHost) reboot() {
	h.t.Helper()
	h.remove(h.liveSets)
	h.remove(h.readyFile)
}

func (h *fakeHost) remove(path string) {
	h.t.Helper()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		h.t.Fatalf("remove %s: %v", path, err)
	}
}

func (h *fakeHost) write(path, content string) {
	h.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		h.t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		h.t.Fatalf("write %s: %v", path, err)
	}
}

// read returns the file's content, or "" if it does not exist.
func (h *fakeHost) read(path string) string {
	h.t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		h.t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

func chainBody(t *testing.T, ruleset, chain string) string {
	t.Helper()
	_, rest, ok := strings.Cut(ruleset, "    chain "+chain+" {\n")
	if !ok {
		t.Fatalf("ruleset has no chain %s:\n%s", chain, ruleset)
	}
	body, _, ok := strings.Cut(rest, "\n    }\n")
	if !ok {
		t.Fatalf("chain %s is not closed:\n%s", chain, ruleset)
	}
	return body
}

// assertBlocked requires that the loaded ruleset drops everything to, from and
// through exactly the named interfaces.
func assertBlocked(t *testing.T, ruleset string, interfaces ...string) {
	t.Helper()
	quoted := `"` + strings.Join(interfaces, `", "`) + `"`
	want := "    set retired_ifs {\n        type ifname\n        elements = { " + quoted + " }\n    }\n"
	if !strings.Contains(ruleset, want) {
		t.Fatalf("ruleset does not list %v as retired:\n%s", interfaces, ruleset)
	}
	for chain, rules := range map[string][]string{
		"prerouting_guard": {"iifname @retired_ifs drop"},
		"input":            {"iifname @retired_ifs drop"},
		"forward":          {"iifname @retired_ifs drop", "oifname @retired_ifs drop"},
		"output":           {"oifname @retired_ifs drop"},
	} {
		body := chainBody(t, ruleset, chain)
		firstAccept := strings.Index(body, " accept\n")
		for _, rule := range rules {
			at := strings.Index(body, rule)
			if at < 0 {
				t.Fatalf("chain %s is missing %q:\n%s", chain, rule, body)
			}
			// The chain policy line ends in "accept;", so this only sees accept rules.
			if firstAccept >= 0 && at > firstAccept {
				t.Fatalf("chain %s: %q comes after an accept rule:\n%s", chain, rule, body)
			}
		}
	}
}

func TestRemovedLinkStaysBlocked(t *testing.T) {
	h := newFakeHost(t)
	h.mustApply(testLinkSbx0, testLinkSbx1)
	if strings.Contains(h.read(h.loaded), "retired_ifs") {
		t.Fatalf("nothing is retired yet:\n%s", h.read(h.loaded))
	}

	// Service restart after sbx1 is removed from the config.
	h.mustApply(testLinkSbx0)
	assertBlocked(t, h.read(h.loaded), "sbx1")

	calls := h.read(h.calls)
	for _, want := range []string{
		"ip addr del 10.200.0.17/28 dev sbx1\n",
		"ip route del default dev sbx1 scope link table 102\n",
		"ip rule del from 10.200.0.17/32 lookup 102\n",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing cleanup %q in:\n%s", want, calls)
		}
	}
	for _, forbidden := range []string{"dev sbx1 down", "flush"} {
		if strings.Contains(calls, forbidden) {
			t.Errorf("netsetup must not run %q:\n%s", forbidden, calls)
		}
	}
	if strings.Index(calls, "nft -f -") > strings.Index(calls, "ip addr del") {
		t.Errorf("drop rules must load before the old address is removed:\n%s", calls)
	}

	// Reboot: the live table is gone and only the record on disk remains.
	h.reboot()
	h.mustApply(testLinkSbx0)
	assertBlocked(t, h.read(h.loaded), "sbx1")

	// A second restart keeps it blocked.
	h.mustApply(testLinkSbx0)
	assertBlocked(t, h.read(h.loaded), "sbx1")
}

func TestRetiredInterfaceNeedNotExist(t *testing.T) {
	h := newFakeHost(t)
	h.mustApply(testLinkSbx0, testLinkSbx1)
	if err := os.RemoveAll(filepath.Join(h.procRoot, "net", "ipv4", "conf", "sbx1")); err != nil {
		t.Fatalf("remove sbx1: %v", err)
	}
	h.write(h.ipFailures, "")
	// Only the cleanup commands may fail; with no configured link every ip call is cleanup.
	err := h.apply(testLinkNoInterface)
	if err == nil || !strings.Contains(err.Error(), "no links declare a Linux interface") {
		t.Fatalf("err = %v, want no-links error", err)
	}
	assertBlocked(t, h.read(h.loaded), "sbx0", "sbx1")
}

func TestRenamedInterfaceIsBlocked(t *testing.T) {
	h := newFakeHost(t)
	h.addInterface("sbx9")
	h.mustApply(testLinkSbx0, testLinkSbx1)
	h.mustApply(testLinkSbx0, strings.ReplaceAll(testLinkSbx1, "interface: sbx1", "interface: sbx9"))
	assertBlocked(t, h.read(h.loaded), "sbx1")
	calls := h.read(h.calls)
	// The same address, table and rule move to sbx9: cleanup must run before they are added.
	del := strings.LastIndex(calls, "ip rule del from 10.200.0.17/32 lookup 102\n")
	add := strings.Index(calls, "ip rule add from 10.200.0.17/32 lookup 102 pref")
	if del < 0 || add < 0 || del > add {
		t.Fatalf("cleanup of the old rule must precede adding the new one:\n%s", calls)
	}
}

func TestEveryEarlierAssignmentIsRemoved(t *testing.T) {
	h := newFakeHost(t)
	h.mustApply(testLinkSbx0, testLinkSbx1)
	h.mustApply(testLinkSbx0, strings.ReplaceAll(testLinkSbx1, "route_table: 102", "route_table: 202"))
	h.mustApply(testLinkSbx0)
	calls := h.read(h.calls)
	for _, want := range []string{
		"ip rule del from 10.200.0.17/32 lookup 102\n",
		"ip rule del from 10.200.0.17/32 lookup 202\n",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing cleanup %q in:\n%s", want, calls)
		}
	}
}

func TestConfiguringALinkAgainUnblocksIt(t *testing.T) {
	h := newFakeHost(t)
	h.mustApply(testLinkSbx0, testLinkSbx1)
	h.mustApply(testLinkSbx0)
	h.mustApply(testLinkSbx0, testLinkSbx1)
	if ruleset := h.read(h.loaded); strings.Contains(ruleset, "retired_ifs") {
		t.Fatalf("sbx1 is configured again but still retired:\n%s", ruleset)
	}
	if calls := h.read(h.calls); strings.Contains(calls, "ip addr del") {
		t.Fatalf("configured links must not be cleaned up:\n%s", calls)
	}
}

// An upgrade finds no record, but the table loaded by the previous version
// still lists the interface being removed.
func TestInterfacesInLiveTableAreAdopted(t *testing.T) {
	for _, set := range []string{"sandbox_ifs", "retired_ifs"} {
		t.Run(set, func(t *testing.T) {
			h := newFakeHost(t)
			h.write(h.liveSets, `{"nftables": [{"metainfo": {"json_schema_version": 1}},
{"set": {"family": "inet", "name": "`+set+`", "table": "gw", "type": "ifname", "elem": ["sbx0", "sbx1"]}},
{"set": {"family": "inet", "name": "`+set+`", "table": "other", "type": "ifname", "elem": ["eth0"]}}]}`)
			h.mustApply(testLinkSbx0)
			assertBlocked(t, h.read(h.loaded), "sbx1")
			h.reboot()
			h.mustApply(testLinkSbx0)
			assertBlocked(t, h.read(h.loaded), "sbx1")
		})
	}
}

func TestRecordIsWrittenBeforeKernelChanges(t *testing.T) {
	h := newFakeHost(t)
	h.mustApply(testLinkSbx0, testLinkSbx1)
	atLoad := h.read(h.stateAtLoad)
	for _, want := range []string{"sbx0", "sbx1", "10.200.0.17"} {
		if !strings.Contains(atLoad, want) {
			t.Fatalf("record at first nft load is missing %q: %q", want, atLoad)
		}
	}
}

// A configured interface that is missing fails setup, but must not leave a
// retired one open after a reboot.
func TestSysctlFailureStillBlocksRetiredInterfaces(t *testing.T) {
	h := newFakeHost(t)
	h.mustApply(testLinkSbx0, testLinkSbx1)
	h.reboot()
	if err := os.RemoveAll(filepath.Join(h.procRoot, "net", "ipv4", "conf", "sbx0")); err != nil {
		t.Fatalf("remove sbx0: %v", err)
	}
	err := h.apply(testLinkSbx0)
	if err == nil || !strings.Contains(err.Error(), "write sysctl") {
		t.Fatalf("err = %v, want sysctl failure", err)
	}
	assertBlocked(t, h.read(h.loaded), "sbx1")
	if calls := h.read(h.calls); strings.Contains(calls, "ip link set") {
		t.Fatalf("no link may be brought up after a sysctl failure:\n%s", calls)
	}
	if h.read(h.readyFile) != "" {
		t.Fatal("ready_file must not be written after a failure")
	}
}

func TestUnusableRecordFailsClosed(t *testing.T) {
	for name, content := range map[string]string{
		"not json":          "{",
		"empty":             "",
		"unknown version":   `{"version": 2, "interfaces": []}`,
		"unknown field":     `{"version": 1, "interfaces": [], "extra": true}`,
		"bad name":          `{"version": 1, "interfaces": [{"name": "a\" }"}]}`,
		"bad address":       `{"version": 1, "interfaces": [{"name": "sbx1", "assignments": [{"gateway_ip": "x", "prefix_bits": 28, "route_table": 102}]}]}`,
		"ipv6 gateway":      `{"version": 1, "interfaces": [{"name": "sbx1", "assignments": [{"gateway_ip": "::1", "prefix_bits": 28, "route_table": 102}]}]}`,
		"bad prefix":        `{"version": 1, "interfaces": [{"name": "sbx1", "assignments": [{"gateway_ip": "10.200.0.17", "prefix_bits": 33, "route_table": 102}]}]}`,
		"trailing document": `{"version": 1, "interfaces": []} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			h := newFakeHost(t)
			h.write(h.stateFile, content)
			err := h.apply(testLinkSbx0)
			if err == nil || !strings.Contains(err.Error(), "state_file") {
				t.Fatalf("err = %v, want state_file error", err)
			}
			if h.read(h.loaded) != "" || h.read(h.readyFile) != "" {
				t.Fatal("an unusable record must stop netsetup before it changes anything")
			}
			if got := h.read(h.stateFile); got != content {
				t.Fatalf("unusable record was overwritten: %q", got)
			}
		})
	}
}

func TestReleaseUnblocksOneRetiredInterface(t *testing.T) {
	h := newFakeHost(t)
	h.mustApply(testLinkSbx0, testLinkSbx1)
	h.mustApply(testLinkSbx0)
	release := func(name string) error {
		h.remove(h.calls)
		return applyWithPaths(context.Background(), h.config(testLinkSbx0), h.procRoot, uint32(os.Getuid()), name)
	}

	for name, want := range map[string]string{"sbx0": "still configures it", "eth9": "not a retired interface"} {
		if err := release(name); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("release %s: err = %v, want %q", name, err, want)
		}
		if calls := h.read(h.calls); strings.Contains(calls, "nft -f -") {
			t.Fatalf("a refused release must not load a ruleset:\n%s", calls)
		}
	}

	// The table loaded by the previous run still lists sbx1; release must win.
	h.write(h.liveSets, `{"nftables": [{"set": {"family": "inet", "name": "retired_ifs", "table": "gw", "elem": ["sbx1"]}}]}`)
	if err := release("sbx1"); err != nil {
		t.Fatalf("release sbx1: %v", err)
	}
	if ruleset := h.read(h.loaded); strings.Contains(ruleset, "sbx1") {
		t.Fatalf("released interface is still in the ruleset:\n%s", ruleset)
	}
	if state := h.read(h.stateFile); strings.Contains(state, "sbx1") {
		t.Fatalf("released interface is still recorded:\n%s", state)
	}
	calls := h.read(h.calls)
	if strings.Count(calls, "nft -f -") != 2 ||
		strings.Index(calls, "ip addr del 10.200.0.17/28") > strings.LastIndex(calls, "nft -f -") {
		t.Fatalf("the old address must be removed while the interface is still blocked:\n%s", calls)
	}

	h.reboot()
	h.mustApply(testLinkSbx0)
	if ruleset := h.read(h.loaded); strings.Contains(ruleset, "retired_ifs") {
		t.Fatalf("released interface came back:\n%s", ruleset)
	}
}

func TestRetiredPlanReadsTheRecordAndChangesNothing(t *testing.T) {
	h := newFakeHost(t)
	h.mustApply(testLinkSbx0, testLinkSbx1)
	before := h.read(h.stateFile)
	h.remove(h.calls)

	retired, cleanup, err := retiredPlan(h.config(testLinkSbx0), uint32(os.Getuid()))
	if err != nil {
		t.Fatalf("retiredPlan: %v", err)
	}
	if len(retired) != 1 || retired[0] != "sbx1" {
		t.Fatalf("retired = %v, want [sbx1]", retired)
	}
	if len(cleanup) != 3 {
		t.Fatalf("cleanup = %+v, want rule, route and address deletion", cleanup)
	}
	if h.read(h.stateFile) != before || h.read(h.calls) != "" {
		t.Fatalf("planning must not write the record or run commands: %q", h.read(h.calls))
	}
}
