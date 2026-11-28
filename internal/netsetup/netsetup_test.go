// SPDX-License-Identifier: AGPL-3.0-only

package netsetup_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/goleak"
	"gopkg.in/yaml.v3"

	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/netsetup"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func loadExampleConfig(t *testing.T) *config.Config {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "gateway.yaml"))
	if err != nil {
		t.Fatalf("read examples/gateway.yaml: %v", err)
	}
	// Example config must use <forge-ip> placeholder and never hardcode a literal IPv4 in records:.
	if !strings.Contains(string(raw), "<forge-ip>") {
		t.Fatal("examples/gateway.yaml must contain <forge-ip> placeholder")
	}
	var doc struct {
		Records map[string]string `yaml:"records"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal records from examples/gateway.yaml: %v", err)
	}
	for host, val := range doc.Records {
		if addr, err := netip.ParseAddr(strings.TrimSpace(val)); err == nil && addr.Is4() {
			t.Fatalf("examples/gateway.yaml records[%q] must not contain literal IPv4 address %q", host, val)
		}
	}
	replaced := strings.ReplaceAll(string(raw), "<forge-ip>", "10.10.20.5")
	cfg, err := config.Parse([]byte(replaced))
	if err != nil {
		t.Fatalf("parse examples/gateway.yaml with sample IP: %v", err)
	}
	return cfg
}

func TestRenderNftablesInvariants(t *testing.T) {
	cfg := loadExampleConfig(t)
	nft, err := netsetup.RenderNftables(cfg)
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}

	// Table must be `inet gw` with atomic recreate header.
	mustContain := []string{
		"table inet gw",
		"delete table inet gw",
		"table inet gw {",
		`elements = { "sbx0", "sbx1" }`,
		`iifname "sbx0" ct zone set 101`,
		`ip saddr 10.200.0.1 ct zone set 101`,
		`iifname @sandbox_ifs meta nfproto ipv6 drop`,
		`iifname "sbx0" fib daddr type local ip daddr 10.200.0.1 udp dport { 53, 67 } accept`,
		`iifname @sandbox_ifs fib daddr type local drop`,
		// All guest :53 (any destination IP) must be DNATed to gateway's DNS.
		`iifname "sbx0" udp dport 53 dnat ip to 10.200.0.1:10053`,
		`iifname "sbx0" tcp dport 53 dnat ip to 10.200.0.1:10053`,
		`iifname "sbx0" tcp dport 443 dnat ip to 10.200.0.1:10443`,
		`iifname "sbx0" tcp dport 80 dnat ip to 10.200.0.1:10080`,
		`iifname @sandbox_ifs ct status dnat accept`,
		`iifname @sandbox_ifs udp sport 68 udp dport 67 accept`,
		`oifname @sandbox_ifs meta nfproto ipv6 drop`,
	}
	for _, want := range mustContain {
		if !strings.Contains(nft, want) {
			t.Errorf("rendered nftables missing %q\nfull output:\n%s", want, nft)
		}
	}

	// Extract input chain and verify NO udp/tcp dport 53 accepts exist there.
	inputStart := strings.Index(nft, "chain input {")
	inputEnd := strings.Index(nft[inputStart:], "}")
	inputChain := nft[inputStart : inputStart+inputEnd]
	if strings.Contains(inputChain, "dport 53") {
		t.Fatalf("input chain must not contain dport 53 rules:\n%s", inputChain)
	}
	if !strings.Contains(inputChain, "udp dport 67 accept") {
		t.Fatalf("input chain must keep UDP 67 accept:\n%s", inputChain)
	}

	// Extract prerouting_nat and verify :53 dnat has NO ip daddr filter.
	natStart := strings.Index(nft, "chain prerouting_nat {")
	natEnd := strings.Index(nft[natStart:], "}")
	natChain := nft[natStart : natStart+natEnd]
	if strings.Contains(natChain, "ip daddr") {
		t.Fatalf("prerouting_nat must redirect all guest :53 regardless of ip daddr:\n%s", natChain)
	}

	// VerifyNftTableOutput positive control & containment.
	if err := netsetup.VerifyNftTableOutput(nft); err != nil {
		t.Fatalf("VerifyNftTableOutput positive control failed: %v", err)
	}
	missingInput := strings.Replace(nft, "chain input {", "chain renamed_input {", 1)
	if err := netsetup.VerifyNftTableOutput(missingInput); err == nil {
		t.Fatal("VerifyNftTableOutput must fail when a required chain is missing")
	}
	wrongTable := strings.ReplaceAll(nft, "table inet gw", "table inet other")
	if err := netsetup.VerifyNftTableOutput(wrongTable); err == nil {
		t.Fatal("VerifyNftTableOutput must fail when table inet gw is absent")
	}
}

func TestIPCommandsAndSysctlsAndDnsmasq(t *testing.T) {
	cfg := loadExampleConfig(t)

	// IP commands: subnet prefix (/28, NOT /32) on interface + /32 source rule + scope link.
	cmds := netsetup.IPCommands(cfg)
	var joined []string
	for _, c := range cmds {
		joined = append(joined, strings.Join(c.Args, " "))
	}
	allCmds := strings.Join(joined, "\n")
	for _, want := range []string{
		"ip addr replace 10.200.0.1/28 dev sbx0",
		"ip route replace default dev sbx0 scope link table 101",
		"ip rule add from 10.200.0.1/32 lookup 101 pref 1000",
		"ip addr replace 10.200.0.17/28 dev sbx1",
		"ip route replace default dev sbx1 scope link table 102",
		"ip rule add from 10.200.0.17/32 lookup 102 pref 1001",
	} {
		if !strings.Contains(allCmds, want) {
			t.Errorf("IPCommands missing %q\ngot:\n%s", want, allCmds)
		}
	}
	if strings.Contains(allCmds, "ip addr replace 10.200.0.1/32") {
		t.Fatalf("IPCommands must assign DHCP subnet prefix, not /32:\n%s", allCmds)
	}

	// Dnsmasq config: DHCP-only, unconditional dhcp-broadcast (no tag), no-ping, bind-interfaces, explicit user, router+DNS options.
	dm, err := netsetup.RenderDnsmasq(cfg)
	if err != nil {
		t.Fatalf("RenderDnsmasq: %v", err)
	}
	for _, want := range []string{
		"\nport=0\n",
		"\ndhcp-broadcast\n",
		"\nno-ping\n",
		"\nbind-interfaces\n",
		"\nuser=dnsmasq\n",
		"\ndhcp-leasefile=/var/lib/gateway/dnsmasq.leases\n",
		"\ninterface=sbx0\n",
		"\ndhcp-range=interface:sbx0,10.200.0.2,10.200.0.14,255.255.255.240,12h\n",
		"\ndhcp-option=interface:sbx0,option:router,10.200.0.1\n",
		"\ndhcp-option=interface:sbx0,option:dns-server,10.200.0.1\n",
		"\ninterface=sbx1\n",
		"\ndhcp-range=interface:sbx1,10.200.0.18,10.200.0.30,255.255.255.240,12h\n",
		"\ndhcp-option=interface:sbx1,option:router,10.200.0.17\n",
		"\ndhcp-option=interface:sbx1,option:dns-server,10.200.0.17\n",
	} {
		if !strings.Contains(dm, want) {
			t.Errorf("RenderDnsmasq missing %q\ngot:\n%s", want, dm)
		}
	}
	if strings.Contains(dm, "dhcp-broadcast=") {
		t.Fatalf("dhcp-broadcast must have no tag:\n%s", dm)
	}

	// VerifySysctls positive control & containment against a temp /proc/sys root.
	procRoot := t.TempDir()
	for _, sc := range netsetup.DesiredSysctls(cfg) {
		p := filepath.Join(procRoot, strings.ReplaceAll(sc.Key, ".", string(filepath.Separator)))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir sysctl parent: %v", err)
		}
		if err := os.WriteFile(p, []byte(sc.Value+"\n"), 0o644); err != nil {
			t.Fatalf("write sysctl: %v", err)
		}
	}
	if err := netsetup.VerifySysctls(procRoot, cfg); err != nil {
		t.Fatalf("VerifySysctls positive control failed: %v", err)
	}

	// Flip ip_forward to 1 -> must fail closed.
	ipFwd := filepath.Join(procRoot, "net", "ipv4", "ip_forward")
	if err := os.WriteFile(ipFwd, []byte("1\n"), 0o644); err != nil {
		t.Fatalf("flip ip_forward: %v", err)
	}
	if err := netsetup.VerifySysctls(procRoot, cfg); err == nil {
		t.Fatal("VerifySysctls must fail when net.ipv4.ip_forward=1")
	}
}

func TestExampleConfigsParseAndRenderNftables(t *testing.T) {
	for _, name := range []string{"workers.yaml", "two-links.yaml"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "examples", name)
			cfg, _, err := config.LoadFile(path)
			if err != nil {
				t.Fatalf("config.LoadFile(%s): %v", path, err)
			}
			nft, err := netsetup.RenderNftables(cfg)
			if err != nil {
				t.Fatalf("netsetup.RenderNftables(%s): %v", name, err)
			}
			if err := netsetup.VerifyNftTableOutput(nft); err != nil {
				t.Fatalf("netsetup.VerifyNftTableOutput(%s): %v", name, err)
			}
		})
	}
}

// TestRenderNftablesGoldenTwoLinks compares RenderNftables(examples/two-links.yaml)
// byte for byte against internal/netsetup/testdata/two-links.nft.
//
// To regenerate the golden file deliberately after an intentional ruleset change, run:
//
//	UPDATE_NFT_GOLDEN=1 go test -run TestRenderNftablesGoldenTwoLinks ./internal/netsetup
func TestRenderNftablesGoldenTwoLinks(t *testing.T) {
	cfgPath := filepath.Join("..", "..", "examples", "two-links.yaml")
	cfg, _, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("config.LoadFile(%s): %v", cfgPath, err)
	}
	got, err := netsetup.RenderNftables(cfg)
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}

	goldenPath := filepath.Join("testdata", "two-links.nft")
	if os.Getenv("UPDATE_NFT_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden %s: %v", goldenPath, err)
		}
	}

	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v", goldenPath, err)
	}
	want := string(wantBytes)
	if got != want {
		t.Fatalf("RenderNftables(examples/two-links.yaml) drifted from %s:\n--- want ---\n%s\n--- got ---\n%s", goldenPath, want, got)
	}
}
