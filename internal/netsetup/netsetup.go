// Package netsetup generates and applies the Linux data plane (nftables ruleset,
// sysctls, per-link ip addr/route/rule commands, and DHCP-only dnsmasq config)
// purely from gateway's YAML configuration.
package netsetup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/manufactory-project/gateway/internal/config"
)

// NftTableName is the sole nftables inet table managed by gateway netsetup.
const NftTableName = "gw"

// RequiredNftChains are the chains that must exist inside table inet gw.
var RequiredNftChains = []string{
	"raw_prerouting",
	"raw_output",
	"prerouting_guard",
	"prerouting_nat",
	"input",
	"forward",
	"output",
}

// Sysctl represents one kernel sysctl key and its required value.
type Sysctl struct {
	Key   string
	Value string
}

// IPCommand represents one `ip` invocation; Optional means non-zero exit is ignored
// (for deletions of things that may not exist).
type IPCommand struct {
	Args     []string
	Optional bool
}

// RenderNftables generates the atomic nftables ruleset for table inet gw from cfg.
// All traffic to, from and through the retired interfaces is dropped.
func RenderNftables(cfg *config.Config, retired ...string) (string, error) {
	links := cfg.Links
	if len(links) == 0 && len(retired) == 0 {
		return "", errors.New("netsetup: no links declare a Linux interface")
	}
	return renderRuleset(links, retired), nil
}

func renderRuleset(links []config.LinkConfig, retired []string) string {
	// retiredDrop writes a drop rule for retired interfaces, if there are any.
	retiredDrop := func(b *strings.Builder, direction string) {
		if len(retired) > 0 {
			writeLine(b, "        ", direction, " @", retiredSet, " drop")
		}
	}

	var b strings.Builder
	b.WriteString("table inet gw\n")
	b.WriteString("delete table inet gw\n\n")
	b.WriteString("table inet gw {\n")

	var configured []string
	for _, l := range links {
		configured = append(configured, l.Interface)
	}
	writeIfnameSet(&b, sandboxSet, configured)
	if len(retired) > 0 {
		writeIfnameSet(&b, retiredSet, retired)
	}

	b.WriteString("    chain raw_prerouting {\n")
	b.WriteString("        type filter hook prerouting priority raw; policy accept;\n")
	for _, l := range links {
		writeLine(&b, "        iifname ", strconv.Quote(l.Interface), " ct zone set ", strconv.Itoa(int(l.CTZone)))
	}
	b.WriteString("    }\n\n")

	b.WriteString("    chain raw_output {\n")
	b.WriteString("        type filter hook output priority raw; policy accept;\n")
	for _, l := range links {
		writeLine(&b, "        ip saddr ", l.ParsedGatewayIP.String(), " ct zone set ", strconv.Itoa(int(l.CTZone)))
	}
	b.WriteString("    }\n\n")

	b.WriteString("    chain prerouting_guard {\n")
	b.WriteString("        type filter hook prerouting priority dstnat - 10; policy accept;\n")
	retiredDrop(&b, "iifname")
	b.WriteString("        iifname @sandbox_ifs meta nfproto ipv6 drop\n")
	for _, l := range links {
		qIf := strconv.Quote(l.Interface)
		gw := l.ParsedGatewayIP.String()
		writeLine(&b, "        iifname ", qIf, " fib daddr type local ip daddr ", gw, " udp dport { 53, 67 } accept")
		writeLine(&b, "        iifname ", qIf, " fib daddr type local ip daddr ", gw, " tcp dport 53 accept")
	}
	b.WriteString("        iifname @sandbox_ifs fib daddr type local drop\n")
	b.WriteString("    }\n\n")

	b.WriteString("    chain prerouting_nat {\n")
	b.WriteString("        type nat hook prerouting priority dstnat; policy accept;\n")
	for _, l := range links {
		qIf := strconv.Quote(l.Interface)
		gw := l.ParsedGatewayIP.String()
		// Redirect ALL guest :53 to any destination to gateway's DNS.
		writeLine(&b, "        iifname ", qIf, " udp dport 53 dnat ip to ", gw, ":", strconv.Itoa(int(l.DNSPort)))
		writeLine(&b, "        iifname ", qIf, " tcp dport 53 dnat ip to ", gw, ":", strconv.Itoa(int(l.DNSPort)))
		writeLine(&b, "        iifname ", qIf, " tcp dport 443 dnat ip to ", gw, ":", strconv.Itoa(int(l.HTTPSPort)))
		writeLine(&b, "        iifname ", qIf, " tcp dport 80 dnat ip to ", gw, ":", strconv.Itoa(int(l.HTTPPort)))
	}
	b.WriteString("    }\n\n")

	// DNS has already been DNATed to :<dns_port> and admitted by `ct status dnat accept`;
	// no udp/tcp dport 53 rules belong here. Keep UDP 67 for DHCPv4.
	b.WriteString("    chain input {\n")
	b.WriteString("        type filter hook input priority filter; policy accept;\n")
	retiredDrop(&b, "iifname")
	b.WriteString("        iifname @sandbox_ifs meta nfproto ipv6 drop\n")
	b.WriteString("        iifname @sandbox_ifs ct state invalid drop\n")
	b.WriteString("        iifname @sandbox_ifs ct status dnat accept\n")
	b.WriteString("        iifname @sandbox_ifs udp sport 68 udp dport 67 accept\n")
	b.WriteString("        iifname @sandbox_ifs drop\n")
	b.WriteString("    }\n\n")

	b.WriteString("    chain forward {\n")
	b.WriteString("        type filter hook forward priority filter; policy accept;\n")
	retiredDrop(&b, "iifname")
	retiredDrop(&b, "oifname")
	b.WriteString("        iifname @sandbox_ifs drop\n")
	b.WriteString("        oifname @sandbox_ifs drop\n")
	b.WriteString("    }\n\n")

	b.WriteString("    chain output {\n")
	b.WriteString("        type filter hook output priority filter; policy accept;\n")
	retiredDrop(&b, "oifname")
	b.WriteString("        oifname @sandbox_ifs meta nfproto ipv6 drop\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")

	return b.String()
}

func writeIfnameSet(b *strings.Builder, name string, interfaces []string) {
	writeLine(b, "    set ", name, " {")
	b.WriteString("        type ifname\n")
	if len(interfaces) > 0 {
		quoted := make([]string, len(interfaces))
		for i, ifname := range interfaces {
			quoted[i] = strconv.Quote(ifname)
		}
		writeLine(b, "        elements = { ", strings.Join(quoted, ", "), " }")
	}
	b.WriteString("    }\n\n")
}

// DesiredSysctls returns the exact kernel sysctls required by gateway.
func DesiredSysctls(cfg *config.Config) []Sysctl {
	out := []Sysctl{
		{Key: "net.ipv4.ip_forward", Value: "0"},
		{Key: "net.ipv6.conf.all.forwarding", Value: "0"},
	}
	for _, l := range cfg.Links {
		out = append(out,
			Sysctl{Key: fmt.Sprintf("net.ipv4.conf.%s.rp_filter", l.Interface), Value: "2"},
			Sysctl{Key: fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6", l.Interface), Value: "1"},
			Sysctl{Key: fmt.Sprintf("net.ipv4.conf.%s.arp_ignore", l.Interface), Value: "1"},
			Sysctl{Key: fmt.Sprintf("net.ipv4.conf.%s.arp_filter", l.Interface), Value: "1"},
		)
	}
	return out
}

// IPCommands returns the ordered `ip` commands to configure sandbox link addresses,
// per-link scope-link routes, and source-based policy routing rules.
func IPCommands(cfg *config.Config) []IPCommand {
	var cmds []IPCommand
	for _, l := range cfg.Links {
		addrWithPrefix := fmt.Sprintf("%s/%d", l.ParsedGatewayIP, l.ParsedSubnet.Bits())
		gwHost := fmt.Sprintf("%s/32", l.ParsedGatewayIP)
		tableStr := strconv.Itoa(l.RouteTable)
		prefStr := strconv.Itoa(l.RoutePref)

		cmds = append(cmds,
			IPCommand{Args: []string{"ip", "link", "set", "dev", l.Interface, "up"}},
			IPCommand{Args: []string{"ip", "addr", "replace", addrWithPrefix, "dev", l.Interface}},
			IPCommand{Args: []string{"ip", "route", "replace", "default", "dev", l.Interface, "scope", "link", "table", tableStr}},
			IPCommand{Args: []string{"ip", "rule", "del", "from", gwHost, "lookup", tableStr}, Optional: true},
			IPCommand{Args: []string{"ip", "rule", "add", "from", gwHost, "lookup", tableStr, "pref", prefStr}},
		)
	}
	return cmds
}

// RenderDnsmasq generates the DHCP-only dnsmasq configuration from cfg.
// Unconditional dhcp-broadcast (no tag) + no-ping ensures dnsmasq drops both
// CAP_NET_ADMIN and CAP_NET_RAW after binding port 67 and dropping to dhcp.user.
func RenderDnsmasq(cfg *config.Config) (string, error) {
	links := cfg.Links
	if len(links) == 0 {
		return "", errors.New("netsetup: no links declare a Linux interface")
	}
	if cfg.Dataplane.DHCP.User == "" {
		return "", errors.New("netsetup: dataplane.dhcp.user is required")
	}
	if cfg.Dataplane.DHCP.LeaseFile == "" {
		return "", errors.New("netsetup: dataplane.dhcp.lease_file is required")
	}

	var b strings.Builder
	b.WriteString("# Generated by gateway netsetup. Do not edit by hand.\n")
	b.WriteString("port=0\n")
	b.WriteString("dhcp-broadcast\n")
	b.WriteString("no-ping\n")
	b.WriteString("bind-interfaces\n")
	b.WriteString("no-resolv\n")
	b.WriteString("no-hosts\n")
	writeLine(&b, "user=", cfg.Dataplane.DHCP.User)
	writeLine(&b, "dhcp-leasefile=", cfg.Dataplane.DHCP.LeaseFile)

	for _, l := range links {
		start, end, mask, err := dhcpPool(l.ParsedSubnet, l.ParsedGatewayIP)
		if err != nil {
			return "", fmt.Errorf("netsetup: link %q dhcp pool: %w", l.Name, err)
		}
		gw := l.ParsedGatewayIP.String()
		writeLine(&b, "interface=", l.Interface)
		writeLine(&b, "dhcp-range=interface:", l.Interface, ",", start.String(), ",", end.String(), ",", mask.String(), ",", cfg.Dataplane.DHCP.LeaseTime)
		writeLine(&b, "dhcp-option=interface:", l.Interface, ",option:router,", gw)
		writeLine(&b, "dhcp-option=interface:", l.Interface, ",option:dns-server,", gw)
	}
	return b.String(), nil
}

func writeLine(b *strings.Builder, parts ...string) {
	for _, p := range parts {
		b.WriteString(p)
	}
	b.WriteByte('\n')
}

// VerifyNftTableOutput confirms that `nft list table inet gw` output contains
// `table inet gw` and every required chain. It does not hash nft output.
func VerifyNftTableOutput(listOutput string) error {
	if !strings.Contains(listOutput, "table inet "+NftTableName+" {") {
		return fmt.Errorf("netsetup: table inet %s not found in nft output", NftTableName)
	}
	var missing []string
	for _, chain := range RequiredNftChains {
		needle := "chain " + chain + " {"
		if !strings.Contains(listOutput, needle) {
			missing = append(missing, chain)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("netsetup: table inet %s missing required chains: %s", NftTableName, strings.Join(missing, ", "))
	}
	return nil
}

// VerifySysctls checks every required sysctl under procSysRoot (normally "/proc/sys").
func VerifySysctls(procSysRoot string, cfg *config.Config) error {
	for _, sc := range DesiredSysctls(cfg) {
		rel := strings.ReplaceAll(sc.Key, ".", string(filepath.Separator))
		p := filepath.Join(procSysRoot, rel)
		raw, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("netsetup: read sysctl %s (%s): %w", sc.Key, p, err)
		}
		got := strings.TrimSpace(string(raw))
		if got != sc.Value {
			return fmt.Errorf("netsetup: sysctl %s=%q, want %q", sc.Key, got, sc.Value)
		}
	}
	return nil
}

// Apply executes netsetup as root (invoked from systemd ExecStartPre=+):
// removes any stale ready_file first, records the managed interfaces in
// state_file, writes sysctls, loads and verifies the nftables ruleset atomically
// via `nft -f -` (blocking retired interfaces), removes what it earlier added to
// those, then configures interfaces/routes/rules, writes the dnsmasq config, and
// writes ready_file last only after everything has succeeded.
func Apply(ctx context.Context, cfg *config.Config) error {
	return applyWithPaths(ctx, cfg, "/proc/sys", 0)
}

// Release is Apply, but also stops blocking the retired interface name and
// removes it from state_file. A configured interface cannot be released.
func Release(ctx context.Context, cfg *config.Config, name string) error {
	return applyWithPaths(ctx, cfg, "/proc/sys", 0, name)
}

func applyWithPaths(ctx context.Context, cfg *config.Config, procSysRoot string, expectedUID uint32, release ...string) error {
	for _, name := range release {
		if isConfigured(cfg, name) {
			return fmt.Errorf("netsetup: cannot release %q: a link still configures it", name)
		}
	}
	if cfg.Dataplane.ReadyFile != "" {
		if err := removeOwnedFile(cfg.Dataplane.ReadyFile, expectedUID); err != nil {
			return fmt.Errorf("netsetup: remove stale ready_file %s: %w", cfg.Dataplane.ReadyFile, err)
		}
	}

	prev, err := loadRecord(cfg.Dataplane.StateFile, expectedUID)
	if err != nil {
		return err
	}
	live, err := liveInterfaces(ctx)
	if err != nil {
		return err
	}
	rec := mergeRecord(prev, live, cfg)
	retired := retiredInterfaces(rec, cfg)
	for _, name := range release {
		if !slices.Contains(interfaceNames(retired), name) {
			return fmt.Errorf("netsetup: cannot release %q: it is not a retired interface", name)
		}
	}
	ruleset, err := RenderNftables(cfg, interfaceNames(retired)...)
	if err != nil {
		return err
	}
	// Record before changing the kernel, so an interrupted run forgets nothing.
	if err := saveRecord(cfg.Dataplane.StateFile, rec, expectedUID); err != nil {
		return err
	}

	// Apply sysctls and nftables BEFORE bringing links up or assigning addresses
	// so there is no unguarded forwarding or link-local IPv6 window. A sysctl
	// failure (such as a missing interface) is reported only after the ruleset is
	// loaded, so that it cannot leave retired interfaces unblocked.
	sysctlErr := writeSysctls(procSysRoot, cfg)
	if err := loadRuleset(ctx, ruleset); err != nil {
		return errors.Join(sysctlErr, err)
	}
	if err := runIPCommands(ctx, cleanupCommands(retired)); err != nil {
		return errors.Join(sysctlErr, err)
	}
	if sysctlErr != nil {
		return sysctlErr
	}

	// Released interfaces were blocked and cleaned up above; now let them go.
	if len(release) > 0 {
		released := func(m managedInterface) bool { return slices.Contains(release, m.Name) }
		rec.Interfaces = slices.DeleteFunc(rec.Interfaces, released)
		retired = slices.DeleteFunc(retired, released)
		if err := loadRuleset(ctx, renderRuleset(cfg.Links, interfaceNames(retired))); err != nil {
			return err
		}
		if err := saveRecord(cfg.Dataplane.StateFile, rec, expectedUID); err != nil {
			return err
		}
	}

	// Fails when no link declares an interface; retired ones are blocked by now.
	dnsmasqConf, err := RenderDnsmasq(cfg)
	if err != nil {
		return err
	}
	if err := runIPCommands(ctx, IPCommands(cfg)); err != nil {
		return err
	}

	if cfg.Dataplane.DHCP.ConfigPath != "" {
		if err := writeOwnedFile(cfg.Dataplane.DHCP.ConfigPath, []byte(dnsmasqConf), expectedUID); err != nil {
			return fmt.Errorf("netsetup: write dnsmasq config %s: %w", cfg.Dataplane.DHCP.ConfigPath, err)
		}
	}

	if cfg.Dataplane.ReadyFile != "" {
		if err := writeOwnedFile(cfg.Dataplane.ReadyFile, []byte("ok\n"), expectedUID); err != nil {
			return fmt.Errorf("netsetup: write ready_file %s: %w", cfg.Dataplane.ReadyFile, err)
		}
	}
	return nil
}

func writeSysctls(procSysRoot string, cfg *config.Config) error {
	for _, sc := range DesiredSysctls(cfg) {
		rel := strings.ReplaceAll(sc.Key, ".", string(filepath.Separator))
		p := filepath.Join(procSysRoot, rel)
		if err := os.WriteFile(p, []byte(sc.Value+"\n"), 0o644); err != nil {
			return fmt.Errorf("netsetup: write sysctl %s=%s: %w", sc.Key, sc.Value, err)
		}
	}
	return nil
}

func loadRuleset(ctx context.Context, ruleset string) error {
	nftLoad := exec.CommandContext(ctx, "nft", "-f", "-")
	nftLoad.Stdin = strings.NewReader(ruleset)
	if out, err := nftLoad.CombinedOutput(); err != nil {
		return fmt.Errorf("netsetup: nft -f failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return CheckNftTable(ctx)
}

func runIPCommands(ctx context.Context, cmds []IPCommand) error {
	for _, cmdSpec := range cmds {
		cmd := exec.CommandContext(ctx, cmdSpec.Args[0], cmdSpec.Args[1:]...)
		out, err := cmd.CombinedOutput()
		if err != nil && !cmdSpec.Optional {
			return fmt.Errorf("netsetup: %s failed: %w: %s", strings.Join(cmdSpec.Args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// verifyOwnedDir confirms dir is a real (non-symlink) directory owned by expectedUID
// with no group or other write bits set.
func verifyOwnedDir(dir string, expectedUID uint32) error {
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("lstat dir %s: %w", dir, err)
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink parent directory %s", dir)
	}
	if !dirInfo.IsDir() {
		return fmt.Errorf("parent %s is not a directory", dir)
	}
	st, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect owner of %s", dir)
	}
	if st.Uid != expectedUID {
		return fmt.Errorf("directory %s owned by uid %d, want %d", dir, st.Uid, expectedUID)
	}
	if dirInfo.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("directory %s has unsafe mode %04o (group/other writable)", dir, dirInfo.Mode().Perm())
	}
	return nil
}

// removeOwnedFile verifies path's parent directory is owned by expectedUID, not a
// symlink, and not group/other writable, refuses a symlink path, and removes path if
// present. A missing parent directory or missing file is not an error.
func removeOwnedFile(path string, expectedUID uint32) error {
	dir := filepath.Dir(path)
	if err := verifyOwnedDir(dir, expectedUID); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lstat %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink %s", path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// writeOwnedFile ensures path's parent directory is a real (non-symlink) directory
// owned by expectedUID with no group/other write permissions (creating it 0755 if
// missing), refuses a symlink destination, and atomically replaces path via temp file + rename.
func writeOwnedFile(path string, data []byte, expectedUID uint32) error {
	dir := filepath.Dir(path)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
			return fmt.Errorf("mkdir %s: %w", dir, mkErr)
		}
		if chErr := os.Chmod(dir, 0o755); chErr != nil {
			return fmt.Errorf("chmod %s: %w", dir, chErr)
		}
		if syncErr := syncDir(filepath.Dir(dir)); syncErr != nil {
			return syncErr
		}
	}
	if err := verifyOwnedDir(dir, expectedUID); err != nil {
		return err
	}

	if destInfo, lErr := os.Lstat(path); lErr == nil {
		if destInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink destination %s", path)
		}
		if destInfo.IsDir() {
			return fmt.Errorf("destination %s is a directory", path)
		}
	} else if !errors.Is(lErr, os.ErrNotExist) {
		return fmt.Errorf("lstat destination %s: %w", path, lErr)
	}

	tmp, err := os.CreateTemp(dir, ".gateway-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanupTmp := func(cause error) error {
		return errors.Join(cause, os.Remove(tmpName))
	}
	if _, err := tmp.Write(data); err != nil {
		return cleanupTmp(errors.Join(fmt.Errorf("write temp %s: %w", tmpName, err), tmp.Close()))
	}
	if err := tmp.Chmod(0o644); err != nil {
		return cleanupTmp(errors.Join(fmt.Errorf("chmod temp %s: %w", tmpName, err), tmp.Close()))
	}
	if err := tmp.Sync(); err != nil {
		return cleanupTmp(errors.Join(fmt.Errorf("sync temp %s: %w", tmpName, err), tmp.Close()))
	}
	if err := tmp.Close(); err != nil {
		return cleanupTmp(fmt.Errorf("close temp %s: %w", tmpName, err))
	}
	if err := os.Rename(tmpName, path); err != nil {
		return cleanupTmp(fmt.Errorf("rename %s -> %s: %w", tmpName, path, err))
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir %s: %w", dir, err)
	}
	if err := errors.Join(d.Sync(), d.Close()); err != nil {
		return fmt.Errorf("sync dir %s: %w", dir, err)
	}
	return nil
}

// CheckNftTable runs `nft list table inet gw` and confirms table inet gw and its chains exist.
func CheckNftTable(ctx context.Context) error {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "nft", "list", "table", "inet", NftTableName)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("netsetup: nft list table inet %s failed: %w: %s", NftTableName, err, strings.TrimSpace(stderr.String()))
	}
	return VerifyNftTableOutput(stdout.String())
}

// dhcpPool computes a contiguous multi-address DHCP pool inside prefix excluding
// the network address, broadcast address, and gatewayIP.
func dhcpPool(prefix netip.Prefix, gatewayIP netip.Addr) (start, end, netmask netip.Addr, err error) {
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return netip.Addr{}, netip.Addr{}, netip.Addr{}, errors.New("subnet must be IPv4")
	}
	bits := prefix.Bits()
	hostBits := 32 - bits
	if hostBits < 3 {
		return netip.Addr{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("subnet /%d is too small for a multi-address DHCP pool", bits)
	}

	base := addrToUint32(prefix.Addr())
	maskVal := ^uint32(0) << hostBits
	bcast := base | ^maskVal
	gw := addrToUint32(gatewayIP)

	firstHost := base + 1
	lastHost := bcast - 1

	var lo1, hi1, lo2, hi2 uint32
	if gw > firstHost {
		lo1, hi1 = firstHost, gw-1
	}
	if gw < lastHost {
		lo2, hi2 = gw+1, lastHost
	}

	var bestLo, bestHi uint32
	size1 := uint32(0)
	if hi1 >= lo1 && lo1 != 0 {
		size1 = hi1 - lo1 + 1
	}
	size2 := uint32(0)
	if hi2 >= lo2 && lo2 != 0 {
		size2 = hi2 - lo2 + 1
	}
	if size2 >= size1 {
		bestLo, bestHi = lo2, hi2
	} else {
		bestLo, bestHi = lo1, hi1
	}
	if bestHi <= bestLo {
		return netip.Addr{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("cannot carve >=2 DHCP addresses from %s around gateway %s", prefix, gatewayIP)
	}

	return uint32ToAddr(bestLo), uint32ToAddr(bestHi), uint32ToAddr(maskVal), nil
}

func addrToUint32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
