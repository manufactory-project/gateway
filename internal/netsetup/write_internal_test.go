// SPDX-License-Identifier: AGPL-3.0-only

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

func TestWriteOwnedFileSafety(t *testing.T) {
	uid := uint32(os.Getuid())

	t.Run("creates missing dir 0755 and writes 0644 atomically", func(t *testing.T) {
		targetDir := filepath.Join(t.TempDir(), "dataplane")
		target := filepath.Join(targetDir, "dnsmasq.conf")
		if err := writeOwnedFile(target, []byte("port=0\n"), uid); err != nil {
			t.Fatalf("writeOwnedFile: %v", err)
		}
		dirInfo, err := os.Lstat(targetDir)
		if err != nil {
			t.Fatalf("lstat dir: %v", err)
		}
		if dirInfo.Mode().Perm() != 0o755 {
			t.Fatalf("dir mode = %04o, want 0755", dirInfo.Mode().Perm())
		}
		fileInfo, err := os.Lstat(target)
		if err != nil {
			t.Fatalf("lstat file: %v", err)
		}
		if fileInfo.Mode().Perm() != 0o644 {
			t.Fatalf("file mode = %04o, want 0644", fileInfo.Mode().Perm())
		}
		got, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("read file: %v", err)
		}
		if string(got) != "port=0\n" {
			t.Fatalf("content = %q, want %q", got, "port=0\n")
		}
	})

	t.Run("refuses wrong owner uid", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "owned")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		err := writeOwnedFile(filepath.Join(dir, "f"), []byte("x"), uid+1)
		if err == nil || !strings.Contains(err.Error(), "owned by uid") {
			t.Fatalf("expected ownership error, got %v", err)
		}
	})

	t.Run("refuses group-writable dir", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "grp")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Chmod(dir, 0o775); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		err := writeOwnedFile(filepath.Join(dir, "f"), []byte("x"), uid)
		if err == nil || !strings.Contains(err.Error(), "unsafe mode") {
			t.Fatalf("expected unsafe mode error for 0775, got %v", err)
		}
	})

	t.Run("refuses other-writable dir", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "oth")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Chmod(dir, 0o757); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		err := writeOwnedFile(filepath.Join(dir, "f"), []byte("x"), uid)
		if err == nil || !strings.Contains(err.Error(), "unsafe mode") {
			t.Fatalf("expected unsafe mode error for 0757, got %v", err)
		}
	})

	t.Run("refuses symlinked directory", func(t *testing.T) {
		base := t.TempDir()
		realDir := filepath.Join(base, "real")
		if err := os.Mkdir(realDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		symDir := filepath.Join(base, "sym")
		if err := os.Symlink(realDir, symDir); err != nil {
			t.Fatalf("symlink dir: %v", err)
		}
		err := writeOwnedFile(filepath.Join(symDir, "f"), []byte("x"), uid)
		if err == nil || !strings.Contains(err.Error(), "symlink parent directory") {
			t.Fatalf("expected symlink dir error, got %v", err)
		}
	})

	t.Run("refuses symlinked destination file", func(t *testing.T) {
		base := t.TempDir()
		dir := filepath.Join(base, "dp")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		victim := filepath.Join(base, "victim")
		if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
			t.Fatalf("write victim: %v", err)
		}
		link := filepath.Join(dir, "dnsmasq.conf")
		if err := os.Symlink(victim, link); err != nil {
			t.Fatalf("symlink file: %v", err)
		}
		err := writeOwnedFile(link, []byte("overwrite"), uid)
		if err == nil || !strings.Contains(err.Error(), "symlink destination") {
			t.Fatalf("expected symlink destination error, got %v", err)
		}
		got, rErr := os.ReadFile(victim)
		if rErr != nil || string(got) != "keep" {
			t.Fatalf("victim file altered: %q (err=%v)", got, rErr)
		}
	})
}

func TestApplyOrderSysctlsAndNftBeforeIP(t *testing.T) {
	dir := t.TempDir()
	procRoot := filepath.Join(dir, "proc-sys")
	dpDir := filepath.Join(dir, "dataplane")
	readyFile := filepath.Join(dpDir, "dataplane.ready")
	dnsmasqFile := filepath.Join(dpDir, "dnsmasq.conf")
	stateFile := filepath.Join(dir, "state", "links.json")

	cfgYAML := fmt.Sprintf(`
ca:
  cert_path: /etc/gateway/ca/ca.crt
  key_path: /etc/gateway/ca/ca.key
audit:
  dir: /var/log/gateway/audit
dataplane:
  ready_file: %s
  state_file: %s
  dhcp:
    user: dnsmasq
    lease_file: /var/lib/gateway/dnsmasq.leases
    config_path: %s
links:
  - name: sbx0
    interface: sbx0
    principal: worker-a
    subnet: 10.200.0.0/28
    gateway_ip: 10.200.0.1
    ct_zone: 101
    route_table: 101
`, readyFile, stateFile, dnsmasqFile)
	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, sc := range DesiredSysctls(cfg) {
		p := filepath.Join(procRoot, strings.ReplaceAll(sc.Key, ".", string(filepath.Separator)))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir sysctl dir: %v", err)
		}
		if err := os.WriteFile(p, []byte("9\n"), 0o644); err != nil {
			t.Fatalf("seed sysctl: %v", err)
		}
	}

	nftOut, err := RenderNftables(cfg)
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}
	nftOutPath := filepath.Join(dir, "nft.out")
	if err := os.WriteFile(nftOutPath, []byte(nftOut), 0o600); err != nil {
		t.Fatalf("write nft.out: %v", err)
	}
	orderLog := filepath.Join(dir, "order.log")
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir binDir: %v", err)
	}
	ipFwdFile := filepath.Join(procRoot, "net", "ipv4", "ip_forward")
	nftScript := fmt.Sprintf(`#!/bin/sh
val="$(cat %q)"
printf 'nft %%s (ip_forward=%%s)\n' "$*" "$val" >> %q
if [ "$1" = "-j" ]; then
  echo '{"nftables": []}'
fi
if [ "$1" = "list" ]; then
  cat %q
fi
`, ipFwdFile, orderLog, nftOutPath)
	ipScript := fmt.Sprintf(`#!/bin/sh
printf 'ip %%s\n' "$*" >> %q
`, orderLog)
	if err := os.WriteFile(filepath.Join(binDir, "nft"), []byte(nftScript), 0o755); err != nil {
		t.Fatalf("write fake nft: %v", err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "ip"), []byte(ipScript), 0o755); err != nil {
		t.Fatalf("write fake ip: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := applyWithPaths(context.Background(), cfg, procRoot, uint32(os.Getuid())); err != nil {
		t.Fatalf("applyWithPaths: %v", err)
	}

	rawLog, err := os.ReadFile(orderLog)
	if err != nil {
		t.Fatalf("read order.log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(rawLog)), "\n")
	nftLoadIdx, firstIPIdx := -1, -1
	for i, line := range lines {
		if strings.HasPrefix(line, "nft -f -") {
			nftLoadIdx = i
			if !strings.Contains(line, "(ip_forward=0)") {
				t.Fatalf("sysctls were not applied before nft -f -: %q", line)
			}
		}
		if strings.HasPrefix(line, "ip ") && firstIPIdx == -1 {
			firstIPIdx = i
		}
	}
	if nftLoadIdx < 0 || firstIPIdx < 0 {
		t.Fatalf("missing expected commands in order.log:\n%s", string(rawLog))
	}
	if nftLoadIdx >= firstIPIdx {
		t.Fatalf("nft -f - (line %d) must run BEFORE first ip command (line %d):\n%s", nftLoadIdx, firstIPIdx, string(rawLog))
	}
}

func TestApplyRefusesUnsafeReadyFileBeforeRemoval(t *testing.T) {
	uid := uint32(os.Getuid())

	newCfg := func(readyFile string) *config.Config {
		t.Helper()
		cfgYAML := fmt.Sprintf(`
ca:
  cert_path: /etc/gateway/ca/ca.crt
  key_path: /etc/gateway/ca/ca.key
audit:
  dir: /var/log/gateway/audit
dataplane:
  ready_file: %s
  dhcp:
    user: dnsmasq
    lease_file: /var/lib/gateway/dnsmasq.leases
links:
  - name: sbx0
    interface: sbx0
    principal: worker-a
    subnet: 10.200.0.0/28
    gateway_ip: 10.200.0.1
    ct_zone: 101
    route_table: 101
`, readyFile)
		cfg, err := config.Parse([]byte(cfgYAML))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		return cfg
	}

	t.Run("symlinked_ready_file_refused_and_untouched", func(t *testing.T) {
		base := t.TempDir()
		dpDir := filepath.Join(base, "dp")
		if err := os.Mkdir(dpDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		victim := filepath.Join(base, "victim")
		if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
			t.Fatalf("write victim: %v", err)
		}
		readyLink := filepath.Join(dpDir, "dataplane.ready")
		if err := os.Symlink(victim, readyLink); err != nil {
			t.Fatalf("symlink: %v", err)
		}

		err := applyWithPaths(context.Background(), newCfg(readyLink), filepath.Join(base, "proc"), uid)
		if err == nil || !strings.Contains(err.Error(), "refusing symlink") {
			t.Fatalf("applyWithPaths err = %v, want symlink refusal", err)
		}
		if _, lErr := os.Lstat(readyLink); lErr != nil {
			t.Fatalf("symlinked ready_file was removed despite refusal: %v", lErr)
		}
		got, rErr := os.ReadFile(victim)
		if rErr != nil || string(got) != "keep" {
			t.Fatalf("victim file altered: %q (err=%v)", got, rErr)
		}
	})

	t.Run("group_writable_parent_dir_refused_and_untouched", func(t *testing.T) {
		base := t.TempDir()
		dpDir := filepath.Join(base, "dp-grp")
		if err := os.Mkdir(dpDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		readyFile := filepath.Join(dpDir, "dataplane.ready")
		if err := os.WriteFile(readyFile, []byte("keep"), 0o644); err != nil {
			t.Fatalf("write readyFile: %v", err)
		}
		if err := os.Chmod(dpDir, 0o775); err != nil {
			t.Fatalf("chmod: %v", err)
		}

		err := applyWithPaths(context.Background(), newCfg(readyFile), filepath.Join(base, "proc"), uid)
		if err == nil || !strings.Contains(err.Error(), "unsafe mode") {
			t.Fatalf("applyWithPaths err = %v, want unsafe mode refusal", err)
		}
		got, rErr := os.ReadFile(readyFile)
		if rErr != nil || string(got) != "keep" {
			t.Fatalf("ready_file in group-writable dir was removed/altered: %q (err=%v)", got, rErr)
		}
	})

	t.Run("symlinked_parent_dir_refused_and_untouched", func(t *testing.T) {
		base := t.TempDir()
		realDir := filepath.Join(base, "real")
		if err := os.Mkdir(realDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		victim := filepath.Join(realDir, "dataplane.ready")
		if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
			t.Fatalf("write victim: %v", err)
		}
		symDir := filepath.Join(base, "sym")
		if err := os.Symlink(realDir, symDir); err != nil {
			t.Fatalf("symlink dir: %v", err)
		}

		err := applyWithPaths(context.Background(), newCfg(filepath.Join(symDir, "dataplane.ready")), filepath.Join(base, "proc"), uid)
		if err == nil || !strings.Contains(err.Error(), "symlink parent directory") {
			t.Fatalf("applyWithPaths err = %v, want symlink parent directory refusal", err)
		}
		got, rErr := os.ReadFile(victim)
		if rErr != nil || string(got) != "keep" {
			t.Fatalf("target file under symlinked parent was removed/altered: %q (err=%v)", got, rErr)
		}
	})

	t.Run("wrong_owner_uid_parent_dir_refused_and_untouched", func(t *testing.T) {
		base := t.TempDir()
		dpDir := filepath.Join(base, "dp-uid")
		if err := os.Mkdir(dpDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		readyFile := filepath.Join(dpDir, "dataplane.ready")
		if err := os.WriteFile(readyFile, []byte("keep"), 0o644); err != nil {
			t.Fatalf("write readyFile: %v", err)
		}

		err := applyWithPaths(context.Background(), newCfg(readyFile), filepath.Join(base, "proc"), uid+1)
		if err == nil || !strings.Contains(err.Error(), "owned by uid") {
			t.Fatalf("applyWithPaths err = %v, want uid ownership refusal", err)
		}
		got, rErr := os.ReadFile(readyFile)
		if rErr != nil || string(got) != "keep" {
			t.Fatalf("ready_file in wrong-owner dir was removed/altered: %q (err=%v)", got, rErr)
		}
	})
}

func TestApplyRemovesStaleReadyFileBeforeFailing(t *testing.T) {
	base := t.TempDir()
	dpDir := filepath.Join(base, "dp")
	if err := os.Mkdir(dpDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	staleReady := filepath.Join(dpDir, "dataplane.ready")
	if err := os.WriteFile(staleReady, []byte("stale\n"), 0o644); err != nil {
		t.Fatalf("write stale ready file: %v", err)
	}
	cfgYAML := fmt.Sprintf(`
ca:
  cert_path: /etc/gateway/ca/ca.crt
  key_path: /etc/gateway/ca/ca.key
audit:
  dir: /var/log/gateway/audit
dataplane:
  ready_file: %s
  state_file: %s
  dhcp:
    user: dnsmasq
    lease_file: /var/lib/gateway/dnsmasq.leases
links:
  - name: sbx0
    interface: sbx0
    principal: worker-a
    subnet: 10.200.0.0/28
    gateway_ip: 10.200.0.1
    ct_zone: 101
    route_table: 101
`, staleReady, filepath.Join(base, "state", "links.json"))
	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// applyWithPaths fails on missing procfs sysctl, and MUST have deleted staleReady first when parent ownership checks pass.
	if err := applyWithPaths(context.Background(), cfg, filepath.Join(base, "nonexistent-proc"), uint32(os.Getuid())); err == nil {
		t.Fatal("expected applyWithPaths to fail on missing procfs")
	}
	if _, err := os.Stat(staleReady); !os.IsNotExist(err) {
		t.Fatalf("stale ready_file was not removed before applyWithPaths failed: stat err=%v", err)
	}
}
