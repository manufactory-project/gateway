// SPDX-License-Identifier: AGPL-3.0-or-later

// Command gateway-probe is a static, stdlib-only guest probe that verifies
// gateway and Linux nftables containment with positive controls and emits
// one JSON line per check ({check, expect, got, pass}).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"
)

func logf(w io.Writer, format string, args ...any) {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		return
	}
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		logf(os.Stderr, "gateway-probe: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	cfg, err := parseFlags(args, stderr)
	if err != nil {
		return err
	}
	results := runAllChecks(ctx, cfg)
	return emitResults(stdout, results)
}

func parseFlags(args []string, stderr io.Writer) (probeConfig, error) {
	fs := flag.NewFlagSet("gateway-probe", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var cfg probeConfig
	var fakeCIDR string

	fs.StringVar(&cfg.AllowHost, "allow-host", "", "allowlisted HTTPS hostname (required)")
	fs.StringVar(&cfg.AllowPath, "allow-path", "/get", "GET path on allow-host returning 2xx")
	fs.StringVar(&cfg.UploadPath, "upload-path", "/post", "POST path on allow-host accepting >64 KiB body")
	fs.StringVar(&cfg.DownloadPath, "download-path", "/bytes/70000", "GET path on allow-host returning >64 KiB body")
	fs.StringVar(&cfg.DenyHost, "deny-host", "denied.example.invalid", "non-allowlisted hostname for DNS REFUSED and Host spoof")
	fs.StringVar(&cfg.LinkIP, "link-ip", "", "guest gateway link IP (required in normal mode)")
	fs.IntVar(&cfg.HTTPSPort, "https-port", 10443, "gateway HTTPS listener port on link-ip")
	fs.StringVar(&fakeCIDR, "fake-cidr", "198.18.0.0/15", "expected fake-IPv4 CIDR for allowlisted DNS A records")
	fs.StringVar(&cfg.WrongIP, "wrong-ip", "203.0.113.1", "non-upstream IPv4 used for dial-by-name control")
	fs.StringVar(&cfg.DirectHTTPSIP, "direct-https-ip", "1.1.1.1", "IP literal for direct HTTPS (no SNI) check")
	fs.StringVar(&cfg.DNSServer, "dns-server", "", "DNS server host:port (defaults to <link-ip>:53)")
	fs.StringVar(&cfg.RedirectDNS, "redirect-dns", "8.8.8.8:53", "external DNS host:port for :53 redirect checks")
	fs.StringVar(&cfg.TCP22Target, "tcp22-target", "1.1.1.1:22", "blocked TCP 22 target")
	fs.StringVar(&cfg.DoTTarget, "dot-target", "1.1.1.1:853", "blocked TCP 853 (DoT) target")
	fs.StringVar(&cfg.QUICTarget, "quic-target", "1.1.1.1:443", "blocked UDP 443 (QUIC) target")
	fs.StringVar(&cfg.LANAddr, "lan-addr", "", "LAN ip:port expected to be unreachable (required in normal mode)")
	fs.StringVar(&cfg.MetadataAddr, "metadata-addr", "169.254.169.254:80", "cloud metadata ip:port expected to be unreachable")
	fs.StringVar(&cfg.MgmtIP, "mgmt-ip", "", "gateway management IP expected to be unreachable (required in normal mode)")
	fs.StringVar(&cfg.IPv6Target, "ipv6-target", "[2606:4700:4700::1111]:443", "IPv6 target expected to be dropped")
	fs.StringVar(&cfg.PeerLinkIP, "peer-link-ip", "", "other sandbox link gateway IP expected to be unreachable")
	fs.StringVar(&cfg.PeerGuestAddr, "peer-guest-addr", "", "other sandbox link guest ip:port expected to be unreachable")
	fs.DurationVar(&cfg.Timeout, "timeout", 3*time.Second, "per-check timeout")

	fs.BoolVar(&cfg.SameIP, "same-ip", false, "run same-IP mode using fixed --src-ip and --src-port for TCP :443 and UDP :53")
	fs.StringVar(&cfg.SrcIP, "src-ip", "", "fixed source IPv4 for --same-ip mode")
	fs.IntVar(&cfg.SrcPort, "src-port", 0, "fixed source port (1-65535) for --same-ip mode")
	fs.StringVar(&cfg.SameIPHTTPSDst, "same-ip-https-dst", "", "shared TCP :443 destination ip:port for --same-ip mode (defaults to <wrong-ip>:443)")
	fs.StringVar(&cfg.SameIPDNSDst, "same-ip-dns-dst", "8.8.8.8:53", "shared UDP :53 destination ip:port for --same-ip mode")
	fs.DurationVar(&cfg.Hold, "hold", 0, "hold same-IP TCP :443 connection open for this duration")

	if err := fs.Parse(args); err != nil {
		return probeConfig{}, err
	}
	if cfg.AllowHost == "" {
		return probeConfig{}, errors.New("--allow-host is required")
	}
	prefix, err := netip.ParsePrefix(fakeCIDR)
	if err != nil || !prefix.Addr().Is4() {
		return probeConfig{}, fmt.Errorf("invalid --fake-cidr %q", fakeCIDR)
	}
	cfg.FakePrefix = prefix.Masked()

	if cfg.SameIP {
		if ip, err := netip.ParseAddr(cfg.SrcIP); err != nil || !ip.Is4() {
			return probeConfig{}, fmt.Errorf("--src-ip %q must be a valid IPv4 address in --same-ip mode", cfg.SrcIP)
		}
		if cfg.SrcPort < 1 || cfg.SrcPort > 65535 {
			return probeConfig{}, fmt.Errorf("--src-port %d must be in [1, 65535] in --same-ip mode", cfg.SrcPort)
		}
		if cfg.SameIPHTTPSDst == "" {
			cfg.SameIPHTTPSDst = net.JoinHostPort(cfg.WrongIP, "443")
		}
		return cfg, nil
	}

	if cfg.LinkIP == "" {
		return probeConfig{}, errors.New("--link-ip is required")
	}
	if cfg.LANAddr == "" {
		return probeConfig{}, errors.New("--lan-addr is required")
	}
	if cfg.MgmtIP == "" {
		return probeConfig{}, errors.New("--mgmt-ip is required")
	}
	if cfg.DNSServer == "" {
		cfg.DNSServer = net.JoinHostPort(cfg.LinkIP, "53")
	}
	return cfg, nil
}

func emitResults(w io.Writer, results []Result) error {
	enc := json.NewEncoder(w)
	failed := 0
	for _, r := range results {
		if err := enc.Encode(r); err != nil {
			return err
		}
		if !r.Pass {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d checks failed", failed, len(results))
	}
	return nil
}
