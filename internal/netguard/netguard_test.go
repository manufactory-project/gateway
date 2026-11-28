// SPDX-License-Identifier: AGPL-3.0-only

package netguard_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"go.uber.org/goleak"

	"github.com/manufactory-project/gateway/internal/netguard"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

type stubResolver struct {
	mu      sync.Mutex
	answers map[string][][]netip.Addr
	calls   map[string]int
}

func (r *stubResolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	host, rooted := strings.CutSuffix(host, ".")
	if !rooted {
		return nil, errors.New("unrooted lookup: the resolver search list could rewrite the name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := r.calls[host]
	r.calls[host] = idx + 1
	seq := r.answers[host]
	if len(seq) == 0 {
		return nil, errors.New("nxdomain")
	}
	if idx >= len(seq) {
		idx = len(seq) - 1
	}
	return seq[idx], nil
}

func TestCheckAddrIPv4AndIPv6Matrix(t *testing.T) {
	deniedIPv4 := []string{
		"0.0.0.0",
		"0.1.2.3",
		"10.0.0.1",
		"100.64.0.1",
		"127.0.0.1",
		"169.254.169.254",
		"172.16.0.1",
		"192.0.0.1",
		"192.0.2.1",
		"192.88.99.1",
		"192.168.1.1",
		"198.18.0.1",
		"198.19.255.254",
		"198.51.100.1",
		"203.0.113.1",
		"224.0.0.1",
		"240.0.0.1",
		"255.255.255.255",
	}
	for _, s := range deniedIPv4 {
		addr := netip.MustParseAddr(s)
		if err := netguard.CheckAddr(addr, netip.Addr{}, netip.Prefix{}); !errors.Is(err, netguard.ErrBlockedAddress) {
			t.Errorf("IPv4 %s: got err=%v, want ErrBlockedAddress", s, err)
		}
	}

	allowedIPv4 := []string{
		"1.1.1.1",
		"8.8.8.8",
		"151.101.1.69",
		"140.82.121.4",
		"::ffff:1.1.1.1", // v4-mapped public IPv4 must unmap before prefix check
	}
	for _, s := range allowedIPv4 {
		addr := netip.MustParseAddr(s)
		if err := netguard.CheckAddr(addr, netip.Addr{}, netip.Prefix{}); err != nil {
			t.Errorf("public IPv4 %s unexpectedly blocked: %v", s, err)
		}
	}
	// v4-mapped pinned IPv4 must unmap before matching pinned record.
	if err := netguard.CheckAddr(netip.MustParseAddr("::ffff:10.10.20.5"), netip.MustParseAddr("10.10.20.5"), netip.Prefix{}); err != nil {
		t.Errorf("v4-mapped pinned IP unexpectedly blocked: %v", err)
	}

	deniedIPv6 := []string{
		"::",
		"::1",
		"::ffff:127.0.0.1",
		"::ffff:10.0.0.1",
		"::ffff:169.254.169.254",
		"64:ff9b::1.1.1.1",
		"64:ff9b:1::1",
		"2001::1",
		"2001:0:4136:e378::1",
		"2001:db8::1",
		"2002:c0a8:101::1",
		"3fff::1",
		"fc00::1",
		"fd12:3456::1",
		"fe80::1",
		"ff02::1",
	}
	for _, s := range deniedIPv6 {
		addr := netip.MustParseAddr(s)
		if err := netguard.CheckAddr(addr, netip.Addr{}, netip.Prefix{}); !errors.Is(err, netguard.ErrBlockedAddress) {
			t.Errorf("IPv6 %s: got err=%v, want ErrBlockedAddress", s, err)
		}
	}

	allowedIPv6 := []string{
		"2606:4700:4700::1111",
		"2001:4860:4860::8888",
		"2a00:1450:4001:800::200e",
	}
	for _, s := range allowedIPv6 {
		addr := netip.MustParseAddr(s)
		if err := netguard.CheckAddr(addr, netip.Addr{}, netip.Prefix{}); err != nil {
			t.Errorf("public IPv6 %s unexpectedly blocked: %v", s, err)
		}
	}
}
