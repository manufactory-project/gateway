package netguard_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/manufactory-project/gateway/internal/config"
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
		if err := netguard.CheckAddr(addr, netip.Addr{}); !errors.Is(err, netguard.ErrBlockedAddress) {
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
		if err := netguard.CheckAddr(addr, netip.Addr{}); err != nil {
			t.Errorf("public IPv4 %s unexpectedly blocked: %v", s, err)
		}
	}
	// v4-mapped pinned IPv4 must unmap before matching pinned record.
	if err := netguard.CheckAddr(netip.MustParseAddr("::ffff:10.10.20.5"), netip.MustParseAddr("10.10.20.5")); err != nil {
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
		if err := netguard.CheckAddr(addr, netip.Addr{}); !errors.Is(err, netguard.ErrBlockedAddress) {
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
		if err := netguard.CheckAddr(addr, netip.Addr{}); err != nil {
			t.Errorf("public IPv6 %s unexpectedly blocked: %v", s, err)
		}
	}
}

func TestDialerConnectTimeSSRFRebindingAndRecordsPin(t *testing.T) {
	// Start a real local TCP listener on 127.0.0.1 with an atomic accept counter.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 127.0.0.1: %v", err)
	}
	var accepted atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			if err := c.Close(); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		if err := ln.Close(); err != nil {
			t.Errorf("close listener: %v", err)
		}
		<-done
	})

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected addr type %T", ln.Addr())
	}
	port := uint16(tcpAddr.Port)

	cfgPath := filepath.Join(t.TempDir(), "gatewayd.yaml")
	cfgYAML := `
ca:
  cert_path: /tmp/ca.crt
  key_path: /tmp/ca.key
audit:
  dir: /tmp/audit
records:
  pinned.lan.example: 127.0.0.1
links:
  - name: sbx0
    principal: worker-a
    subnet: 127.0.10.0/28
    gateway_ip: 127.0.10.1
rules:
  - id: r1
    principal: worker-a
    effect: allow
    hosts: [pinned.lan.example, rebind.nip.io]
    ports: [443]
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	store, err := config.NewStore(cfgPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	res := &stubResolver{
		answers: map[string][][]netip.Addr{
			// DNS rebinding attempt: resolves directly to loopback / v4-mapped loopback.
			"rebind.nip.io": {
				{netip.MustParseAddr("127.0.0.1")},
				{netip.MustParseAddr("::ffff:127.0.0.1")},
			},
			// Even if upstream DNS tried to answer something else for pinned.lan.example,
			// records must win and never query upstream.
			"pinned.lan.example": {
				{netip.MustParseAddr("192.0.2.99")},
			},
		},
		calls: make(map[string]int),
	}

	dialer := netguard.NewDialer(netguard.Options{
		Store:    store,
		Resolver: res,
		Timeout:  time.Second,
	})

	// Containment 1: unpinned host resolving to 127.0.0.1 is blocked in Dialer.Control (received == 0).
	ctx := context.Background()
	if c, err := dialer.DialHost(ctx, "tcp", "rebind.nip.io", port); !errors.Is(err, netguard.ErrBlockedAddress) {
		if c != nil {
			if closeErr := c.Close(); closeErr != nil {
				t.Errorf("close unexpected conn: %v", closeErr)
			}
		}
		t.Fatalf("expected ErrBlockedAddress on 127.0.0.1 rebind, got err=%v", err)
	}
	// Containment 2: v4-mapped IPv6 ::ffff:127.0.0.1 is unmapped and blocked in Dialer.Control.
	if c, err := dialer.DialHost(ctx, "tcp", "rebind.nip.io", port); !errors.Is(err, netguard.ErrBlockedAddress) {
		if c != nil {
			if closeErr := c.Close(); closeErr != nil {
				t.Errorf("close unexpected conn: %v", closeErr)
			}
		}
		t.Fatalf("expected ErrBlockedAddress on ::ffff:127.0.0.1 rebind, got err=%v", err)
	}
	// Containment 3: dialing an IP literal directly is refused (dial-by-name only).
	if c, err := dialer.DialContext(ctx, "tcp", ln.Addr().String()); !errors.Is(err, netguard.ErrIPLiteralHost) {
		if c != nil {
			if closeErr := c.Close(); closeErr != nil {
				t.Errorf("close unexpected conn: %v", closeErr)
			}
		}
		t.Fatalf("expected ErrIPLiteralHost on IP literal dial, got err=%v", err)
	}

	if got := accepted.Load(); got != 0 {
		t.Fatalf("blocked dials reached local listener: accepted=%d, want 0", got)
	}

	// Positive control: explicitly pinned record reaches the local listener without querying upstream DNS.
	conn, err := dialer.DialHost(ctx, "tcp", "pinned.lan.example", port)
	if err != nil {
		t.Fatalf("pinned record dial failed: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close conn: %v", err)
	}
	// Wait briefly for Accept goroutine to increment counter.
	deadline := time.Now().Add(time.Second)
	for accepted.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := accepted.Load(); got != 1 {
		t.Fatalf("pinned record accepted=%d, want 1", got)
	}
	if res.calls["pinned.lan.example"] != 0 {
		t.Fatalf("pinned record must not query upstream DNS, calls=%d", res.calls["pinned.lan.example"])
	}
}
