// SPDX-License-Identifier: AGPL-3.0-only

package netguard_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/netguard"
)

func TestCheckAddrNeverAllowsFakeRange(t *testing.T) {
	fake := netip.MustParsePrefix("203.0.114.0/24") // a range the deny list does not cover
	inside := netip.MustParseAddr("203.0.114.9")
	outside := netip.MustParseAddr("203.0.115.9")

	if err := netguard.CheckAddr(outside, netip.Addr{}, fake); err != nil {
		t.Fatalf("address outside the fake range blocked: %v", err)
	}
	if err := netguard.CheckAddr(inside, netip.Addr{}, fake); !errors.Is(err, netguard.ErrBlockedAddress) {
		t.Fatalf("address inside the fake range: err=%v, want ErrBlockedAddress", err)
	}
	// A pin cannot reopen the fake range either.
	if err := netguard.CheckAddr(inside, inside, fake); !errors.Is(err, netguard.ErrBlockedAddress) {
		t.Fatalf("pin inside the fake range: err=%v, want ErrBlockedAddress", err)
	}
	// A pin elsewhere still works, but only for exactly that address.
	if err := netguard.CheckAddr(outside, outside, fake); err != nil {
		t.Fatalf("pin outside the fake range blocked: %v", err)
	}
	if err := netguard.CheckAddr(netip.MustParseAddr("203.0.115.10"), outside, fake); !errors.Is(err, netguard.ErrBlockedAddress) {
		t.Fatalf("address other than the pin: err=%v, want ErrBlockedAddress", err)
	}
}

func closeConn(t *testing.T, c net.Conn) {
	t.Helper()
	if c != nil {
		if err := c.Close(); err != nil {
			t.Errorf("close conn: %v", err)
		}
	}
}

func TestDialerConnectTimeSSRFRebindingAndPin(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 127.0.0.1: %v", err)
	}
	accepts := make(chan struct{}, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts <- struct{}{}
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
	port := strconv.Itoa(tcpAddr.Port)

	res := &stubResolver{
		answers: map[string][][]netip.Addr{
			// DNS rebinding attempt: resolves directly to loopback / v4-mapped loopback.
			"rebind.nip.io": {
				{netip.MustParseAddr("127.0.0.1")},
				{netip.MustParseAddr("::ffff:127.0.0.1")},
			},
			// Even if upstream DNS answered something else for the pinned host, the pin
			// must win and upstream DNS is never queried.
			"pinned.lan.example": {
				{netip.MustParseAddr("192.0.2.99")},
			},
		},
		calls: make(map[string]int),
	}
	dialer := netguard.NewDialer(netguard.Options{Resolver: res, Timeout: time.Second})
	ctx := context.Background()

	// Containment: unpinned host resolving to 127.0.0.1, then to ::ffff:127.0.0.1, is refused.
	for i := 0; i < 2; i++ {
		c, err := dialer.DialPinned(ctx, "tcp", net.JoinHostPort("rebind.nip.io", port), netip.Addr{})
		closeConn(t, c)
		if !errors.Is(err, netguard.ErrBlockedAddress) {
			t.Fatalf("rebind attempt %d: err=%v, want ErrBlockedAddress", i, err)
		}
	}
	// Containment: an IP literal is refused (dial-by-name only), pinned or not.
	for _, pin := range []netip.Addr{{}, netip.MustParseAddr("127.0.0.1")} {
		c, err := dialer.DialPinned(ctx, "tcp", ln.Addr().String(), pin)
		closeConn(t, c)
		if !errors.Is(err, netguard.ErrIPLiteralHost) {
			t.Fatalf("IP literal dial (pin %v): err=%v, want ErrIPLiteralHost", pin, err)
		}
	}
	if got := len(accepts); got != 0 {
		t.Fatalf("blocked dials reached local listener: accepted=%d, want 0", got)
	}

	// Positive control: an explicit pin reaches the listener without querying upstream DNS.
	pin := netip.MustParseAddr("127.0.0.1")
	conn, err := dialer.DialPinned(ctx, "tcp", net.JoinHostPort("pinned.lan.example", port), pin)
	if err != nil {
		t.Fatalf("pinned dial failed: %v", err)
	}
	closeConn(t, conn)
	if res.calls["pinned.lan.example"] != 0 {
		t.Fatalf("pinned dial queried upstream DNS %d times", res.calls["pinned.lan.example"])
	}

	// A dialer whose fake range covers the pin refuses it: nothing inside the range is dialed.
	fakeDialer := netguard.NewDialer(netguard.Options{Resolver: res, Timeout: time.Second, FakePrefix: netip.MustParsePrefix("127.0.0.0/8")})
	c, err := fakeDialer.DialPinned(ctx, "tcp", net.JoinHostPort("pinned.lan.example", port), pin)
	closeConn(t, c)
	if !errors.Is(err, netguard.ErrBlockedAddress) {
		t.Fatalf("pin inside fake range: err=%v, want ErrBlockedAddress", err)
	}
	select {
	case <-accepts:
	case <-time.After(5 * time.Second):
		t.Fatal("the pinned positive-control dial never reached the listener")
	}
	if got := len(accepts); got != 0 {
		t.Fatalf("fake-range dial reached listener: %d extra accepts", got)
	}
}

type blockingResolver struct{}

func (blockingResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// One overall deadline bounds the whole dial, resolution included.
func TestDialerOverallDeadlineBoundsResolution(t *testing.T) {
	dialer := netguard.NewDialer(netguard.Options{Resolver: blockingResolver{}, Timeout: 50 * time.Millisecond})
	// The outer context only stops a missing deadline from hanging the test.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := dialer.DialPinned(ctx, "tcp", "slow.example.com:443", netip.Addr{})
	closeConn(t, conn)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("dial took %v, want it cut off by the 50ms overall deadline", elapsed)
	}
}
