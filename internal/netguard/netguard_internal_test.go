// SPDX-License-Identifier: AGPL-3.0-only

package netguard

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type fixedResolver []netip.Addr

func (r fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r, nil
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

// A name may resolve to many addresses; one dial tries at most maxDialAddrs of
// those that pass the guard, so a hostile resolver cannot stretch a dial.
func TestResolveCapsAddressesTried(t *testing.T) {
	many := addrs("1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5", "1.1.1.6")
	d := NewDialer(Options{Resolver: fixedResolver(many)})
	got, err := d.resolve(context.Background(), "tcp", "many.example.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(got) != maxDialAddrs {
		t.Fatalf("resolve returned %d addresses, want %d", len(got), maxDialAddrs)
	}

	// Positive control: refused addresses do not use up the cap.
	mixed := addrs("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "8.8.8.8")
	d = NewDialer(Options{Resolver: fixedResolver(mixed)})
	got, err = d.resolve(context.Background(), "tcp", "mixed.example.com")
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("resolve(mixed) = %v, %v; want only 8.8.8.8", got, err)
	}

	d = NewDialer(Options{Resolver: fixedResolver(addrs("10.0.0.1", "127.0.0.1"))})
	if _, err = d.resolve(context.Background(), "tcp", "private.example.com"); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("resolve(all blocked) err = %v, want ErrBlockedAddress", err)
	}
}

type recordingResolver struct{ hosts []string }

func (r *recordingResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.hosts = append(r.hosts, host)
	return addrs("8.8.8.8"), nil
}

// The upstream lookup is rooted: an unrooted name would run through the host's
// resolv.conf search list, which can turn an NXDOMAIN name into an internal one.
func TestResolveLooksUpRootedName(t *testing.T) {
	rec := &recordingResolver{}
	d := NewDialer(Options{Resolver: rec})
	if _, err := d.resolve(context.Background(), "tcp", "zzz.partner.com"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(rec.hosts) != 1 || rec.hosts[0] != "zzz.partner.com." {
		t.Fatalf("resolver saw %q, want exactly [\"zzz.partner.com.\"]", rec.hosts)
	}
}
