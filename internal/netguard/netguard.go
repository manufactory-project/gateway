// SPDX-License-Identifier: AGPL-3.0-only

// Package netguard enforces connect-time SSRF protection in net.Dialer.Control:
// full IPv4 special/private deny list, IPv6 global unicast 2000::/3
// allowlist minus special ranges, Unmap() before prefix checks, dial-by-name only,
// and private-IP exceptions strictly via a pin: the one exact address a rule
// pins for a host. Nothing inside the fake-IP range is ever dialed.
package netguard

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ErrBlockedAddress indicates that a destination IP was refused by connect-time SSRF policy.
var ErrBlockedAddress = errors.New("netguard: destination address blocked by SSRF guard")

// ErrIPLiteralHost indicates that a caller attempted to dial an IP literal instead of a hostname.
var ErrIPLiteralHost = errors.New("netguard: dial-by-name requires a hostname, not an IP literal")

// maxDialAddrs bounds how many resolved addresses one dial may try.
const maxDialAddrs = 4

// IPv4 special-purpose and private ranges denied by default (IANA special-purpose registry).
var ipv4DenyPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// IPv6 allowlist: only global unicast 2000::/3 minus these special ranges.
var (
	ipv6GlobalUnicast = netip.MustParsePrefix("2000::/3")
	ipv6SpecialDeny   = []netip.Prefix{
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("3fff::/20"),
	}
)

// Resolver abstracts upstream DNS hostname resolution (defaults to net.DefaultResolver).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// CheckAddr enforces connect-time SSRF rules on addr after Unmap(). Addresses
// inside fake are always refused, pin included. If pin is valid (a rule's pin for
// this exact host), only that exact unmapped IP is permitted past the private-space guard.
func CheckAddr(addr, pin netip.Addr, fake netip.Prefix) error {
	if !addr.IsValid() {
		return fmt.Errorf("%w: invalid address", ErrBlockedAddress)
	}
	addr = addr.Unmap()
	if fake.Contains(addr) {
		return fmt.Errorf("%w: %s is inside the fake-IP range %s", ErrBlockedAddress, addr, fake)
	}
	if pin.IsValid() {
		if addr == pin.Unmap() {
			return nil
		}
		return fmt.Errorf("%w: %s does not match pin %s", ErrBlockedAddress, addr, pin.Unmap())
	}

	if addr.Is4() {
		for _, p := range ipv4DenyPrefixes {
			if p.Contains(addr) {
				return fmt.Errorf("%w: IPv4 %s in denied prefix %s", ErrBlockedAddress, addr, p)
			}
		}
		return nil
	}

	if addr.Is6() {
		if !ipv6GlobalUnicast.Contains(addr) {
			return fmt.Errorf("%w: IPv6 %s outside 2000::/3", ErrBlockedAddress, addr)
		}
		for _, p := range ipv6SpecialDeny {
			if p.Contains(addr) {
				return fmt.Errorf("%w: IPv6 %s in denied special prefix %s", ErrBlockedAddress, addr, p)
			}
		}
		return nil
	}

	return fmt.Errorf("%w: unsupported address %s", ErrBlockedAddress, addr)
}

// Dialer dials upstream hosts strictly by name and enforces CheckAddr in
// net.Dialer.Control on every connect attempt.
type Dialer struct {
	resolver Resolver
	timeout  time.Duration
	fake     netip.Prefix
}

// Options configures a Dialer.
type Options struct {
	Resolver Resolver
	// Timeout bounds one whole dial, resolution included. Default 15s.
	Timeout time.Duration
	// FakePrefix is dns.fake_cidr: no address inside it is ever dialed.
	FakePrefix netip.Prefix
}

// NewDialer constructs a connect-time SSRF-guarded Dialer.
func NewDialer(opts Options) *Dialer {
	res := opts.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Dialer{resolver: res, timeout: timeout, fake: opts.FakePrefix}
}

// DialPinned dials addr's hostname (refusing IP literals), the shape of
// http.Transport's DialContext plus the pin of the rule that allowed the request:
// a valid pin is dialed directly with no resolution; the zero Addr resolves upstream.
func (d *Dialer) DialPinned(ctx context.Context, network, addr string, pin netip.Addr) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("netguard: split host:port %q: %w", addr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("netguard: invalid port %q", portStr)
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return nil, fmt.Errorf("%w: empty host", ErrIPLiteralHost)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil, fmt.Errorf("%w: %q", ErrIPLiteralHost, addr)
	}

	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	var ips []netip.Addr
	if pin.IsValid() {
		ips = []netip.Addr{pin.Unmap()}
	} else if ips, err = d.resolve(ctx, network, host); err != nil {
		return nil, err
	}

	// Dial per-address shares of the one overall deadline, so a blackholed
	// address cannot use up the time for the rest.
	nd := d.makeNetDialer(pin, d.timeout/time.Duration(len(ips)))
	var lastErr error
	for _, ip := range ips {
		conn, dialErr := nd.DialContext(ctx, network, net.JoinHostPort(ip.String(), portStr))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	return nil, lastErr
}

// resolve returns at most maxDialAddrs addresses that pass CheckAddr. If none
// does, it returns the first refusal.
func (d *Dialer) resolve(ctx context.Context, network, host string) ([]netip.Addr, error) {
	// Rooted, so the host's resolver search list cannot rewrite the name.
	ips, err := d.resolver.LookupNetIP(ctx, ipNetwork(network), host+".")
	if err != nil {
		return nil, fmt.Errorf("netguard: resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("netguard: resolve %s: no addresses", host)
	}
	var ok []netip.Addr
	var firstErr error
	for _, ip := range ips {
		ip = ip.Unmap()
		if err := CheckAddr(ip, netip.Addr{}, d.fake); err != nil {
			firstErr = cmp.Or(firstErr, err)
			continue
		}
		if len(ok) < maxDialAddrs {
			ok = append(ok, ip)
		}
	}
	if len(ok) == 0 {
		return nil, firstErr
	}
	return ok, nil
}

func (d *Dialer) makeNetDialer(pin netip.Addr, perAddr time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout:   perAddr,
		KeepAlive: 30 * time.Second,
		Control: func(_ string, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: parse %q: %v", ErrBlockedAddress, address, err)
			}
			return CheckAddr(ap.Addr(), pin, d.fake)
		},
	}
}

func ipNetwork(network string) string {
	switch network {
	case "tcp4", "udp4":
		return "ip4"
	case "tcp6", "udp6":
		return "ip6"
	default:
		return "ip"
	}
}
