// SPDX-License-Identifier: AGPL-3.0-only

// Package netguard enforces connect-time SSRF protection in net.Dialer.Control:
// full IPv4 special/private deny list, IPv6 global unicast 2000::/3
// allowlist minus special ranges, Unmap() before prefix checks, dial-by-name only,
// and private-IP exceptions strictly via static records (host -> exact IP).
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/manufactory-project/gateway/internal/config"
)

// ErrBlockedAddress indicates that a destination IP was refused by connect-time SSRF policy.
var ErrBlockedAddress = errors.New("netguard: destination address blocked by SSRF guard")

// ErrIPLiteralHost indicates that a caller attempted to dial an IP literal instead of a hostname.
var ErrIPLiteralHost = errors.New("netguard: dial-by-name requires a hostname, not an IP literal")

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

// CheckAddr enforces connect-time SSRF rules on addr after Unmap().
// If pinnedIP is valid (from an explicit static records entry for this exact host),
// only that exact unmapped IP is permitted past the private-space guard.
func CheckAddr(addr netip.Addr, pinnedIP netip.Addr) error {
	if !addr.IsValid() {
		return fmt.Errorf("%w: invalid address", ErrBlockedAddress)
	}
	addr = addr.Unmap()
	if pinnedIP.IsValid() {
		if addr == pinnedIP.Unmap() {
			return nil
		}
		return fmt.Errorf("%w: %s does not match pinned record %s", ErrBlockedAddress, addr, pinnedIP.Unmap())
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

// Dialer dials upstream hosts strictly by name, honoring static records overrides
// from store and enforcing CheckAddr in net.Dialer.Control on every connect attempt.
type Dialer struct {
	store    *config.Store
	resolver Resolver
	timeout  time.Duration
}

// Options configures a Dialer.
type Options struct {
	Store    *config.Store
	Resolver Resolver
	Timeout  time.Duration
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
	return &Dialer{
		store:    opts.Store,
		resolver: res,
		timeout:  timeout,
	}
}

// DialContext implements the http.Transport DialContext signature, dialing strictly
// by hostname (refusing IP literals), applying static records, and checking every
// connect-time address in net.Dialer.Control.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("netguard: split host:port %q: %w", addr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("netguard: invalid port %q", portStr)
	}
	return d.DialHost(ctx, network, host, uint16(port))
}

// DialHost dials hostname on port with connect-time Control enforcement.
func (d *Dialer) DialHost(ctx context.Context, network, rawHost string, port uint16) (net.Conn, error) {
	host := config.NormalizeHost(rawHost)
	if host == "" {
		return nil, fmt.Errorf("%w: empty host", ErrIPLiteralHost)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil, fmt.Errorf("%w: %q", ErrIPLiteralHost, rawHost)
	}

	var pinned netip.Addr
	if d.store != nil {
		if snap := d.store.Current(); snap != nil && snap.Config != nil {
			if rec, ok := snap.Config.ParsedRecords[host]; ok {
				pinned = rec.Unmap()
			}
		}
	}

	// If statically pinned in records, dial ONLY the pinned IP directly (no upstream DNS).
	if pinned.IsValid() {
		nd := d.makeNetDialer(pinned)
		target := net.JoinHostPort(pinned.String(), strconv.Itoa(int(port)))
		return nd.DialContext(ctx, network, target)
	}

	// Resolve via upstream resolver, then dial each address through net.Dialer.Control.
	ips, err := d.resolver.LookupNetIP(ctx, ipNetwork(network), host)
	if err != nil {
		return nil, fmt.Errorf("netguard: resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("netguard: resolve %s: no addresses", host)
	}

	nd := d.makeNetDialer(netip.Addr{})
	var lastErr error
	for _, ip := range ips {
		ip = ip.Unmap()
		target := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
		conn, dialErr := nd.DialContext(ctx, network, target)
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	return nil, lastErr
}

func (d *Dialer) makeNetDialer(pinned netip.Addr) *net.Dialer {
	return &net.Dialer{
		Timeout:   d.timeout,
		KeepAlive: 30 * time.Second,
		Control: func(_ string, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: parse %q: %v", ErrBlockedAddress, address, err)
			}
			return CheckAddr(ap.Addr(), pinned)
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
