// Package dns implements gatewayd's built-in fake-IPv4 DNS server (NOW.md:41).
// No guest query is ever forwarded upstream: allowlisted names receive a synthetic
// A record from dns.fake_cidr and empty NOERROR (NODATA) for AAAA/HTTPS/SVCB;
// all other record types and all non-allowlisted names receive REFUSED.
// Every query is audited synchronously before answering (fail-closed on sink error).
package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	mdns "github.com/miekg/dns"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/policy"
)

// Allocator assigns stable fake IPv4 addresses from a configured CIDR range,
// skipping network and broadcast addresses.
type Allocator struct {
	prefix netip.Prefix
	first  uint32
	count  uint32

	mu         sync.Mutex
	hostToIP   map[string]netip.Addr
	ipToHost   map[netip.Addr]string
	nextOffset uint32
}

// NewAllocator constructs a fake-IPv4 Allocator for prefix (must be IPv4, <= /30).
func NewAllocator(prefix netip.Prefix) (*Allocator, error) {
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() || prefix.Bits() > 30 {
		return nil, fmt.Errorf("dns: invalid fake_cidr %s", prefix)
	}
	b := prefix.Addr().As4()
	base := binary.BigEndian.Uint32(b[:])
	hostBits := 32 - prefix.Bits()
	total := uint32(1) << hostBits
	usable := total - 2 // exclude network and broadcast
	return &Allocator{
		prefix:   prefix,
		first:    base + 1,
		count:    usable,
		hostToIP: make(map[string]netip.Addr),
		ipToHost: make(map[netip.Addr]string),
	}, nil
}

// Allocate returns the fake IPv4 address for normalized host, assigning a new one
// from the pool if not yet seen.
func (a *Allocator) Allocate(host string) netip.Addr {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	a.mu.Lock()
	defer a.mu.Unlock()

	if ip, ok := a.hostToIP[host]; ok {
		return ip
	}

	h := fnv.New32a()
	// hash.Hash.Write never returns an error.
	if _, err := h.Write([]byte(host)); err != nil {
		return uint32ToIPv4(a.first)
	}
	start := h.Sum32() % a.count

	for i := uint32(0); i < a.count; i++ {
		off := (start + i) % a.count
		cand := uint32ToIPv4(a.first + off)
		if _, used := a.ipToHost[cand]; !used {
			a.hostToIP[host] = cand
			a.ipToHost[cand] = host
			return cand
		}
	}

	// Pool exhausted: deterministically reuse next slot cleanly.
	off := a.nextOffset % a.count
	a.nextOffset++
	cand := uint32ToIPv4(a.first + off)
	if oldHost, exists := a.ipToHost[cand]; exists {
		delete(a.hostToIP, oldHost)
	}
	a.hostToIP[host] = cand
	a.ipToHost[cand] = host
	return cand
}

// Prefix returns the allocator's CIDR prefix.
func (a *Allocator) Prefix() netip.Prefix {
	return a.prefix
}

func uint32ToIPv4(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// Server serves fake-IP DNS over explicit-bind UDP and TCP sockets for a single link.
type Server struct {
	link      config.LinkConfig
	store     *config.Store
	eval      *policy.Evaluator
	audit     *audit.Writer
	allocator *Allocator
	onQuery   func(principal, effect string)

	udpConn net.PacketConn
	tcpLn   net.Listener
	udpSrv  *mdns.Server
	tcpSrv  *mdns.Server
	wg      sync.WaitGroup
}

// ServerOptions configures a per-link DNS Server.
type ServerOptions struct {
	Link      config.LinkConfig
	Store     *config.Store
	Evaluator *policy.Evaluator
	Audit     *audit.Writer
	Allocator *Allocator
	OnQuery   func(principal, effect string)
}

// NewServer creates a per-link fake-IP DNS Server bound to link.ParsedGatewayIP:link.DNSPort.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Store == nil || opts.Evaluator == nil || opts.Audit == nil || opts.Allocator == nil {
		return nil, errors.New("dns: store, evaluator, audit, and allocator are required")
	}
	if !opts.Link.ParsedGatewayIP.IsValid() || opts.Link.ParsedGatewayIP.IsUnspecified() {
		return nil, errors.New("dns: explicit non-wildcard gateway_ip is required")
	}
	return &Server{
		link:      opts.Link,
		store:     opts.Store,
		eval:      opts.Evaluator,
		audit:     opts.Audit,
		allocator: opts.Allocator,
		onQuery:   opts.OnQuery,
	}, nil
}

// Start binds explicit UDP and TCP listeners and starts serving DNS queries.
func (s *Server) Start() error {
	addr := net.JoinHostPort(s.link.ParsedGatewayIP.String(), strconv.Itoa(int(s.link.DNSPort)))
	pc, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return fmt.Errorf("dns: listen udp4 %s: %w", addr, err)
	}
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		closeErr := pc.Close()
		return errors.Join(fmt.Errorf("dns: listen tcp4 %s: %w", addr, err), closeErr)
	}
	s.udpConn = pc
	s.tcpLn = ln

	handler := mdns.HandlerFunc(s.handleDNS)
	udpReady := make(chan struct{})
	tcpReady := make(chan struct{})

	acceptAll := func(_ mdns.Header) mdns.MsgAcceptAction {
		return mdns.MsgAccept
	}
	s.udpSrv = &mdns.Server{
		PacketConn:        pc,
		Handler:           handler,
		MsgAcceptFunc:     acceptAll,
		NotifyStartedFunc: func() { close(udpReady) },
	}
	s.tcpSrv = &mdns.Server{
		Listener:          ln,
		Handler:           handler,
		MsgAcceptFunc:     acceptAll,
		NotifyStartedFunc: func() { close(tcpReady) },
	}

	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		if err := s.udpSrv.ActivateAndServe(); err != nil {
			// Shutdown closes the socket, which causes ActivateAndServe to return.
			return
		}
	}()
	go func() {
		defer s.wg.Done()
		if err := s.tcpSrv.ActivateAndServe(); err != nil {
			return
		}
	}()

	<-udpReady
	<-tcpReady
	return nil
}

// UDPAddr returns the bound UDP socket address (useful when DNSPort is configured).
func (s *Server) UDPAddr() string {
	if s.udpConn == nil {
		return ""
	}
	return s.udpConn.LocalAddr().String()
}

// TCPAddr returns the bound TCP socket address.
func (s *Server) TCPAddr() string {
	if s.tcpLn == nil {
		return ""
	}
	return s.tcpLn.Addr().String()
}

// Shutdown gracefully stops both UDP and TCP DNS servers and waits for goroutines to exit.
func (s *Server) Shutdown(ctx context.Context) error {
	var errs error
	if s.udpSrv != nil {
		if err := s.udpSrv.ShutdownContext(ctx); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	if s.tcpSrv != nil {
		if err := s.tcpSrv.ShutdownContext(ctx); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	s.wg.Wait()
	return errs
}

func (s *Server) handleDNS(w mdns.ResponseWriter, r *mdns.Msg) {
	resp := new(mdns.Msg)
	resp.SetReply(r)
	resp.Authoritative = true
	resp.RecursionAvailable = true

	srcIP := ""
	if remote := w.RemoteAddr(); remote != nil {
		if host, _, err := net.SplitHostPort(remote.String()); err == nil {
			srcIP = host
		}
	}
	proto := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		proto = "tcp"
	}

	if r.Opcode != mdns.OpcodeQuery {
		qname := ""
		qtypeName := ""
		if len(r.Question) > 0 {
			qname = strings.TrimSuffix(strings.ToLower(r.Question[0].Name), ".")
			qtypeName = mdns.TypeToString[r.Question[0].Qtype]
		}
		s.auditAndReply(w, resp, mdns.RcodeNotImplemented, audit.Event{
			Kind:      audit.KindDNS,
			Principal: s.link.Principal,
			Link:      s.link.Name,
			SrcIP:     srcIP,
			Protocol:  proto,
			Host:      qname,
			Port:      53,
			QType:     qtypeName,
			Effect:    audit.EffectDeny,
			Reason:    "opcode-not-implemented",
		})
		return
	}

	if len(r.Question) != 1 {
		qname := ""
		if len(r.Question) > 0 {
			qname = strings.TrimSuffix(strings.ToLower(r.Question[0].Name), ".")
		}
		s.auditAndReply(w, resp, mdns.RcodeRefused, audit.Event{
			Kind:      audit.KindDNS,
			Principal: s.link.Principal,
			Link:      s.link.Name,
			SrcIP:     srcIP,
			Protocol:  proto,
			Host:      qname,
			Port:      53,
			Effect:    audit.EffectDeny,
			Reason:    "invalid-question-count",
		})
		return
	}

	q := r.Question[0]
	qname := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	qtypeName := mdns.TypeToString[q.Qtype]
	if qtypeName == "" {
		qtypeName = fmt.Sprintf("TYPE%d", q.Qtype)
	}

	if q.Qclass != mdns.ClassINET {
		s.auditAndReply(w, resp, mdns.RcodeRefused, audit.Event{
			Kind:      audit.KindDNS,
			Principal: s.link.Principal,
			Link:      s.link.Name,
			SrcIP:     srcIP,
			Protocol:  proto,
			Host:      qname,
			Port:      53,
			QType:     qtypeName,
			Effect:    audit.EffectDeny,
			Reason:    "qclass-refused",
		})
		return
	}

	dec := s.eval.DecideDNS(s.link.Principal, qname)

	var (
		effect  = audit.EffectDeny
		reason  = dec.Reason
		ansAddr string
		rcode   = mdns.RcodeRefused
	)

	if dec.Allow {
		switch q.Qtype {
		case mdns.TypeA:
			fakeIP := s.allocator.Allocate(qname)
			ttl := s.store.Current().Config.DNS.TTLSeconds
			rr := &mdns.A{
				Hdr: mdns.RR_Header{
					Name:   q.Name,
					Rrtype: mdns.TypeA,
					Class:  mdns.ClassINET,
					Ttl:    ttl,
				},
				A: net.IP(fakeIP.AsSlice()),
			}
			resp.Answer = []mdns.RR{rr}
			rcode = mdns.RcodeSuccess
			effect = audit.EffectAllow
			reason = dec.Reason
			ansAddr = fakeIP.String()
		case mdns.TypeAAAA, mdns.TypeHTTPS, mdns.TypeSVCB:
			// Empty NOERROR (NODATA): keeps ECH configs out and avoids stub-resolver refusal errors.
			rcode = mdns.RcodeSuccess
			effect = audit.EffectAllow
			reason = "nodata"
		default:
			// Refuse TXT, MX, NS, SRV, CNAME, etc. even inside allowlisted zones (NOW.md:41).
			rcode = mdns.RcodeRefused
			effect = audit.EffectDeny
			reason = "qtype-refused"
		}
	}

	ev := audit.Event{
		Kind:      audit.KindDNS,
		Principal: s.link.Principal,
		Link:      s.link.Name,
		SrcIP:     srcIP,
		Protocol:  proto,
		Host:      qname,
		Address:   ansAddr,
		Port:      53,
		QType:     qtypeName,
		Effect:    effect,
		Reason:    reason,
		RuleID:    dec.RuleID,
		GrantID:   dec.GrantID,
	}

	s.auditAndReply(w, resp, rcode, ev)
}

func (s *Server) auditAndReply(w mdns.ResponseWriter, resp *mdns.Msg, rcode int, ev audit.Event) {
	// Fail closed if audit sink is unwritable: never answer with an A record.
	if err := s.audit.WriteSync(ev); err != nil {
		resp.Answer = nil
		resp.Rcode = mdns.RcodeServerFailure
		if s.onQuery != nil {
			s.onQuery(s.link.Principal, "audit_error")
		}
		s.writeResponse(w, resp)
		return
	}

	resp.Rcode = rcode
	if s.onQuery != nil {
		s.onQuery(s.link.Principal, string(ev.Effect))
	}
	s.writeResponse(w, resp)
}

func (s *Server) writeResponse(w mdns.ResponseWriter, msg *mdns.Msg) {
	if err := w.WriteMsg(msg); err != nil {
		return
	}
}
