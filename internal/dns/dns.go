// Package dns implements gateway's built-in fake-IPv4 DNS server.
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
	"sync"
	"sync/atomic"

	mdns "github.com/miekg/dns"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/connlimit"
	"github.com/manufactory-project/gateway/internal/policy"
)

// Allocator deterministically maps normalized hostnames into usable IPv4 addresses
// in a configured CIDR range (excluding network and broadcast addresses).
// It is stateless and concurrency-safe: nothing reverse-resolves fake IPs because
// the proxy routes by TLS SNI and HTTP Host/:authority.
type Allocator struct {
	first uint32
	count uint32
}

// NewAllocator constructs a stateless fake-IPv4 Allocator for prefix (must be IPv4, <= /30).
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
		first: base + 1,
		count: usable,
	}, nil
}

// Allocate returns the deterministic fake IPv4 address for normalized host.
func (a *Allocator) Allocate(host string) netip.Addr {
	host = config.NormalizeHost(host)
	h := fnv.New32a()
	// hash.Hash.Write never returns an error.
	if _, err := h.Write([]byte(host)); err != nil {
		return uint32ToIPv4(a.first)
	}
	return uint32ToIPv4(a.first + (h.Sum32() % a.count))
}

func uint32ToIPv4(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// Server serves fake-IP DNS over explicit-bind UDP and TCP sockets for a single link.
type Server struct {
	link           config.LinkConfig
	store          *config.Store
	eval           *policy.Evaluator
	audit          *audit.Writer
	allocator      *Allocator
	onQuery        func(principal, effect string)
	onConnRejected func(link string)
	onServeError   func(error)

	shuttingDown atomic.Bool
	udpConn      net.PacketConn
	tcpLn        net.Listener
	udpSrv       *mdns.Server
	tcpSrv       *mdns.Server
	wg           sync.WaitGroup
}

// ServerOptions configures a per-link DNS Server.
type ServerOptions struct {
	Link      config.LinkConfig
	Store     *config.Store
	Evaluator *policy.Evaluator
	Audit     *audit.Writer
	Allocator *Allocator
	OnQuery   func(principal, effect string)
	// OnConnRejected is called for each TCP connection over http.max_conns_per_link.
	OnConnRejected func(link string)
	OnServeError   func(error)
}

// NewServer creates a per-link fake-IP DNS Server bound to link.ParsedGatewayIP:link.DNSPort.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Store == nil || opts.Evaluator == nil || opts.Audit == nil || opts.Allocator == nil || opts.OnServeError == nil {
		return nil, errors.New("dns: store, evaluator, audit, allocator, and onServeError are required")
	}
	if !opts.Link.ParsedGatewayIP.IsValid() || opts.Link.ParsedGatewayIP.IsUnspecified() {
		return nil, errors.New("dns: explicit non-wildcard gateway_ip is required")
	}
	return &Server{
		link:           opts.Link,
		onConnRejected: opts.OnConnRejected,
		store:          opts.Store,
		eval:           opts.Evaluator,
		audit:          opts.Audit,
		allocator:      opts.Allocator,
		onQuery:        opts.OnQuery,
		onServeError:   opts.OnServeError,
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
	// TCP queries get their own per-link budget, so held DNS connections cannot
	// exhaust the daemon and do not consume the proxy's slots.
	limit := connlimit.New(s.store.Current().Config.HTTP.MaxConnsPerLink, func() {
		if s.onConnRejected != nil {
			s.onConnRejected(s.link.Name)
		}
	})

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
		MsgInvalidFunc:    func(_ []byte, _ error) { s.auditMalformed("udp") },
		NotifyStartedFunc: func() { close(udpReady) },
	}
	s.tcpSrv = &mdns.Server{
		Listener:          limit.Listener(ln),
		Handler:           handler,
		MsgAcceptFunc:     acceptAll,
		MsgInvalidFunc:    func(_ []byte, _ error) { s.auditMalformed("tcp") },
		NotifyStartedFunc: func() { close(tcpReady) },
	}

	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		serveDNSUntilClosed(s.udpSrv, &s.shuttingDown, func(err error) {
			if s.onServeError != nil {
				s.onServeError(fmt.Errorf("dns(%s/udp): %w", s.link.Name, err))
			}
		})
	}()
	go func() {
		defer s.wg.Done()
		serveDNSUntilClosed(s.tcpSrv, &s.shuttingDown, func(err error) {
			if s.onServeError != nil {
				s.onServeError(fmt.Errorf("dns(%s/tcp): %w", s.link.Name, err))
			}
		})
	}()

	<-udpReady
	<-tcpReady
	return nil
}

// Shutdown gracefully stops both UDP and TCP DNS servers and waits for goroutines to exit.
func (s *Server) Shutdown(ctx context.Context) error {
	s.shuttingDown.Store(true)
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

func (s *Server) newEvent(srcIP, proto, host, qtype string) audit.Event {
	return audit.Event{
		Kind:      audit.KindDNS,
		Principal: s.link.Principal,
		Link:      s.link.Name,
		SrcIP:     srcIP,
		Protocol:  proto,
		Host:      host,
		Port:      53,
		QType:     qtype,
	}
}

func firstQuestionMeta(r *mdns.Msg) (qname, qtypeName string) {
	if len(r.Question) == 0 {
		return "", ""
	}
	q := r.Question[0]
	qname = config.NormalizeHost(q.Name)
	qtypeName = mdns.TypeToString[q.Qtype]
	if qtypeName == "" {
		qtypeName = fmt.Sprintf("TYPE%d", q.Qtype)
	}
	return qname, qtypeName
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

	qname, qtypeName := firstQuestionMeta(r)
	ev := s.newEvent(srcIP, proto, qname, qtypeName)

	if r.Response {
		ev.Effect = audit.EffectDeny
		ev.Reason = "response-packet-ignored"
		if err := s.audit.WriteSync(ev); err != nil {
			if s.onQuery != nil {
				s.onQuery(s.link.Principal, "audit_error")
			}
			return
		}
		if s.onQuery != nil {
			s.onQuery(s.link.Principal, string(ev.Effect))
		}
		return
	}

	if r.Opcode != mdns.OpcodeQuery {
		ev.Effect = audit.EffectDeny
		ev.Reason = "opcode-not-implemented"
		s.auditAndReply(w, resp, mdns.RcodeNotImplemented, ev)
		return
	}

	if len(r.Question) != 1 {
		ev.QType = ""
		ev.Effect = audit.EffectDeny
		ev.Reason = "invalid-question-count"
		s.auditAndReply(w, resp, mdns.RcodeRefused, ev)
		return
	}

	q := r.Question[0]
	if q.Qclass != mdns.ClassINET {
		ev.Effect = audit.EffectDeny
		ev.Reason = "qclass-refused"
		s.auditAndReply(w, resp, mdns.RcodeRefused, ev)
		return
	}

	dec := s.eval.DecideDNS(s.link.Principal, qname)
	ev.Effect = audit.EffectDeny
	ev.Reason = dec.Reason
	ev.RuleID = dec.RuleID
	ev.GrantID = dec.GrantID
	rcode := mdns.RcodeRefused

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
			ev.Effect = audit.EffectAllow
			ev.Address = fakeIP.String()
		case mdns.TypeAAAA, mdns.TypeHTTPS, mdns.TypeSVCB:
			// Empty NOERROR (NODATA): keeps ECH configs out and avoids stub-resolver refusal errors.
			rcode = mdns.RcodeSuccess
			ev.Effect = audit.EffectAllow
			ev.Reason = "nodata"
		default:
			// Refuse TXT, MX, NS, SRV, CNAME, etc. even inside allowlisted zones.
			rcode = mdns.RcodeRefused
			ev.Effect = audit.EffectDeny
			ev.Reason = "qtype-refused"
		}
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

func (s *Server) auditMalformed(proto string) {
	ev := s.newEvent("", proto, "", "")
	ev.Effect = audit.EffectDeny
	ev.Reason = "malformed"
	if err := s.audit.WriteSync(ev); err != nil {
		if s.onQuery != nil {
			s.onQuery(s.link.Principal, "audit_error")
		}
		return
	}
	if s.onQuery != nil {
		s.onQuery(s.link.Principal, string(audit.EffectDeny))
	}
}

func serveDNSUntilClosed(srv *mdns.Server, shuttingDown *atomic.Bool, onErr func(error)) {
	// Shutdown closes the underlying socket, causing ActivateAndServe to exit.
	if err := srv.ActivateAndServe(); err != nil && !shuttingDown.Load() {
		if onErr != nil {
			onErr(err)
		}
	}
}

func (s *Server) writeResponse(w mdns.ResponseWriter, msg *mdns.Msg) {
	if err := w.WriteMsg(msg); err != nil {
		return
	}
}
