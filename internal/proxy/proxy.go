// SPDX-License-Identifier: AGPL-3.0-or-later

// Package proxy implements gateway's per-(link, dstPort) TLS MITM and HTTP/1.1,
// HTTP/2, SSE, and opted-in WebSocket egress proxy with secret substitution,
// identity response redaction, and live open-flow teardown.
package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"path"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/ca"
	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/connlimit"
	"github.com/manufactory-project/gateway/internal/netguard"
	"github.com/manufactory-project/gateway/internal/policy"
	"github.com/manufactory-project/gateway/internal/secret"
)

const statusClientClosedRequest = 499

// Options configures a per-link MITM proxy Server.
type Options struct {
	Link           config.LinkConfig
	Store          *config.Store
	Evaluator      *policy.Evaluator
	Audit          *audit.Writer
	Leaves         *ca.LeafCache
	Dialer         *netguard.Dialer
	// DialContext is a test hook: tests redirect ports 443 and 80 to local mock
	// upstreams, still through netguard.Dialer. Production leaves it nil.
	DialContext    func(ctx context.Context, network, addr string) (net.Conn, error)
	Flows          *FlowRegistry
	OnRequest      func(principal, effect string, status int, reason string)
	OnConnRejected func(link string)
	OnServeError   func(error)
}

// Server owns the explicit-bind HTTPS (:443 semantics) and HTTP (:80 semantics)
// listeners for a single sandbox link.
type Server struct {
	link           config.LinkConfig
	store          *config.Store
	eval           *policy.Evaluator
	audit          *audit.Writer
	leaves         *ca.LeafCache
	dialContext    func(ctx context.Context, network, addr string) (net.Conn, error)
	flows          *FlowRegistry
	onRequest      func(principal, effect string, status int, reason string)
	onConnRejected func(link string)
	onServeError   func(error)

	transport *http.Transport

	httpsLn  net.Listener
	httpLn   net.Listener
	httpsSrv *http.Server
	httpSrv  *http.Server
	wg       sync.WaitGroup
}

// NewServer constructs a per-link Server without binding sockets yet.
func NewServer(opts Options) (*Server, error) {
	if opts.Store == nil || opts.Evaluator == nil || opts.Audit == nil || opts.Leaves == nil || opts.Flows == nil || opts.OnServeError == nil {
		return nil, errors.New("proxy: store, evaluator, audit, leaves, flows, and onServeError are required")
	}
	if !opts.Link.ParsedGatewayIP.IsValid() || opts.Link.ParsedGatewayIP.IsUnspecified() {
		return nil, errors.New("proxy: explicit non-wildcard gateway_ip is required")
	}
	dialFn := opts.DialContext
	if dialFn == nil {
		if opts.Dialer == nil {
			return nil, errors.New("proxy: dialer or dialContext is required")
		}
		dialFn = opts.Dialer.DialContext
	}

	hCfg := opts.Store.Current().Config.HTTP
	tr := &http.Transport{
		DialContext: dialFn,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, // uses system roots; never InsecureSkipVerify
		},
		ForceAttemptHTTP2:      true,
		DisableCompression:     true,
		MaxIdleConns:           100,
		IdleConnTimeout:        60 * time.Second,
		TLSHandshakeTimeout:    15 * time.Second,
		ResponseHeaderTimeout:  hCfg.ParsedUpstreamResponseHeaderTimeout,
		ExpectContinueTimeout:  1 * time.Second,
		MaxResponseHeaderBytes: int64(hCfg.MaxHeaderBytes),
	}

	s := &Server{
		link:           opts.Link,
		store:          opts.Store,
		eval:           opts.Evaluator,
		audit:          opts.Audit,
		leaves:         opts.Leaves,
		dialContext:    dialFn,
		flows:          opts.Flows,
		onRequest:      opts.OnRequest,
		onConnRejected: opts.OnConnRejected,
		onServeError:   opts.OnServeError,
		transport:      tr,
	}
	return s, nil
}

// CloseIdleConnections closes any idle pooled upstream connections held by this server.
func (s *Server) CloseIdleConnections() {
	s.transport.CloseIdleConnections()
}

// Start binds explicit HTTPS and HTTP TCP listeners on link.ParsedGatewayIP.
func (s *Server) Start() error {
	gw := s.link.ParsedGatewayIP.String()
	httpsAddr := net.JoinHostPort(gw, strconv.Itoa(int(s.link.HTTPSPort)))
	httpAddr := net.JoinHostPort(gw, strconv.Itoa(int(s.link.HTTPPort)))

	rawHTTPSLn, err := net.Listen("tcp4", httpsAddr)
	if err != nil {
		return fmt.Errorf("proxy: listen https %s: %w", httpsAddr, err)
	}
	httpLn, err := net.Listen("tcp4", httpAddr)
	if err != nil {
		closeErr := rawHTTPSLn.Close()
		return errors.Join(fmt.Errorf("proxy: listen http %s: %w", httpAddr, err), closeErr)
	}

	hCfg := s.store.Current().Config.HTTP
	limit := connlimit.New(hCfg.MaxConnsPerLink, func() {
		if s.onConnRejected != nil {
			s.onConnRejected(s.link.Name)
		}
	})

	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1"},
		GetCertificate: s.getCertificate,
	}
	httpsLn := tls.NewListener(limit.Listener(rawHTTPSLn), tlsCfg)
	cappedHTTPLn := limit.Listener(httpLn)

	var httpsProtos http.Protocols
	httpsProtos.SetHTTP1(true)
	httpsProtos.SetHTTP2(true)
	httpsProtos.SetUnencryptedHTTP2(false)

	var httpProtos http.Protocols
	httpProtos.SetHTTP1(true)
	httpProtos.SetHTTP2(false)
	httpProtos.SetUnencryptedHTTP2(false)

	connCtx := func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, guestConnCtxKey{}, c)
	}

	s.httpsSrv = &http.Server{
		Handler:                      http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serveHTTP(w, r, 443) }),
		ConnContext:                  connCtx,
		MaxHeaderBytes:               hCfg.MaxHeaderBytes,
		ReadHeaderTimeout:            10 * time.Second,
		IdleTimeout:                  90 * time.Second,
		Protocols:                    &httpsProtos,
		DisableGeneralOptionsHandler: true,
	}
	s.httpSrv = &http.Server{
		Handler:                      http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serveHTTP(w, r, 80) }),
		ConnContext:                  connCtx,
		MaxHeaderBytes:               hCfg.MaxHeaderBytes,
		ReadHeaderTimeout:            10 * time.Second,
		IdleTimeout:                  90 * time.Second,
		Protocols:                    &httpProtos,
		DisableGeneralOptionsHandler: true,
	}

	s.httpsLn = httpsLn
	s.httpLn = cappedHTTPLn

	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		serveUntilClosed(s.httpsSrv, httpsLn, func(err error) {
			if s.onServeError != nil {
				s.onServeError(fmt.Errorf("proxy(%s/https): %w", s.link.Name, err))
			}
		})
	}()
	go func() {
		defer s.wg.Done()
		serveUntilClosed(s.httpSrv, cappedHTTPLn, func(err error) {
			if s.onServeError != nil {
				s.onServeError(fmt.Errorf("proxy(%s/http): %w", s.link.Name, err))
			}
		})
	}()
	return nil
}

func serveUntilClosed(srv *http.Server, ln net.Listener, onErr func(error)) {
	// Shutdown closes the listener and causes Serve to return http.ErrServerClosed.
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		if onErr != nil {
			onErr(err)
		}
	}
}

func auditBestEffort(w *audit.Writer, ev audit.Event) {
	// WriteSync already notifies OnWriteError on sink failure.
	if err := w.WriteSync(ev); err != nil {
		return
	}
}

// Shutdown drains listeners, tears down remaining link flows, closes idle upstream connections, and waits for goroutines.
func (s *Server) Shutdown(ctx context.Context) error {
	s.flows.drainLink(s.link.Name)

	var errs error
	if s.httpsSrv != nil {
		if err := s.httpsSrv.Shutdown(ctx); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	if s.httpSrv != nil {
		if err := s.httpSrv.Shutdown(ctx); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	s.transport.CloseIdleConnections()
	s.wg.Wait()
	return errs
}

func (s *Server) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := config.NormalizeHost(hello.ServerName)
	srcIP := ""
	if hello.Conn != nil && hello.Conn.RemoteAddr() != nil {
		if h, _, err := net.SplitHostPort(hello.Conn.RemoteAddr().String()); err == nil {
			srcIP = h
		}
	}

	if sni == "" {
		s.auditDeniedSNI(srcIP, "", "missing-sni", "")
		return nil, errors.New("proxy: missing TLS SNI")
	}
	if _, err := netip.ParseAddr(sni); err == nil {
		s.auditDeniedSNI(srcIP, sni, "ip-literal-sni", "")
		return nil, errors.New("proxy: IP literal SNI denied")
	}

	dec := s.eval.DecideHost(s.link.Principal, sni, 443)
	if !dec.Allow {
		s.auditDeniedSNI(srcIP, sni, dec.Reason, dec.RuleID)
		return nil, fmt.Errorf("proxy: SNI %q denied by policy", sni)
	}

	// Only allowed SNIs ever reach LeafCache (never cache leaves for denied SNIs).
	return s.leaves.Leaf(sni)
}

func (s *Server) auditDeniedSNI(srcIP, sni, reason, ruleID string) {
	if s.onRequest != nil {
		s.onRequest(s.link.Principal, string(audit.EffectDeny), 0, reason)
	}
	ev := audit.Event{
		Kind:      audit.KindRequest,
		Principal: s.link.Principal,
		Link:      s.link.Name,
		SrcIP:     srcIP,
		Protocol:  "tls",
		Host:      sni,
		Port:      443,
		Effect:    audit.EffectDeny,
		Reason:    reason,
		RuleID:    ruleID,
	}
	auditBestEffort(s.audit, ev)
}

type reqContext struct {
	srv           *Server
	r             *http.Request
	srcIP         string
	proto         string
	host          string
	dstPort       uint16
	dec           policy.Decision
	admitSnap     *config.Snapshot
	admitGrantGen uint64
	wantWS        bool
	maxBody       int64
	flowID        string
	secretNames   []string
	redactor      *secret.Redactor // non-nil exactly on bound hosts
	outHeaders    http.Header
}

func (rc *reqContext) baseEvent(kind audit.Kind) audit.Event {
	return audit.Event{
		Kind:      kind,
		Principal: rc.srv.link.Principal,
		Link:      rc.srv.link.Name,
		SrcIP:     rc.srcIP,
		Protocol:  rc.proto,
		Host:      rc.host,
		Port:      int(rc.dstPort),
		Method:    rc.r.Method,
		Path:      rc.r.URL.EscapedPath(),
		HasQuery:  rc.r.URL.RawQuery != "",
		Reason:    rc.dec.Reason,
		RuleID:    rc.dec.RuleID,
		GrantID:   rc.dec.GrantID,
		FlowID:    rc.flowID,
		Secrets:   rc.secretNames,
	}
}

func (rc *reqContext) deny(w http.ResponseWriter, status int, reason string) {
	ev := rc.baseEvent(audit.KindRequest)
	ev.Status = status
	ev.Effect = audit.EffectDeny
	ev.Reason = reason
	if err := rc.srv.audit.WriteSync(ev); err != nil {
		if rc.srv.onRequest != nil {
			rc.srv.onRequest(rc.srv.link.Principal, string(audit.EffectDeny), http.StatusServiceUnavailable, "audit-unavailable")
		}
		http.Error(w, "audit sink unavailable", http.StatusServiceUnavailable)
		return
	}
	if rc.srv.onRequest != nil {
		rc.srv.onRequest(rc.srv.link.Principal, string(audit.EffectDeny), status, reason)
	}
	http.Error(w, "egress denied: "+reason, status)
}

func (rc *reqContext) auditAdmitted() error {
	ev := rc.baseEvent(audit.KindRequestAdmitted)
	ev.Effect = audit.EffectAllow
	return rc.srv.audit.WriteSync(ev)
}

// upstreamErrorText returns what may be audited about a failed upstream exchange.
// Failures before the request is sent are recorded verbatim. Later errors can
// quote upstream bytes, including a reflected secret or header value, so they are
// reduced to a fixed class chosen by type, never by text.
func upstreamErrorText(err error) string {
	var (
		opErr     *net.OpError
		dnsErr    *net.DNSError
		certErr   *tls.CertificateVerificationError
		netErr    net.Error
		alertErr  tls.AlertError
		recordErr tls.RecordHeaderError
		protoErr  textproto.ProtocolError
	)
	switch {
	case errors.As(err, &opErr) && opErr.Op == "dial", errors.As(err, &dnsErr), errors.As(err, &certErr),
		errors.Is(err, netguard.ErrBlockedAddress), errors.Is(err, netguard.ErrIPLiteralHost):
		return err.Error()
	case errors.As(err, &netErr) && netErr.Timeout():
		return "upstream-error: timeout"
	case errors.As(err, &alertErr), errors.As(err, &recordErr):
		return "upstream-error: tls"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, syscall.ECONNRESET):
		return "upstream-error: connection-closed"
	case errors.As(err, &protoErr):
		return "upstream-error: malformed-response"
	default:
		return "upstream-error"
	}
}

func completionMetricReason(admitReason, errText string) string {
	if errText == "" {
		if admitReason != "" {
			return admitReason
		}
		return "ok"
	}
	if strings.HasPrefix(errText, "ws-egress-cap-exceeded:") {
		return "ws-egress-cap-exceeded"
	}
	switch errText {
	case TeardownRevoked, TeardownGrantExpired, TeardownReload, TeardownClientCanceled,
		"compressed-response-on-bound-host", "partial-response-on-bound-host",
		"unexpected-101", "unexpected-101-non-websocket":
		return errText
	default:
		return "upstream-error"
	}
}

func (rc *reqContext) auditCompleted(status int, bytesOut, bytesIn int64, errText string) {
	if rc.srv.onRequest != nil {
		rc.srv.onRequest(rc.srv.link.Principal, string(audit.EffectAllow), status, completionMetricReason(rc.dec.Reason, errText))
	}
	kind := audit.KindRequest
	if rc.wantWS {
		kind = audit.KindWebSocket
	}
	ev := rc.baseEvent(kind)
	ev.Status = status
	ev.Effect = audit.EffectAllow
	ev.BytesOut = bytesOut
	ev.BytesIn = bytesIn
	ev.Error = errText
	auditBestEffort(rc.srv.audit, ev)
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request, dstPort uint16) {
	rc, ok := s.admit(w, r, dstPort)
	if !ok {
		return
	}
	if !s.prepare(w, rc) {
		return
	}
	s.relay(w, rc)
}

func (s *Server) admit(w http.ResponseWriter, r *http.Request, dstPort uint16) (*reqContext, bool) {
	srcIP := ""
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		srcIP = h
	}
	rc := &reqContext{
		srv:     s,
		r:       r,
		srcIP:   srcIP,
		proto:   r.Proto,
		host:    r.Host,
		dstPort: dstPort,
	}

	// 1. Reject CONNECT, non-origin-form targets, and H2 explicit Host header.
	if r.Method == http.MethodConnect {
		rc.deny(w, http.StatusForbidden, "connect-forbidden")
		return nil, false
	}
	if errReason := validateOriginForm(r); errReason != "" {
		rc.deny(w, http.StatusForbidden, errReason)
		return nil, false
	}
	if r.ProtoMajor == 2 && len(r.Header["Host"]) > 0 {
		rc.deny(w, http.StatusForbidden, "h2-host-header")
		return nil, false
	}

	// 2. Validate Host/:authority, port match against dstPort, and SNI == Host on HTTPS.
	host, errReason := validateHostAndSNI(r, dstPort)
	if errReason != "" {
		rc.deny(w, http.StatusForbidden, errReason)
		return nil, false
	}
	rc.host = host

	// 3. Classify Upgrade headers (reject h2c and arbitrary upgrades).
	wantWS, upgradeErr := classifyUpgrade(r)
	if upgradeErr != "" {
		rc.deny(w, http.StatusForbidden, upgradeErr)
		return nil, false
	}
	rc.wantWS = wantWS

	// 4. Evaluate policy live per HTTP request (never snapshotted at SYN).
	rc.admitSnap, rc.admitGrantGen = s.store.StateToken()
	rc.dec = s.eval.DecideRequest(s.link.Principal, host, dstPort, r.Method, r.URL.Path)
	if !rc.dec.Allow {
		rc.deny(w, http.StatusForbidden, rc.dec.Reason)
		return nil, false
	}
	if wantWS {
		if !rc.dec.AllowWebSocket {
			rc.deny(w, http.StatusForbidden, "websocket-not-allowed")
			return nil, false
		}
		if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
			rc.deny(w, http.StatusBadRequest, "websocket-upgrade-with-body")
			return nil, false
		}
		rc.proto = "websocket"
	}

	// 5. Reject declared request bodies exceeding the streaming body cap before dialing.
	rc.maxBody = s.store.Current().Config.HTTP.MaxRequestBodyBytes
	if r.ContentLength > rc.maxBody {
		rc.deny(w, http.StatusRequestEntityTooLarge, "body-too-large")
		return nil, false
	}
	return rc, true
}

func (s *Server) prepare(w http.ResponseWriter, rc *reqContext) bool {
	rc.outHeaders = make(http.Header)
	copyEndToEndHeaders(rc.outHeaders, rc.r.Header, rc.wantWS)
	if rc.wantWS {
		secret.SweepHeaders(rc.outHeaders)
		return true
	}

	// Every secret of a bound host is resolved before dispatch: a request whose
	// response could not be scrubbed must never reach the upstream.
	pairs, err := secret.ResolveHostPairs(rc.dec.HostBindings)
	if err != nil {
		var resErr *secret.ResolveError
		if errors.As(err, &resErr) {
			rc.secretNames = []string{resErr.Name}
		}
		rc.deny(w, http.StatusForbidden, "secret-unresolved")
		return false
	}
	rc.secretNames = secret.ApplyRequest(rc.outHeaders, rc.dec.MatchedBindings, pairs, rc.dstPort)
	if rc.dec.HasBindings {
		rc.redactor = secret.NewRedactor(pairs)
		// A bound host must answer whole and unencoded: ranges and compression
		// would both let a secret past the scrubber.
		rc.outHeaders.Del("Range")
		rc.outHeaders.Del("If-Range")
		rc.outHeaders.Set("Accept-Encoding", "identity")
	}
	return true
}

func (s *Server) relay(w http.ResponseWriter, rc *reqContext) {
	parentCtx := rc.r.Context()
	reqCtx, reqCancel := context.WithCancel(parentCtx)
	defer reqCancel()

	af := s.flows.register(FlowInfo{
		Principal: s.link.Principal,
		Link:      s.link.Name,
		Host:      rc.host,
		Port:      rc.dstPort,
		Method:    rc.r.Method,
		Path:      rc.r.URL.Path,
		RuleID:    rc.dec.RuleID,
		GrantID:   rc.dec.GrantID,
		Protocol:  rc.proto,
	}, reqCancel, guestConnFromContext(parentCtx))
	defer s.flows.unregister(af.info.ID)
	rc.flowID = af.info.ID

	// Re-verify admission after flow registration if config or grants changed since admit().
	if !s.recheckAdmissionAfterRegister(w, rc) {
		return
	}

	// Fail-closed admission audit BEFORE dialing upstream.
	if err := rc.auditAdmitted(); err != nil {
		if rc.srv.onRequest != nil {
			rc.srv.onRequest(rc.srv.link.Principal, string(audit.EffectDeny), http.StatusServiceUnavailable, "audit-unavailable")
		}
		http.Error(w, "audit sink unavailable", http.StatusServiceUnavailable)
		return
	}

	if rc.wantWS {
		rc.r = rc.r.WithContext(reqCtx)
		s.serveWebSocket(w, rc, af)
		return
	}

	countingBody := &countingReadCloser{rc: http.MaxBytesReader(w, rc.r.Body, rc.maxBody)}
	// A nil body keeps a bodiless request bodiless; a non-nil reader with length 0
	// would be sent upstream as a body of unknown length.
	var body io.Reader
	if rc.r.ContentLength != 0 {
		body = countingBody
	}
	outReq, err := buildOutboundRequest(reqCtx, rc, body)
	if err != nil {
		rc.deny(w, http.StatusBadGateway, "build-request-failed")
		return
	}

	// RoundTrip directly (never follow 3xx redirects).
	resp, err := s.transport.RoundTrip(outReq)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			rc.deny(w, http.StatusRequestEntityTooLarge, "body-too-large")
			return
		}
		if reason := af.reason(); reason != "" {
			rc.auditCompleted(http.StatusBadGateway, countingBody.n.Load(), 0, reason)
			panic(http.ErrAbortHandler)
		}
		if parentCtx.Err() != nil {
			rc.auditCompleted(statusClientClosedRequest, countingBody.n.Load(), 0, TeardownClientCanceled)
			panic(http.ErrAbortHandler)
		}
		rc.auditCompleted(http.StatusBadGateway, countingBody.n.Load(), 0, upstreamErrorText(err))
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer closeQuietly(resp.Body)

	if resp.StatusCode == http.StatusSwitchingProtocols {
		rc.auditCompleted(http.StatusBadGateway, countingBody.n.Load(), 0, "unexpected-101")
		http.Error(w, "unexpected protocol upgrade", http.StatusBadGateway)
		return
	}

	if reason := refuseBoundResponse(rc, resp); reason != "" {
		rc.auditCompleted(http.StatusBadGateway, countingBody.n.Load(), 0, reason)
		http.Error(w, "bound host response refused: "+reason, http.StatusBadGateway)
		return
	}

	bytesIn, copyErr := writeProxiedResponse(w, resp, rc.redactor)
	errText := ""
	if reason := af.reason(); reason != "" {
		errText = reason
	} else if copyErr != nil {
		if parentCtx.Err() != nil {
			errText = TeardownClientCanceled
		} else {
			errText = upstreamErrorText(copyErr)
		}
	}
	rc.auditCompleted(resp.StatusCode, countingBody.n.Load(), bytesIn, errText)
	if copyErr != nil {
		panic(http.ErrAbortHandler)
	}
}

func (s *Server) recheckAdmissionAfterRegister(w http.ResponseWriter, rc *reqContext) bool {
	curSnap, curGrantGen := s.store.StateToken()
	if curSnap == rc.admitSnap && curGrantGen == rc.admitGrantGen {
		return true
	}
	reDec := s.eval.DecideRequest(s.link.Principal, rc.host, rc.dstPort, rc.r.Method, rc.r.URL.Path)
	if !reflect.DeepEqual(rc.dec, reDec) {
		rc.dec = reDec
		rc.deny(w, http.StatusForbidden, "admission-changed")
		return false
	}
	return true
}

func buildOutboundRequest(ctx context.Context, rc *reqContext, body io.Reader) (*http.Request, error) {
	scheme := "https"
	if rc.dstPort == 80 {
		scheme = "http"
	}
	outURL := *rc.r.URL
	outURL.Scheme = scheme
	outURL.Host = net.JoinHostPort(rc.host, strconv.Itoa(int(rc.dstPort)))

	outReq, err := http.NewRequestWithContext(ctx, rc.r.Method, outURL.String(), body)
	if err != nil {
		return nil, err
	}
	outReq.Host = rc.host
	outReq.ContentLength = rc.r.ContentLength
	outReq.Header = rc.outHeaders
	return outReq, nil
}

// refuseBoundResponse returns why a bound host's response cannot be scrubbed,
// or "" when it can be forwarded.
func refuseBoundResponse(rc *reqContext, resp *http.Response) string {
	switch {
	case rc.redactor == nil:
		return ""
	case !isIdentityContentEncoding(resp.Header.Values("Content-Encoding")):
		return "compressed-response-on-bound-host"
	case resp.StatusCode == http.StatusPartialContent:
		return "partial-response-on-bound-host"
	default:
		return ""
	}
}

// writeProxiedResponse forwards resp, scrubbing it when redactor is non-nil.
func writeProxiedResponse(w http.ResponseWriter, resp *http.Response, redactor *secret.Redactor) (int64, error) {
	copyEndToEndHeaders(w.Header(), resp.Header, false)
	if redactor != nil {
		redactor.ScrubHeader(w.Header())
		// Always strip Content-Length on bound hosts before WriteHeader.
		w.Header().Del("Content-Length")
	}
	for k := range resp.Trailer {
		w.Header().Add("Trailer", k)
	}
	w.WriteHeader(resp.StatusCode)
	// A streaming upstream may send headers long before its first body byte. A
	// response of known length is not flushed here, so that an empty one still
	// completes only after its completion audit is written.
	if resp.ContentLength < 0 {
		if err := flush(w); err != nil {
			return 0, err
		}
	}

	var (
		bytesIn int64
		copyErr error
	)
	if redactor.Active() {
		bytesIn, copyErr = copyStreamingRedacted(w, resp.Body, redactor)
		redactor.ScrubHeader(resp.Trailer)
	} else {
		bytesIn, copyErr = copyStreaming(w, resp.Body)
	}

	for k, vals := range resp.Trailer {
		tk := http.TrailerPrefix + k
		for _, v := range vals {
			w.Header().Add(tk, v)
		}
	}
	return bytesIn, copyErr
}

func isIdentityContentEncoding(vals []string) bool {
	for _, v := range vals {
		for _, tok := range strings.Split(v, ",") {
			t := strings.TrimSpace(tok)
			if t == "" {
				continue
			}
			if !strings.EqualFold(t, "identity") {
				return false
			}
		}
	}
	return true
}

func validateOriginForm(r *http.Request) string {
	if r.RequestURI == "*" {
		return "asterisk-target-forbidden"
	}
	if r.URL.Scheme != "" || r.URL.Host != "" {
		return "absolute-uri-forbidden"
	}
	if strings.HasPrefix(r.RequestURI, "http://") || strings.HasPrefix(r.RequestURI, "https://") {
		return "absolute-uri-forbidden"
	}
	if !strings.HasPrefix(r.URL.Path, "/") {
		return "non-origin-form-target"
	}
	if r.URL.RawPath != "" {
		lowerRaw := strings.ToLower(r.URL.RawPath)
		if strings.Contains(lowerRaw, "%2f") || strings.Contains(lowerRaw, "%5c") {
			return "escaped-path-separator"
		}
	}
	if strings.Contains(r.URL.Path, "\\") {
		return "backslash-in-path"
	}
	for _, seg := range strings.Split(r.URL.Path, "/") {
		if seg == ".." {
			return "path-traversal"
		}
	}
	if !isCanonicalPath(r.URL.Path) {
		return "non-canonical-path"
	}
	return ""
}

func isCanonicalPath(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	cleaned := path.Clean(p)
	if cleaned == p {
		return true
	}
	// Allow a single trailing slash on a non-root canonical path (e.g. "/a/"),
	// but reject "//", "/./", "/a/.", "/a//", "/v1/./admin", "/v1//admin".
	if cleaned != "/" && cleaned+"/" == p {
		return true
	}
	return false
}

func validateHostAndSNI(r *http.Request, dstPort uint16) (string, string) {
	if strings.TrimSpace(r.Host) == "" {
		return "", "missing-host"
	}
	rawHost := strings.TrimSpace(r.Host)
	hostPart := rawHost
	if strings.Contains(rawHost, ":") {
		h, portStr, err := net.SplitHostPort(rawHost)
		if err != nil {
			return "", "invalid-host"
		}
		p, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || uint16(p) != dstPort {
			return "", "host-port-mismatch"
		}
		hostPart = h
	}
	host := config.NormalizeHost(hostPart)
	if host == "" {
		return "", "invalid-host"
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", "ip-literal-host"
	}
	if dstPort == 443 {
		if r.TLS == nil {
			return "", "missing-tls"
		}
		sni := config.NormalizeHost(r.TLS.ServerName)
		if sni == "" || sni != host {
			return "", "sni-host-mismatch"
		}
	}
	return host, ""
}

func classifyUpgrade(r *http.Request) (wantWS bool, errReason string) {
	upgrades := r.Header.Values("Upgrade")
	if len(upgrades) == 0 {
		return false, ""
	}
	var tokens []string
	for _, v := range upgrades {
		for _, part := range strings.Split(v, ",") {
			tok := strings.ToLower(strings.TrimSpace(part))
			if tok != "" {
				tokens = append(tokens, tok)
			}
		}
	}
	if len(tokens) == 0 {
		return false, ""
	}
	if len(tokens) == 1 && tokens[0] == "websocket" {
		if r.Method != http.MethodGet || !headerContainsToken(r.Header, "Connection", "upgrade") {
			return false, "invalid-websocket-upgrade"
		}
		return true, ""
	}
	return false, "upgrade-forbidden"
}

func headerContainsToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

func copyEndToEndHeaders(dst, src http.Header, keepWS bool) {
	connHeaders := make(map[string]bool)
	for _, v := range src.Values("Connection") {
		for _, field := range strings.Split(v, ",") {
			f := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(field))
			if f != "" {
				connHeaders[f] = true
			}
		}
	}

	for k, vals := range src {
		canon := textproto.CanonicalMIMEHeaderKey(k)
		if canon == "Te" {
			for _, v := range vals {
				if strings.EqualFold(strings.TrimSpace(v), "trailers") {
					dst.Add("TE", "trailers")
				}
			}
			continue
		}
		if hopByHopHeaders[canon] || connHeaders[canon] {
			if keepWS && (canon == "Upgrade" || canon == "Connection" || strings.HasPrefix(canon, "Sec-Websocket-")) {
				for _, v := range vals {
					dst.Add(canon, v)
				}
			}
			continue
		}
		for _, v := range vals {
			dst.Add(canon, v)
		}
	}
}

// flush pushes buffered response bytes to the guest.
func flush(w http.ResponseWriter) error {
	if err := http.NewResponseController(w).Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	return nil
}

func copyStreaming(w http.ResponseWriter, src io.Reader) (int64, error) {
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			written, writeErr := w.Write(buf[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if flushErr := flush(w); flushErr != nil {
				return total, flushErr
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, readErr
		}
	}
}

func copyStreamingRedacted(w http.ResponseWriter, src io.Reader, redactor *secret.Redactor) (int64, error) {
	sw := redactor.StreamWriter(w, func() error { return flush(w) })
	buf := make([]byte, 32<<10)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if _, writeErr := sw.Write(buf[:n]); writeErr != nil {
				return sw.Written(), writeErr
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				closeErr := sw.Close()
				return sw.Written(), closeErr
			}
			return sw.Written(), readErr
		}
	}
}

type countingReadCloser struct {
	rc io.ReadCloser
	n  atomic.Int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func (c *countingReadCloser) Close() error {
	return c.rc.Close()
}
