// Package proxy implements gatewayd's per-(link, dstPort) TLS MITM and HTTP/1.1,
// HTTP/2, SSE, and opted-in WebSocket egress proxy with secret substitution,
// identity response redaction, and live open-flow teardown (NOW.md:47-64).
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/ca"
	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/netguard"
	"github.com/manufactory-project/gateway/internal/policy"
	"github.com/manufactory-project/gateway/internal/secret"
)

// Options configures a per-link MITM proxy Server.
type Options struct {
	Link          config.LinkConfig
	Store         *config.Store
	Evaluator     *policy.Evaluator
	Audit         *audit.Writer
	Leaves        *ca.LeafCache
	Dialer        *netguard.Dialer
	DialContext   func(ctx context.Context, network, addr string) (net.Conn, error)
	UpstreamRoots *x509.CertPool
	Flows         *FlowRegistry
	OnRequest     func(principal, effect string, status int)
}

// Server owns the explicit-bind HTTPS (:443 semantics) and HTTP (:80 semantics)
// listeners for a single sandbox link.
type Server struct {
	link          config.LinkConfig
	store         *config.Store
	eval          *policy.Evaluator
	audit         *audit.Writer
	leaves        *ca.LeafCache
	dialContext   func(ctx context.Context, network, addr string) (net.Conn, error)
	upstreamRoots *x509.CertPool
	flows         *FlowRegistry
	onRequest     func(principal, effect string, status int)

	transport *http.Transport

	httpsLn  net.Listener
	httpLn   net.Listener
	httpsSrv *http.Server
	httpSrv  *http.Server
	wg       sync.WaitGroup
}

// NewServer constructs a per-link Server without binding sockets yet.
func NewServer(opts Options) (*Server, error) {
	if opts.Store == nil || opts.Evaluator == nil || opts.Audit == nil || opts.Leaves == nil {
		return nil, errors.New("proxy: store, evaluator, audit, and leaves are required")
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
	flows := opts.Flows
	if flows == nil {
		flows = NewFlowRegistry()
	}

	hCfg := opts.Store.Current().Config.HTTP
	tr := &http.Transport{
		DialContext: dialFn,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    opts.UpstreamRoots, // nil uses system roots; never InsecureSkipVerify
		},
		ForceAttemptHTTP2:      true,
		DisableCompression:     true,
		MaxIdleConns:           100,
		IdleConnTimeout:        60 * time.Second,
		TLSHandshakeTimeout:    15 * time.Second,
		ExpectContinueTimeout:  1 * time.Second,
		MaxResponseHeaderBytes: int64(hCfg.MaxHeaderBytes),
	}

	s := &Server{
		link:          opts.Link,
		store:         opts.Store,
		eval:          opts.Evaluator,
		audit:         opts.Audit,
		leaves:        opts.Leaves,
		dialContext:   dialFn,
		upstreamRoots: opts.UpstreamRoots,
		flows:         flows,
		onRequest:     opts.OnRequest,
		transport:     tr,
	}

	opts.Store.OnReload(s.onConfigReload)
	opts.Store.SetOnGrantExpired(func(grantID string) {
		s.flows.RevokeByGrant(grantID)
	})
	return s, nil
}

func (s *Server) onConfigReload(_, _ *config.Snapshot, wipedGrantIDs []string) {
	s.flows.RevokeWhere(func(info FlowInfo) bool {
		if info.Link != s.link.Name {
			return false
		}
		if info.GrantID != "" && slices.Contains(wipedGrantIDs, info.GrantID) {
			return true
		}
		dec := s.eval.DecideRequest(info.Principal, info.Host, info.Port, info.Method, info.Path)
		if !dec.Allow {
			return true
		}
		if info.Protocol == "websocket" && !dec.AllowWebSocket {
			return true
		}
		return false
	})
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

	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1"},
		GetCertificate: s.getCertificate,
	}
	httpsLn := tls.NewListener(rawHTTPSLn, tlsCfg)

	hCfg := s.store.Current().Config.HTTP

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
	s.httpLn = httpLn

	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		if err := s.httpsSrv.Serve(httpsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return
		}
	}()
	go func() {
		defer s.wg.Done()
		if err := s.httpSrv.Serve(httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return
		}
	}()
	return nil
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
	sni := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hello.ServerName)), ".")
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
	if err := s.audit.WriteSync(ev); err != nil {
		return
	}
	if s.onRequest != nil {
		s.onRequest(s.link.Principal, string(audit.EffectDeny), 0)
	}
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request, dstPort uint16) {
	srcIP := ""
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		srcIP = h
	}
	reqPath := r.URL.Path
	hasQuery := r.URL.RawQuery != ""

	deny := func(status int, reason, ruleID, host string, secretNames []string) {
		ev := audit.Event{
			Kind:      audit.KindRequest,
			Principal: s.link.Principal,
			Link:      s.link.Name,
			SrcIP:     srcIP,
			Protocol:  r.Proto,
			Host:      host,
			Port:      int(dstPort),
			Method:    r.Method,
			Path:      reqPath,
			HasQuery:  hasQuery,
			Status:    status,
			Effect:    audit.EffectDeny,
			Reason:    reason,
			RuleID:    ruleID,
			Secrets:   secretNames,
		}
		if err := s.audit.WriteSync(ev); err != nil {
			http.Error(w, "audit sink unavailable", http.StatusServiceUnavailable)
			return
		}
		if s.onRequest != nil {
			s.onRequest(s.link.Principal, string(audit.EffectDeny), status)
		}
		http.Error(w, "egress denied: "+reason, status)
	}

	// 1. Reject CONNECT unconditionally.
	if r.Method == http.MethodConnect {
		deny(http.StatusForbidden, "connect-forbidden", "", r.Host, nil)
		return
	}

	// 2. Reject non-origin-form targets (*, absolute-URI, relative path, path traversal, escaped slashes).
	if errReason := validateOriginForm(r); errReason != "" {
		deny(http.StatusForbidden, errReason, "", r.Host, nil)
		return
	}

	// 3. Reject explicit Host header alongside :authority on HTTP/2 (NOW.md:49).
	if r.ProtoMajor == 2 && len(r.Header["Host"]) > 0 {
		deny(http.StatusForbidden, "h2-host-header", "", r.Host, nil)
		return
	}

	// 4. Validate Host/:authority non-empty, exact port match against listener dstPort, and SNI == Host on HTTPS.
	host, errReason := validateHostAndSNI(r, dstPort)
	if errReason != "" {
		deny(http.StatusForbidden, errReason, "", r.Host, nil)
		return
	}

	// 5. Inspect Upgrade headers: reject h2c and arbitrary upgrades unconditionally.
	wantWS, upgradeErr := classifyUpgrade(r)
	if upgradeErr != "" {
		deny(http.StatusForbidden, upgradeErr, "", host, nil)
		return
	}

	// 6. Evaluate policy live per HTTP request (never snapshotted at SYN).
	dec := s.eval.DecideRequest(s.link.Principal, host, dstPort, r.Method, r.URL.Path)
	if !dec.Allow {
		deny(http.StatusForbidden, dec.Reason, dec.RuleID, host, nil)
		return
	}

	if wantWS && !dec.AllowWebSocket {
		deny(http.StatusForbidden, "websocket-not-allowed", dec.RuleID, host, nil)
		return
	}
	if wantWS && (r.ContentLength != 0 || len(r.TransferEncoding) > 0) {
		deny(http.StatusBadRequest, "websocket-upgrade-with-body", dec.RuleID, host, nil)
		return
	}

	// 7. Check Content-Length against streaming body cap before dialing upstream.
	maxBody := s.store.Current().Config.HTTP.MaxRequestBodyBytes
	if r.ContentLength > maxBody {
		deny(http.StatusRequestEntityTooLarge, "body-too-large", dec.RuleID, host, nil)
		return
	}

	// 8. Substitute bound secrets (HTTPS :443 only) and unconditionally sweep Proxy-Authorization & mf_ph_*.
	outHeaders := make(http.Header)
	copyEndToEndHeaders(outHeaders, r.Header, wantWS)

	var (
		secretNames []string
		subPairs    []secret.Pair
	)
	if !wantWS {
		matchedBindings := s.eval.MatchBindings(s.link.Principal, host, dstPort, r.Method, r.URL.Path)
		var subErr error
		secretNames, subPairs, subErr = secret.ApplyRequest(outHeaders, matchedBindings, dstPort, secret.FileResolver{})
		if subErr != nil {
			var resErr *secret.ResolveError
			var badNames []string
			if errors.As(subErr, &resErr) && resErr.Name != "" {
				badNames = []string{resErr.Name}
			}
			deny(http.StatusForbidden, "secret-unresolved", dec.RuleID, host, badNames)
			return
		}
		if dec.HasBindings {
			// Force identity encoding on every request to a bound host (NOW.md:61).
			outHeaders.Set("Accept-Encoding", "identity")
		}
	} else {
		secret.SweepHeaders(outHeaders)
	}

	// 9. Register per-request/per-stream flow BEFORE dialing upstream so live revoke/reload/TTL works immediately.
	flowProto := r.Proto
	if wantWS {
		flowProto = "websocket"
	}
	reqCtx, reqCancel := context.WithCancel(r.Context())
	defer reqCancel()

	af := s.flows.register(FlowInfo{
		Principal: s.link.Principal,
		Link:      s.link.Name,
		Host:      host,
		Port:      dstPort,
		Method:    r.Method,
		Path:      r.URL.Path,
		RuleID:    dec.RuleID,
		GrantID:   dec.GrantID,
		Protocol:  flowProto,
	}, reqCancel, guestConnFromContext(r.Context()))
	defer s.flows.unregister(af.info.ID)

	// 10. Fail-closed admission audit BEFORE dialing upstream.
	admitEv := audit.Event{
		Kind:      audit.KindRequestAdmitted,
		Principal: s.link.Principal,
		Link:      s.link.Name,
		SrcIP:     srcIP,
		Protocol:  flowProto,
		Host:      host,
		Port:      int(dstPort),
		Method:    r.Method,
		Path:      reqPath,
		HasQuery:  hasQuery,
		Effect:    audit.EffectAllow,
		Reason:    dec.Reason,
		RuleID:    dec.RuleID,
		GrantID:   dec.GrantID,
		FlowID:    af.info.ID,
		Secrets:   secretNames,
	}
	if err := s.audit.WriteSync(admitEv); err != nil {
		http.Error(w, "audit sink unavailable", http.StatusServiceUnavailable)
		return
	}

	if wantWS {
		s.serveWebSocket(w, r.WithContext(reqCtx), dstPort, host, srcIP, dec, outHeaders, af)
		return
	}

	// 11. Rebuild outbound request with streaming MaxBytesReader and upstream conn trace.
	scheme := "https"
	if dstPort == 80 {
		scheme = "http"
	}

	limitedBody := http.MaxBytesReader(w, r.Body, maxBody)
	countingBody := &countingReadCloser{rc: limitedBody}

	outURL := *r.URL
	outURL.Scheme = scheme
	outURL.Host = net.JoinHostPort(host, strconv.Itoa(int(dstPort)))

	outReq, err := http.NewRequestWithContext(reqCtx, r.Method, outURL.String(), countingBody)
	if err != nil {
		deny(http.StatusBadGateway, "build-request-failed", dec.RuleID, host, secretNames)
		return
	}
	outReq.Host = host
	outReq.ContentLength = r.ContentLength
	outReq.Header = outHeaders

	// 12. RoundTrip directly (never follow 3xx redirects!).
	resp, err := s.transport.RoundTrip(outReq)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			deny(http.StatusRequestEntityTooLarge, "body-too-large", dec.RuleID, host, secretNames)
			return
		}
		s.auditCompleted(srcIP, r, dstPort, host, dec, af.info.ID, secretNames, http.StatusBadGateway, countingBody.n.Load(), 0, err.Error())
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			return
		}
	}()

	// Refuse unexpected 101 Switching Protocols on non-WebSocket flows.
	if resp.StatusCode == http.StatusSwitchingProtocols {
		s.auditCompleted(srcIP, r, dstPort, host, dec, af.info.ID, secretNames, http.StatusBadGateway, countingBody.n.Load(), 0, "unexpected-101")
		http.Error(w, "unexpected protocol upgrade", http.StatusBadGateway)
		return
	}

	// 13. Bound-host response enforcement: fail closed 502 on any non-identity
	// Content-Encoding token or any unresolvable bound secret, strip Content-Length,
	// and scrub headers + streaming body + trailers (NOW.md:61).
	var redactor *secret.Redactor
	if dec.HasBindings {
		if !isIdentityContentEncoding(resp.Header.Values("Content-Encoding")) {
			s.auditCompleted(srcIP, r, dstPort, host, dec, af.info.ID, secretNames, http.StatusBadGateway, countingBody.n.Load(), 0, "compressed-response-on-bound-host")
			http.Error(w, "bound host returned compressed response", http.StatusBadGateway)
			return
		}
		hostPairs, pairErr := secret.ResolveHostPairs(s.eval.HostBindings(s.link.Principal, host), subPairs, secret.FileResolver{})
		if pairErr != nil {
			s.auditCompleted(srcIP, r, dstPort, host, dec, af.info.ID, secretNames, http.StatusBadGateway, countingBody.n.Load(), 0, "redaction-secret-unresolved")
			http.Error(w, "bound secret unavailable for response redaction", http.StatusBadGateway)
			return
		}
		redactor = secret.NewRedactor(hostPairs)
	}

	// 14. Copy response headers, scrub if bound, announce trailers, flush per-chunk, forward trailers.
	copyEndToEndHeaders(w.Header(), resp.Header, false)
	if dec.HasBindings {
		if redactor.Active() {
			redactor.ScrubHeader(w.Header())
		}
		// Always strip Content-Length on bound hosts before WriteHeader.
		w.Header().Del("Content-Length")
	}
	for k := range resp.Trailer {
		w.Header().Add("Trailer", k)
	}
	w.WriteHeader(resp.StatusCode)

	var (
		bytesIn int64
		copyErr error
	)
	if redactor != nil && redactor.Active() {
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

	errText := ""
	if copyErr != nil {
		errText = copyErr.Error()
	}
	s.auditCompleted(srcIP, r, dstPort, host, dec, af.info.ID, secretNames, resp.StatusCode, countingBody.n.Load(), bytesIn, errText)
}

func (s *Server) auditCompleted(srcIP string, r *http.Request, dstPort uint16, host string, dec policy.Decision, flowID string, secretNames []string, status int, bytesOut, bytesIn int64, errText string) {
	ev := audit.Event{
		Kind:      audit.KindRequest,
		Principal: s.link.Principal,
		Link:      s.link.Name,
		SrcIP:     srcIP,
		Protocol:  r.Proto,
		Host:      host,
		Port:      int(dstPort),
		Method:    r.Method,
		Path:      r.URL.Path,
		HasQuery:  r.URL.RawQuery != "",
		Status:    status,
		Effect:    audit.EffectAllow,
		Reason:    dec.Reason,
		RuleID:    dec.RuleID,
		GrantID:   dec.GrantID,
		FlowID:    flowID,
		Secrets:   secretNames,
		BytesOut:  bytesOut,
		BytesIn:   bytesIn,
		Error:     errText,
	}
	if err := s.audit.WriteSync(ev); err != nil {
		return
	}
	if s.onRequest != nil {
		s.onRequest(s.link.Principal, string(audit.EffectAllow), status)
	}
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
	host := strings.TrimSuffix(strings.ToLower(hostPart), ".")
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
		sni := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.TLS.ServerName)), ".")
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

func copyStreaming(w http.ResponseWriter, src io.Reader) (int64, error) {
	rc := http.NewResponseController(w)
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
			if flushErr := rc.Flush(); flushErr != nil && !errors.Is(flushErr, http.ErrNotSupported) {
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
	rc := http.NewResponseController(w)
	flushFn := func() error {
		err := rc.Flush()
		if errors.Is(err, http.ErrNotSupported) {
			return nil
		}
		return err
	}
	sw := redactor.StreamWriter(w, flushFn)
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
