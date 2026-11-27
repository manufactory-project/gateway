// Package proxy implements gatewayd's per-(link, dstPort) TLS MITM and HTTP/1.1,
// HTTP/2, SSE, and opted-in WebSocket egress proxy (NOW.md:47-57).
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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/ca"
	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/netguard"
	"github.com/manufactory-project/gateway/internal/policy"
)

// Options configures a per-link MITM proxy Server.
type Options struct {
	Link          config.LinkConfig
	Store         *config.Store
	Evaluator     *policy.Evaluator
	Audit         *audit.Writer
	Leaves        *ca.LeafCache
	SNILimiter    *ca.DeniedSNILimiter
	Dialer        *netguard.Dialer
	DialContext   func(ctx context.Context, network, addr string) (net.Conn, error)
	UpstreamRoots *x509.CertPool
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
	sniLimiter    *ca.DeniedSNILimiter
	dialContext   func(ctx context.Context, network, addr string) (net.Conn, error)
	upstreamRoots *x509.CertPool
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
	sniLim := opts.SNILimiter
	if sniLim == nil {
		h := opts.Store.Current().Config.HTTP
		sniLim = ca.NewDeniedSNILimiter(h.DeniedSNIRatePerSec, h.DeniedSNIBurst)
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

	return &Server{
		link:          opts.Link,
		store:         opts.Store,
		eval:          opts.Evaluator,
		audit:         opts.Audit,
		leaves:        opts.Leaves,
		sniLimiter:    sniLim,
		dialContext:   dialFn,
		upstreamRoots: opts.UpstreamRoots,
		onRequest:     opts.OnRequest,
		transport:     tr,
	}, nil
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

	s.httpsSrv = &http.Server{
		Handler:                      http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serveHTTP(w, r, 443) }),
		MaxHeaderBytes:               hCfg.MaxHeaderBytes,
		ReadHeaderTimeout:            10 * time.Second,
		IdleTimeout:                  90 * time.Second,
		Protocols:                    &httpsProtos,
		DisableGeneralOptionsHandler: true,
	}
	s.httpSrv = &http.Server{
		Handler:                      http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serveHTTP(w, r, 80) }),
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

// HTTPSAddr returns the bound HTTPS listener address.
func (s *Server) HTTPSAddr() string {
	if s.httpsLn == nil {
		return ""
	}
	return s.httpsLn.Addr().String()
}

// HTTPAddr returns the bound HTTP listener address.
func (s *Server) HTTPAddr() string {
	if s.httpLn == nil {
		return ""
	}
	return s.httpLn.Addr().String()
}

// Shutdown drains listeners, closes idle upstream connections, and waits for goroutines.
func (s *Server) Shutdown(ctx context.Context) error {
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
	if !s.sniLimiter.Allow(s.link.Principal) {
		return
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

	deny := func(status int, reason, ruleID, host string) {
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
		deny(http.StatusForbidden, "connect-forbidden", "", r.Host)
		return
	}

	// 2. Reject non-origin-form targets (*, absolute-URI, relative path, path traversal, escaped slashes).
	if errReason := validateOriginForm(r); errReason != "" {
		deny(http.StatusForbidden, errReason, "", r.Host)
		return
	}

	// 3. Reject explicit Host header alongside :authority on HTTP/2 (NOW.md:49).
	if r.ProtoMajor == 2 && len(r.Header["Host"]) > 0 {
		deny(http.StatusForbidden, "h2-host-header", "", r.Host)
		return
	}

	// 4. Validate Host/:authority non-empty, exact port match against listener dstPort, and SNI == Host on HTTPS.
	host, errReason := validateHostAndSNI(r, dstPort)
	if errReason != "" {
		deny(http.StatusForbidden, errReason, "", r.Host)
		return
	}

	// 5. Inspect Upgrade headers: reject h2c and arbitrary upgrades unconditionally.
	wantWS, upgradeErr := classifyUpgrade(r)
	if upgradeErr != "" {
		deny(http.StatusForbidden, upgradeErr, "", host)
		return
	}

	// 6. Evaluate policy live per HTTP request (never snapshotted at SYN).
	dec := s.eval.DecideRequest(s.link.Principal, host, dstPort, r.Method, r.URL.Path)
	if !dec.Allow {
		deny(http.StatusForbidden, dec.Reason, dec.RuleID, host)
		return
	}

	if wantWS && !dec.AllowWebSocket {
		deny(http.StatusForbidden, "websocket-not-allowed", dec.RuleID, host)
		return
	}

	// 7. Check Content-Length against streaming body cap before dialing upstream.
	maxBody := s.store.Current().Config.HTTP.MaxRequestBodyBytes
	if r.ContentLength > maxBody {
		deny(http.StatusRequestEntityTooLarge, "body-too-large", dec.RuleID, host)
		return
	}

	// 8. Fail-closed admission audit BEFORE dialing upstream.
	admitEv := audit.Event{
		Kind:      audit.KindRequestAdmitted,
		Principal: s.link.Principal,
		Link:      s.link.Name,
		SrcIP:     srcIP,
		Protocol:  r.Proto,
		Host:      host,
		Port:      int(dstPort),
		Method:    r.Method,
		Path:      reqPath,
		HasQuery:  hasQuery,
		Effect:    audit.EffectAllow,
		Reason:    dec.Reason,
		RuleID:    dec.RuleID,
		GrantID:   dec.GrantID,
	}
	if err := s.audit.WriteSync(admitEv); err != nil {
		http.Error(w, "audit sink unavailable", http.StatusServiceUnavailable)
		return
	}

	if wantWS {
		s.serveWebSocket(w, r, dstPort, host, srcIP, dec)
		return
	}

	// 9. Rebuild outbound request with streaming MaxBytesReader and stripped hop-by-hop headers.
	scheme := "https"
	if dstPort == 80 {
		scheme = "http"
	}

	limitedBody := http.MaxBytesReader(w, r.Body, maxBody)
	countingBody := &countingReadCloser{rc: limitedBody}

	outURL := *r.URL
	outURL.Scheme = scheme
	outURL.Host = net.JoinHostPort(host, strconv.Itoa(int(dstPort)))

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), countingBody)
	if err != nil {
		deny(http.StatusBadGateway, "build-request-failed", dec.RuleID, host)
		return
	}
	outReq.Host = host
	outReq.ContentLength = r.ContentLength
	copyEndToEndHeaders(outReq.Header, r.Header, false)

	// 10. RoundTrip directly (never follow 3xx redirects!).
	resp, err := s.transport.RoundTrip(outReq)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			deny(http.StatusRequestEntityTooLarge, "body-too-large", dec.RuleID, host)
			return
		}
		s.auditCompleted(srcIP, r, dstPort, host, dec, http.StatusBadGateway, countingBody.n, 0, err.Error())
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
		s.auditCompleted(srcIP, r, dstPort, host, dec, http.StatusBadGateway, countingBody.n, 0, "unexpected-101")
		http.Error(w, "unexpected protocol upgrade", http.StatusBadGateway)
		return
	}

	// 11. Copy response headers, announce trailers, flush per-chunk for SSE, and forward trailers after EOF.
	copyEndToEndHeaders(w.Header(), resp.Header, false)
	for k := range resp.Trailer {
		w.Header().Add("Trailer", k)
	}
	w.WriteHeader(resp.StatusCode)

	bytesIn, copyErr := copyStreaming(w, resp.Body)
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
	s.auditCompleted(srcIP, r, dstPort, host, dec, resp.StatusCode, countingBody.n, bytesIn, errText)
}

func (s *Server) auditCompleted(srcIP string, r *http.Request, dstPort uint16, host string, dec policy.Decision, status int, bytesOut, bytesIn int64, errText string) {
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
	// Reject uncleaned traversal segments like /v1/../admin.
	if strings.Contains(r.URL.Path, "\\") {
		return "backslash-in-path"
	}
	for _, seg := range strings.Split(r.URL.Path, "/") {
		if seg == ".." {
			return "path-traversal"
		}
	}
	// Keep single check that path.Clean doesn't escape root.
	if !strings.HasPrefix(path.Clean(r.URL.Path), "/") {
		return "non-origin-form-target"
	}
	return ""
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
			// Preserve TE: trailers for gRPC/HTTP2 trailers.
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

type countingReadCloser struct {
	rc io.ReadCloser
	n  int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingReadCloser) Close() error {
	return c.rc.Close()
}
