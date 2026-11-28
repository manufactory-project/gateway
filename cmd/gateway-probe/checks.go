package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type writeCounterConn struct {
	net.Conn
	written atomic.Int64
}

func (w *writeCounterConn) Write(p []byte) (int, error) {
	n, err := w.Conn.Write(p)
	if n > 0 {
		w.written.Add(int64(n))
	}
	return n, err
}

func (w *writeCounterConn) BytesWritten() int64 {
	return w.written.Load()
}

// Result is emitted as one JSON line per probe check.
type Result struct {
	Check  string `json:"check"`
	Expect string `json:"expect"`
	Got    string `json:"got"`
	Pass   bool   `json:"pass"`
}

type probeConfig struct {
	AllowHost       string
	AllowPath       string
	UploadPath      string
	DownloadPath    string
	DenyHost        string
	LinkIP          string
	HTTPSPort       int
	FakePrefix      netip.Prefix
	WrongIP         string
	DirectHTTPSIP   string
	DNSServer       string
	RedirectDNS     string
	TCP22Target     string
	DoTTarget       string
	QUICTarget      string
	LANAddr         string
	MetadataAddr    string
	MgmtIP          string
	IPv6Target      string
	PeerLinkIP      string
	PeerGuestAddr   string
	Timeout         time.Duration
	SameIP          bool
	SrcIP           string
	SrcPort         int
	SameIPHTTPSDst  string
	SameIPDNSDst    string
	Hold            time.Duration
	RootCAs         *x509.CertPool
	AllowHTTPSPort  int
	AllowHTTPClient *http.Client
}

func (c probeConfig) transferTimeout() time.Duration {
	t := c.Timeout * 4
	if t < 15*time.Second {
		return 15 * time.Second
	}
	return t
}

func (c probeConfig) httpsTargetPort() int {
	if c.AllowHTTPSPort > 0 {
		return c.AllowHTTPSPort
	}
	return 443
}

func (c probeConfig) httpClient(timeout time.Duration) *http.Client {
	if c.AllowHTTPClient != nil {
		return c.AllowHTTPClient
	}
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    c.RootCAs,
		},
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func runAllChecks(ctx context.Context, cfg probeConfig) []Result {
	if cfg.SameIP {
		return runSameIPChecks(ctx, cfg)
	}

	var results []Result
	// 1. Direct HTTPS (IP literal without SNI) + dial-by-name control.
	results = append(results,
		checkDirectHTTPSNoSNI(ctx, cfg),
		checkDialByNameControl(ctx, cfg),
	)
	// 2. Blocked ports & protocols + TCP 443 by-name control.
	results = append(results,
		checkTCPBlocked(ctx, "blocked_tcp_22", cfg.TCP22Target, cfg.Timeout),
		checkTCPBlocked(ctx, "blocked_tcp_853_dot", cfg.DoTTarget, cfg.Timeout),
		checkQUICBlocked(ctx, cfg.QUICTarget, cfg.Timeout),
		checkHTTPSByNameControl(ctx, cfg),
	)
	// 3. DNS answers (positive control + REFUSED + NODATA).
	results = append(results, runDNSAnswerChecks(ctx, cfg)...)
	// 4. DNS redirect (UDP and TCP :53 to external resolver).
	results = append(results,
		checkDNSFakeIP(ctx, "dns_redirect_udp_53", "udp", cfg.RedirectDNS, cfg.AllowHost, cfg.FakePrefix, nil, cfg.Timeout),
		checkDNSFakeIP(ctx, "dns_redirect_tcp_53", "tcp", cfg.RedirectDNS, cfg.AllowHost, cfg.FakePrefix, nil, cfg.Timeout),
	)
	// 5. Unreachable addresses: LAN, metadata, gateway management IP.
	results = append(results,
		checkUnreachableService(ctx, "unreachable_lan", cfg.LANAddr, cfg.Timeout),
		checkUnreachableService(ctx, "unreachable_metadata", cfg.MetadataAddr, cfg.Timeout),
		checkTCPBlocked(ctx, "unreachable_gateway_mgmt", net.JoinHostPort(cfg.MgmtIP, "443"), cfg.Timeout),
	)
	// 6. SNI vs Host spoof + matching SNI/Host control.
	results = append(results,
		checkSNIHostSpoof(ctx, cfg),
		checkSNIHostMatchControl(ctx, cfg),
	)
	// 7. Transfer size > 64 KiB upload and download.
	results = append(results,
		checkUploadGT64K(ctx, cfg),
		checkDownloadGT64K(ctx, cfg),
	)
	// 8. Guest has no IPv6 path.
	results = append(results, checkIPv6NoPath(ctx, cfg.IPv6Target, cfg.Timeout))
	// 9. Direct connection to guest's own <link_IP>:<https_port> dropped.
	results = append(results, checkTCPBlocked(
		ctx,
		"gateway_listener_direct_dropped",
		net.JoinHostPort(cfg.LinkIP, strconv.Itoa(cfg.HTTPSPort)),
		cfg.Timeout,
	))
	// 10. Per-link isolation.
	if cfg.PeerLinkIP != "" {
		results = append(results, checkTCPBlocked(
			ctx,
			"peer_link_ip_unreachable",
			net.JoinHostPort(cfg.PeerLinkIP, "443"),
			cfg.Timeout,
		))
	}
	if cfg.PeerGuestAddr != "" {
		results = append(results, checkTCPBlocked(
			ctx,
			"peer_guest_unreachable",
			cfg.PeerGuestAddr,
			cfg.Timeout,
		))
	}
	return results
}

func runSameIPChecks(ctx context.Context, cfg probeConfig) []Result {
	ip := net.ParseIP(cfg.SrcIP)
	udpLocal := &net.UDPAddr{IP: ip, Port: cfg.SrcPort}
	tcpLocal := &net.TCPAddr{IP: ip, Port: cfg.SrcPort}

	dnsRes := checkDNSFakeIP(ctx, "same_ip_udp_53", "udp", cfg.SameIPDNSDst, cfg.AllowHost, cfg.FakePrefix, udpLocal, cfg.Timeout)
	httpsRes := checkSameIPHTTPS(ctx, cfg, tcpLocal)
	return []Result{dnsRes, httpsRes}
}

func checkDirectHTTPSNoSNI(ctx context.Context, cfg probeConfig) Result {
	const expect = "remote TLS handshake failure after sending no-SNI ClientHello"
	target := net.JoinHostPort(cfg.DirectHTTPSIP, strconv.Itoa(cfg.httpsTargetPort()))
	d := net.Dialer{Timeout: cfg.Timeout}
	rawConn, err := d.DialContext(ctx, "tcp4", target)
	if err != nil {
		return Result{
			Check:  "direct_https_ip_literal",
			Expect: expect,
			Got:    fmt.Sprintf("local dial error before sending ClientHello: %v", err),
			Pass:   false,
		}
	}
	defer closeQuietly(rawConn)

	if err := rawConn.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
		return Result{
			Check:  "direct_https_ip_literal",
			Expect: expect,
			Got:    fmt.Sprintf("set deadline: %v", err),
			Pass:   false,
		}
	}
	wc := &writeCounterConn{Conn: rawConn}
	tlsConn := tls.Client(wc, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	})
	defer closeQuietly(tlsConn)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		sent := wc.BytesWritten()
		if sent == 0 {
			return Result{
				Check:  "direct_https_ip_literal",
				Expect: expect,
				Got:    fmt.Sprintf("local error before sending ClientHello: %v", err),
				Pass:   false,
			}
		}
		return Result{
			Check:  "direct_https_ip_literal",
			Expect: expect,
			Got:    fmt.Sprintf("remote rejected no-SNI ClientHello (%d bytes sent): %v", sent, err),
			Pass:   true,
		}
	}
	return Result{
		Check:  "direct_https_ip_literal",
		Expect: expect,
		Got:    "tls handshake unexpectedly succeeded without SNI",
		Pass:   false,
	}
}

func checkDialByNameControl(ctx context.Context, cfg probeConfig) Result {
	target := net.JoinHostPort(cfg.WrongIP, strconv.Itoa(cfg.httpsTargetPort()))
	status, err := rawHTTPSGet(ctx, target, cfg.AllowHost, cfg.AllowHost, cfg.AllowPath, nil, cfg.RootCAs, cfg.Timeout, 0)
	if err != nil {
		return Result{
			Check:  "direct_https_dial_by_name_control",
			Expect: "HTTP 2xx via dial-by-name despite wrong IP",
			Got:    fmt.Sprintf("error: %v", err),
			Pass:   false,
		}
	}
	pass := status >= 200 && status < 300
	return Result{
		Check:  "direct_https_dial_by_name_control",
		Expect: "HTTP 2xx via dial-by-name despite wrong IP",
		Got:    fmt.Sprintf("HTTP %d", status),
		Pass:   pass,
	}
}

func checkTCPBlocked(ctx context.Context, name, addr string, timeout time.Duration) Result {
	const expect = "tcp connect timeout (dropped, never refused/reset)"
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp4", addr)
	if err != nil {
		class := classifyDialError(err)
		return Result{
			Check:  name,
			Expect: expect,
			Got:    fmt.Sprintf("%s: %v", class, err),
			Pass:   class == "timeout",
		}
	}
	closeQuietly(conn)
	return Result{
		Check:  name,
		Expect: expect,
		Got:    fmt.Sprintf("connected to %s", addr),
		Pass:   false,
	}
}

func checkQUICBlocked(ctx context.Context, addr string, timeout time.Duration) Result {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp4", addr)
	if err != nil {
		return Result{
			Check:  "blocked_udp_443_quic",
			Expect: "udp/443 blocked (no reply)",
			Got:    fmt.Sprintf("dial error: %v", err),
			Pass:   true,
		}
	}
	defer closeQuietly(conn)

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return Result{
			Check:  "blocked_udp_443_quic",
			Expect: "udp/443 blocked (no reply)",
			Got:    fmt.Sprintf("set deadline: %v", err),
			Pass:   false,
		}
	}
	// Minimal 1200-byte QUIC long-header packet with reserved version 0x0a0a0a0a
	// to elicit a Version Negotiation reply from any reachable QUIC server.
	pkt := make([]byte, 1200)
	pkt[0] = 0xc0
	pkt[1], pkt[2], pkt[3], pkt[4] = 0x0a, 0x0a, 0x0a, 0x0a
	pkt[5] = 8
	for i := 6; i < 14; i++ {
		pkt[i] = byte(i)
	}
	if _, err := conn.Write(pkt); err != nil {
		return Result{
			Check:  "blocked_udp_443_quic",
			Expect: "udp/443 blocked (no reply)",
			Got:    fmt.Sprintf("write error: %v", err),
			Pass:   true,
		}
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return Result{
			Check:  "blocked_udp_443_quic",
			Expect: "udp/443 blocked (no reply)",
			Got:    fmt.Sprintf("blocked: %v", err),
			Pass:   true,
		}
	}
	return Result{
		Check:  "blocked_udp_443_quic",
		Expect: "udp/443 blocked (no reply)",
		Got:    fmt.Sprintf("unexpectedly received %d bytes from %s", n, addr),
		Pass:   false,
	}
}

func checkHTTPSByNameControl(ctx context.Context, cfg probeConfig) Result {
	u := fmt.Sprintf("https://%s%s", cfg.AllowHost, cfg.AllowPath)
	if cfg.AllowHTTPSPort > 0 && cfg.AllowHTTPSPort != 443 {
		u = fmt.Sprintf("https://%s:%d%s", cfg.AllowHost, cfg.AllowHTTPSPort, cfg.AllowPath)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Result{
			Check:  "allowed_tcp_443_by_name_control",
			Expect: "HTTP 2xx via TCP 443 by name",
			Got:    fmt.Sprintf("build request: %v", err),
			Pass:   false,
		}
	}
	client := cfg.httpClient(cfg.transferTimeout())
	resp, err := client.Do(req)
	if err != nil {
		return Result{
			Check:  "allowed_tcp_443_by_name_control",
			Expect: "HTTP 2xx via TCP 443 by name",
			Got:    fmt.Sprintf("error: %v", err),
			Pass:   false,
		}
	}
	defer closeQuietly(resp.Body)
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return Result{
			Check:  "allowed_tcp_443_by_name_control",
			Expect: "HTTP 2xx via TCP 443 by name",
			Got:    fmt.Sprintf("read body: %v", err),
			Pass:   false,
		}
	}
	return Result{
		Check:  "allowed_tcp_443_by_name_control",
		Expect: "HTTP 2xx via TCP 443 by name",
		Got:    fmt.Sprintf("HTTP %d", resp.StatusCode),
		Pass:   resp.StatusCode >= 200 && resp.StatusCode < 300,
	}
}

func runDNSAnswerChecks(ctx context.Context, cfg probeConfig) []Result {
	var out []Result
	out = append(out, checkDNSFakeIP(ctx, "dns_allow_a_control", "udp", cfg.DNSServer, cfg.AllowHost, cfg.FakePrefix, nil, cfg.Timeout))

	refusedTypes := []struct {
		name  string
		qtype uint16
	}{
		{"dns_refused_txt", qtypeTXT},
		{"dns_refused_mx", qtypeMX},
		{"dns_refused_ns", qtypeNS},
		{"dns_refused_srv", qtypeSRV},
		{"dns_refused_cname", qtypeCNAME},
	}
	for _, tc := range refusedTypes {
		out = append(out, checkDNSRefused(ctx, tc.name, cfg.DNSServer, cfg.AllowHost, tc.qtype, cfg.Timeout))
	}
	out = append(out, checkDNSRefused(ctx, "dns_refused_non_allowlisted", cfg.DNSServer, cfg.DenyHost, qtypeA, cfg.Timeout))

	nodataTypes := []struct {
		name  string
		qtype uint16
	}{
		{"dns_nodata_aaaa", qtypeAAAA},
		{"dns_nodata_https", qtypeHTTPS},
		{"dns_nodata_svcb", qtypeSVCB},
	}
	for _, tc := range nodataTypes {
		out = append(out, checkDNSNoData(ctx, tc.name, cfg.DNSServer, cfg.AllowHost, tc.qtype, cfg.Timeout))
	}
	return out
}

func checkDNSFakeIP(ctx context.Context, name, proto, server, qname string, prefix netip.Prefix, localAddr *net.UDPAddr, timeout time.Duration) Result {
	expect := fmt.Sprintf("NOERROR A in %s", prefix)
	reply, err := queryDNS(ctx, proto, server, qname, qtypeA, localAddr, timeout)
	if err != nil {
		return Result{Check: name, Expect: expect, Got: fmt.Sprintf("error: %v", err), Pass: false}
	}
	if reply.Rcode != rcodeNoError || len(reply.Addrs) == 0 {
		return Result{
			Check:  name,
			Expect: expect,
			Got:    fmt.Sprintf("rcode=%s answers=%d", rcodeName(reply.Rcode), reply.ANCount),
			Pass:   false,
		}
	}
	ip := reply.Addrs[0]
	return Result{
		Check:  name,
		Expect: expect,
		Got:    fmt.Sprintf("rcode=%s a=%s", rcodeName(reply.Rcode), ip),
		Pass:   prefix.Contains(ip),
	}
}

func checkDNSRefused(ctx context.Context, name, server, qname string, qtype uint16, timeout time.Duration) Result {
	reply, err := queryDNS(ctx, "udp", server, qname, qtype, nil, timeout)
	if err != nil {
		return Result{Check: name, Expect: "REFUSED", Got: fmt.Sprintf("error: %v", err), Pass: false}
	}
	return Result{
		Check:  name,
		Expect: "REFUSED",
		Got:    fmt.Sprintf("rcode=%s answers=%d", rcodeName(reply.Rcode), reply.ANCount),
		Pass:   reply.Rcode == rcodeRefused,
	}
}

func checkDNSNoData(ctx context.Context, name, server, qname string, qtype uint16, timeout time.Duration) Result {
	reply, err := queryDNS(ctx, "udp", server, qname, qtype, nil, timeout)
	if err != nil {
		return Result{Check: name, Expect: "NOERROR NODATA (0 answers)", Got: fmt.Sprintf("error: %v", err), Pass: false}
	}
	return Result{
		Check:  name,
		Expect: "NOERROR NODATA (0 answers)",
		Got:    fmt.Sprintf("rcode=%s answers=%d", rcodeName(reply.Rcode), reply.ANCount),
		Pass:   reply.Rcode == rcodeNoError && reply.ANCount == 0,
	}
}

func checkUnreachableService(ctx context.Context, name, addr string, timeout time.Duration) Result {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return Result{Check: name, Expect: "unreachable", Got: fmt.Sprintf("bad addr %q: %v", addr, err), Pass: false}
	}
	if port != "80" {
		return checkTCPBlocked(ctx, name, addr, timeout)
	}
	return checkUnreachableHTTP(ctx, name, addr, host, timeout)
}

func checkUnreachableHTTP(ctx context.Context, name, addr, hostHeader string, timeout time.Duration) Result {
	const expect = "unreachable (timeout or gateway 403)"
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp4", addr)
	if err != nil {
		class := classifyDialError(err)
		return Result{Check: name, Expect: expect, Got: fmt.Sprintf("%s: %v", class, err), Pass: class == "timeout"}
	}
	defer closeQuietly(conn)

	// Port 80 is DNATed to gateway, which must refuse IP-literal Host with 403.
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return Result{Check: name, Expect: expect, Got: fmt.Sprintf("set deadline: %v", err), Pass: false}
	}
	reqStr := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostHeader)
	if _, err := io.WriteString(conn, reqStr); err != nil {
		return Result{Check: name, Expect: expect, Got: fmt.Sprintf("write error: %v", err), Pass: false}
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		return Result{Check: name, Expect: expect, Got: fmt.Sprintf("read error: %v", err), Pass: false}
	}
	defer closeQuietly(resp.Body)
	body, rErr := io.ReadAll(io.LimitReader(resp.Body, 512))
	if rErr != nil {
		return Result{Check: name, Expect: expect, Got: fmt.Sprintf("read body: %v", rErr), Pass: false}
	}
	denied := resp.StatusCode == http.StatusForbidden && strings.Contains(string(body), "egress denied")
	return Result{
		Check:  name,
		Expect: expect,
		Got:    fmt.Sprintf("HTTP %d", resp.StatusCode),
		Pass:   denied,
	}
}

func checkSNIHostSpoof(ctx context.Context, cfg probeConfig) Result {
	const expect = "HTTP 403"
	target := net.JoinHostPort(cfg.WrongIP, strconv.Itoa(cfg.httpsTargetPort()))
	status, err := rawHTTPSGet(ctx, target, cfg.AllowHost, cfg.DenyHost, "/", nil, cfg.RootCAs, cfg.Timeout, 0)
	if err != nil {
		return Result{
			Check:  "sni_host_spoof",
			Expect: expect,
			Got:    fmt.Sprintf("error: %v", err),
			Pass:   false,
		}
	}
	return Result{
		Check:  "sni_host_spoof",
		Expect: expect,
		Got:    fmt.Sprintf("HTTP %d", status),
		Pass:   status == http.StatusForbidden,
	}
}

func checkSNIHostMatchControl(ctx context.Context, cfg probeConfig) Result {
	target := net.JoinHostPort(cfg.WrongIP, strconv.Itoa(cfg.httpsTargetPort()))
	status, err := rawHTTPSGet(ctx, target, cfg.AllowHost, cfg.AllowHost, cfg.AllowPath, nil, cfg.RootCAs, cfg.Timeout, 0)
	if err != nil {
		return Result{
			Check:  "sni_host_match_control",
			Expect: "HTTP 2xx with matching SNI and Host",
			Got:    fmt.Sprintf("error: %v", err),
			Pass:   false,
		}
	}
	return Result{
		Check:  "sni_host_match_control",
		Expect: "HTTP 2xx with matching SNI and Host",
		Got:    fmt.Sprintf("HTTP %d", status),
		Pass:   status >= 200 && status < 300,
	}
}

func checkUploadGT64K(ctx context.Context, cfg probeConfig) Result {
	const payloadSize = 70000 // > 65536 bytes (64 KiB)
	u := fmt.Sprintf("https://%s%s", cfg.AllowHost, cfg.UploadPath)
	if cfg.AllowHTTPSPort > 0 && cfg.AllowHTTPSPort != 443 {
		u = fmt.Sprintf("https://%s:%d%s", cfg.AllowHost, cfg.AllowHTTPSPort, cfg.UploadPath)
	}
	payload := bytes.Repeat([]byte("A"), payloadSize)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return Result{Check: "transfer_upload_gt64k", Expect: "HTTP 2xx for >64 KiB POST", Got: fmt.Sprintf("build request: %v", err), Pass: false}
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	client := cfg.httpClient(cfg.transferTimeout())
	resp, err := client.Do(req)
	if err != nil {
		return Result{Check: "transfer_upload_gt64k", Expect: "HTTP 2xx for >64 KiB POST", Got: fmt.Sprintf("error: %v", err), Pass: false}
	}
	defer closeQuietly(resp.Body)
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return Result{Check: "transfer_upload_gt64k", Expect: "HTTP 2xx for >64 KiB POST", Got: fmt.Sprintf("read body: %v", err), Pass: false}
	}
	return Result{
		Check:  "transfer_upload_gt64k",
		Expect: "HTTP 2xx for >64 KiB POST",
		Got:    fmt.Sprintf("HTTP %d (%d bytes sent)", resp.StatusCode, payloadSize),
		Pass:   resp.StatusCode >= 200 && resp.StatusCode < 300,
	}
}

func checkDownloadGT64K(ctx context.Context, cfg probeConfig) Result {
	const minBytes = 65537 // > 64 KiB
	u := fmt.Sprintf("https://%s%s", cfg.AllowHost, cfg.DownloadPath)
	if cfg.AllowHTTPSPort > 0 && cfg.AllowHTTPSPort != 443 {
		u = fmt.Sprintf("https://%s:%d%s", cfg.AllowHost, cfg.AllowHTTPSPort, cfg.DownloadPath)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Result{Check: "transfer_download_gt64k", Expect: "HTTP 2xx with >64 KiB body", Got: fmt.Sprintf("build request: %v", err), Pass: false}
	}
	client := cfg.httpClient(cfg.transferTimeout())
	resp, err := client.Do(req)
	if err != nil {
		return Result{Check: "transfer_download_gt64k", Expect: "HTTP 2xx with >64 KiB body", Got: fmt.Sprintf("error: %v", err), Pass: false}
	}
	defer closeQuietly(resp.Body)
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		return Result{Check: "transfer_download_gt64k", Expect: "HTTP 2xx with >64 KiB body", Got: fmt.Sprintf("read body: %v", err), Pass: false}
	}
	return Result{
		Check:  "transfer_download_gt64k",
		Expect: "HTTP 2xx with >64 KiB body",
		Got:    fmt.Sprintf("HTTP %d (%d bytes received)", resp.StatusCode, n),
		Pass:   resp.StatusCode >= 200 && resp.StatusCode < 300 && n >= minBytes,
	}
}

func checkIPv6NoPath(ctx context.Context, target string, timeout time.Duration) Result {
	const expect = "guest has no IPv6 path (disable_ipv6 set on link)"
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp6", target)
	if err != nil {
		class := classifyDialError(err)
		return Result{
			Check:  "ipv6_no_path",
			Expect: expect,
			Got:    fmt.Sprintf("%s: %v", class, err),
			Pass:   true,
		}
	}
	closeQuietly(conn)
	return Result{
		Check:  "ipv6_no_path",
		Expect: expect,
		Got:    fmt.Sprintf("connected over IPv6 to %s", target),
		Pass:   false,
	}
}

func checkSameIPHTTPS(ctx context.Context, cfg probeConfig, localAddr *net.TCPAddr) Result {
	status, err := rawHTTPSGet(ctx, cfg.SameIPHTTPSDst, cfg.AllowHost, cfg.AllowHost, cfg.AllowPath, localAddr, cfg.RootCAs, cfg.transferTimeout(), cfg.Hold)
	if err != nil {
		return Result{
			Check:  "same_ip_tcp_443",
			Expect: "HTTP 2xx from fixed source IP and port",
			Got:    fmt.Sprintf("error: %v", err),
			Pass:   false,
		}
	}
	return Result{
		Check:  "same_ip_tcp_443",
		Expect: "HTTP 2xx from fixed source IP and port",
		Got:    fmt.Sprintf("HTTP %d from %s", status, localAddr),
		Pass:   status >= 200 && status < 300,
	}
}

func rawHTTPSGet(
	ctx context.Context,
	dialAddr string,
	sni string,
	hostHeader string,
	path string,
	localAddr *net.TCPAddr,
	rootCAs *x509.CertPool,
	timeout time.Duration,
	hold time.Duration,
) (int, error) {
	d := net.Dialer{
		Timeout: timeout,
		Control: reuseAddrControl,
	}
	if localAddr != nil {
		d.LocalAddr = localAddr
	}
	rawConn, err := d.DialContext(ctx, "tcp4", dialAddr)
	if err != nil {
		return 0, err
	}
	defer closeQuietly(rawConn)

	if err := rawConn.SetDeadline(time.Now().Add(timeout + hold)); err != nil {
		return 0, err
	}
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
	})
	defer closeQuietly(tlsConn)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return 0, err
	}
	connHdr := "close"
	if hold > 0 {
		connHdr = "keep-alive"
	}
	reqLine := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: gateway-probe\r\nConnection: %s\r\n\r\n", path, hostHeader, connHdr)
	if _, err := io.WriteString(tlsConn, reqLine); err != nil {
		return 0, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		return 0, err
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		closeQuietly(resp.Body)
		return 0, err
	}
	closeQuietly(resp.Body)

	if hold > 0 {
		timer := time.NewTimer(hold)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return resp.StatusCode, ctx.Err()
		case <-timer.C:
		}
	}
	return resp.StatusCode, nil
}

func closeQuietly(c io.Closer) {
	if c == nil {
		return
	}
	if err := c.Close(); err != nil {
		return
	}
}
