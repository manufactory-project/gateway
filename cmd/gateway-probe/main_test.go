// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestDNSWireEncodeParse(t *testing.T) {
	q, err := buildDNSQuery(0x1234, "allow.example.com", qtypeA)
	if err != nil {
		t.Fatalf("buildDNSQuery: %v", err)
	}
	// Construct a minimal DNS reply with compression pointer + A 198.18.0.42.
	resp := make([]byte, len(q))
	copy(resp, q)
	binary.BigEndian.PutUint16(resp[2:4], 0x8180) // QR=1, NOERROR
	binary.BigEndian.PutUint16(resp[6:8], 1)      // ANCOUNT=1
	ans := []byte{
		0xc0, 0x0c, // pointer to QNAME at offset 12
		0x00, 0x01, // TYPE A
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x00, 0x3c, // TTL 60
		0x00, 0x04, // RDLENGTH 4
		198, 18, 0, 42,
	}
	resp = append(resp, ans...)

	parsed, err := parseDNSReply(resp, 0x1234)
	if err != nil {
		t.Fatalf("parseDNSReply: %v", err)
	}
	if parsed.Rcode != rcodeNoError || parsed.ANCount != 1 || len(parsed.Addrs) != 1 {
		t.Fatalf("unexpected reply: %+v", parsed)
	}
	if got := parsed.Addrs[0].String(); got != "198.18.0.42" {
		t.Fatalf("got IP %s, want 198.18.0.42", got)
	}
}

func TestEmitResultsJSONLAndExitError(t *testing.T) {
	var buf bytes.Buffer
	okResults := []Result{
		{Check: "a", Expect: "ok", Got: "ok", Pass: true},
		{Check: "b", Expect: "ok", Got: "ok", Pass: true},
	}
	if err := emitResults(&buf, okResults); err != nil {
		t.Fatalf("emitResults all pass: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSONL lines, got %d", len(lines))
	}
	var decoded Result
	if err := json.Unmarshal([]byte(lines[0]), &decoded); err != nil {
		t.Fatalf("unmarshal line 0: %v", err)
	}
	if decoded.Check != "a" || !decoded.Pass {
		t.Fatalf("unexpected decoded line 0: %+v", decoded)
	}

	buf.Reset()
	failResults := []Result{
		{Check: "a", Expect: "ok", Got: "ok", Pass: true},
		{Check: "b", Expect: "ok", Got: "bad", Pass: false},
	}
	if err := emitResults(&buf, failResults); err == nil {
		t.Fatal("expected error when a check fails")
	}
}

func TestMockChecksAndSameIPMode(t *testing.T) {
	caCert, srvCert := mustSelfSignedCert(t, "allow.example.test")
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	// Start mock HTTPS server enforcing SNI == allow.example.test and Host == allow.example.test.
	var (
		sniMu       sync.Mutex
		sawEmptySNI bool
	)
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "" {
				sniMu.Lock()
				sawEmptySNI = true
				sniMu.Unlock()
			}
			if hello.ServerName != "allow.example.test" {
				return nil, io.EOF
			}
			return &srvCert, nil
		},
	}
	rawLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	tlsLn := tls.NewListener(rawLn, tlsCfg)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
			host = h
		}
		if host != "allow.example.test" {
			http.Error(w, "egress denied: host-mismatch", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/get":
			w.WriteHeader(http.StatusOK)
			if _, wErr := io.WriteString(w, "ok"); wErr != nil {
				return
			}
		case "/post":
			n, cErr := io.Copy(io.Discard, r.Body)
			if cErr != nil || n <= 65536 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
		case "/bytes/70000":
			w.WriteHeader(http.StatusOK)
			if _, wErr := w.Write(bytes.Repeat([]byte("B"), 70000)); wErr != nil {
				return
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if sErr := srv.Serve(tlsLn); sErr != nil && sErr != http.ErrServerClosed {
			return
		}
	}()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if sErr := srv.Shutdown(shutCtx); sErr != nil {
			t.Errorf("shutdown https: %v", sErr)
		}
	}()

	tcpAddr, ok := rawLn.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected *net.TCPAddr, got %T", rawLn.Addr())
	}
	httpsPort := tcpAddr.Port

	// Start mock UDP DNS server returning fake IP 198.18.0.55 for A allow.example.test,
	// NODATA for AAAA/HTTPS/SVCB, and REFUSED for everything else.
	udpPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		serveMockUDPDNS(udpPC)
	}()
	defer func() {
		if cErr := udpPC.Close(); cErr != nil {
			t.Errorf("close udp: %v", cErr)
		}
		<-dnsDone
	}()

	// Reserve a loopback port on both TCP and UDP for the whole test so
	// concurrent tests cannot claim it before runSameIPChecks binds it.
	srcPort := reserveSameIPPort(t, [4]byte{127, 0, 0, 1})

	prefix := netip.MustParsePrefix("198.18.0.0/15")
	customClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp4", rawLn.Addr().String())
			},
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    pool,
			},
			DisableKeepAlives: true,
		},
		Timeout: 5 * time.Second,
	}

	cfg := probeConfig{
		AllowHost:       "allow.example.test",
		AllowPath:       "/get",
		UploadPath:      "/post",
		DownloadPath:    "/bytes/70000",
		DenyHost:        "denied.example.test",
		FakePrefix:      prefix,
		WrongIP:         "127.0.0.1",
		DirectHTTPSIP:   "127.0.0.1",
		DNSServer:       udpPC.LocalAddr().String(),
		Timeout:         2 * time.Second,
		RootCAs:         pool,
		AllowHTTPSPort:  httpsPort,
		AllowHTTPClient: customClient,
	}

	ctx := context.Background()
	checks := []Result{
		checkDirectHTTPSNoSNI(ctx, cfg),
		checkDialByNameControl(ctx, cfg),
		checkHTTPSByNameControl(ctx, cfg),
		checkSNIHostSpoof(ctx, cfg),
		checkSNIHostMatchControl(ctx, cfg),
		checkUploadGT64K(ctx, cfg),
		checkDownloadGT64K(ctx, cfg),
	}
	checks = append(checks, runDNSAnswerChecks(ctx, cfg)...)
	for _, r := range checks {
		if !r.Pass {
			t.Errorf("check %s failed: expect=%q got=%q", r.Check, r.Expect, r.Got)
		}
	}
	sniMu.Lock()
	gotEmptySNI := sawEmptySNI
	sniMu.Unlock()
	if !gotEmptySNI {
		t.Fatal("expected direct_https_ip_literal to send a real ClientHello with ServerName == \"\"")
	}

	// Verify same-IP mode binds fixed source IP and port on both UDP and TCP.
	sameCfg := cfg
	sameCfg.SameIP = true
	sameCfg.SrcIP = "127.0.0.1"
	sameCfg.SrcPort = srcPort
	sameCfg.SameIPDNSDst = udpPC.LocalAddr().String()
	sameCfg.SameIPHTTPSDst = rawLn.Addr().String()
	sameCfg.Hold = 20 * time.Millisecond
	for _, r := range runSameIPChecks(ctx, sameCfg) {
		if !r.Pass {
			t.Errorf("same-ip check %s failed: expect=%q got=%q", r.Check, r.Expect, r.Got)
		}
	}
}

func serveMockUDPDNS(pc net.PacketConn) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 12 {
			continue
		}
		pkt := buf[:n]
		qname, next, err := decodeMockQName(pkt, 12)
		if err != nil || next+4 > len(pkt) {
			continue
		}
		qtype := binary.BigEndian.Uint16(pkt[next : next+2])
		resp := make([]byte, len(pkt))
		copy(resp, pkt)
		flags := uint16(0x8180) // QR=1, NOERROR
		switch {
		case qname != "allow.example.test":
			flags |= rcodeRefused
		case qtype == qtypeA:
			binary.BigEndian.PutUint16(resp[6:8], 1)
			resp = append(resp, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 198, 18, 0, 55)
		case qtype == qtypeAAAA || qtype == qtypeHTTPS || qtype == qtypeSVCB:
			// NODATA: NOERROR + 0 answers
		default:
			flags |= rcodeRefused
		}
		binary.BigEndian.PutUint16(resp[2:4], flags)
		if _, wErr := pc.WriteTo(resp, addr); wErr != nil {
			return
		}
	}
}

func decodeMockQName(pkt []byte, off int) (string, int, error) {
	var parts []string
	for off < len(pkt) {
		l := int(pkt[off])
		if l == 0 {
			return strings.Join(parts, "."), off + 1, nil
		}
		if off+1+l > len(pkt) {
			return "", 0, io.ErrUnexpectedEOF
		}
		parts = append(parts, string(pkt[off+1:off+1+l]))
		off += 1 + l
	}
	return "", 0, io.ErrUnexpectedEOF
}

func mustSelfSignedCert(t *testing.T, dnsName string) (*x509.Certificate, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert, tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}

func TestDirectHTTPSNoSNIBypassFails(t *testing.T) {
	_, srvCert := mustSelfSignedCert(t, "bypass.example.test")
	var (
		mu       sync.Mutex
		seenSNIs []string
	)
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			seenSNIs = append(seenSNIs, hello.ServerName)
			mu.Unlock()
			return &srvCert, nil
		},
	}
	rawLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	tlsLn := tls.NewListener(rawLn, tlsCfg)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, aErr := tlsLn.Accept()
		if aErr != nil {
			return
		}
		defer closeQuietly(conn)
		if tConn, ok := conn.(*tls.Conn); ok {
			if hErr := tConn.Handshake(); hErr != nil {
				return
			}
		}
	}()
	defer func() {
		if cErr := tlsLn.Close(); cErr != nil {
			t.Errorf("close tlsLn: %v", cErr)
		}
		<-done
	}()

	tcpAddr, ok := rawLn.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected *net.TCPAddr, got %T", rawLn.Addr())
	}
	res := checkDirectHTTPSNoSNI(context.Background(), probeConfig{
		DirectHTTPSIP:  "127.0.0.1",
		AllowHTTPSPort: tcpAddr.Port,
		Timeout:        2 * time.Second,
	})
	t.Logf("bypass result: %+v", res)
	if res.Pass {
		t.Fatalf("expected direct_https_ip_literal to FAIL against permissive TLS server, got pass: %+v", res)
	}

	mu.Lock()
	snis := append([]string(nil), seenSNIs...)
	mu.Unlock()
	if len(snis) != 1 || snis[0] != "" {
		t.Fatalf("expected GetCertificate to record exactly one ClientHello with ServerName == \"\", got %#v", snis)
	}
}

func TestTCPBlockedRefusedFails(t *testing.T) {
	// Reserve an unlistened TCP port for the whole test: the kernel rejects
	// incoming SYNs with ECONNREFUSED while preventing any other test from
	// reclaiming the port.
	closedAddr := reserveUnlistenedTCP(t, [4]byte{127, 0, 0, 2})

	res := checkTCPBlocked(context.Background(), "blocked_tcp_22", closedAddr, 2*time.Second)
	t.Logf("bypass result: %+v", res)
	if res.Pass {
		t.Fatalf("expected closed loopback port (refused/reset) to FAIL checkTCPBlocked, got pass: %+v", res)
	}
	if !strings.HasPrefix(res.Got, "refused:") && !strings.HasPrefix(res.Got, "reset:") {
		t.Fatalf("expected got to report refused/reset class, got %q", res.Got)
	}
}

func TestBypassSNIHostSpoof200(t *testing.T) {
	caCert, srvCert := mustSelfSignedCert(t, "allow.example.test")
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	rawLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	tlsLn := tls.NewListener(rawLn, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{srvCert},
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, wErr := io.WriteString(w, "spoofed ok"); wErr != nil {
			return
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if sErr := srv.Serve(tlsLn); sErr != nil && sErr != http.ErrServerClosed {
			return
		}
	}()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if sErr := srv.Shutdown(shutCtx); sErr != nil {
			t.Errorf("shutdown https: %v", sErr)
		}
	}()

	tcpAddr, ok := rawLn.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected *net.TCPAddr, got %T", rawLn.Addr())
	}
	res := checkSNIHostSpoof(context.Background(), probeConfig{
		AllowHost:      "allow.example.test",
		DenyHost:       "spoof.example.test",
		WrongIP:        "127.0.0.1",
		AllowHTTPSPort: tcpAddr.Port,
		RootCAs:        pool,
		Timeout:        2 * time.Second,
	})
	t.Logf("bypass result: %+v", res)
	if res.Pass {
		t.Fatalf("expected sni_host_spoof to FAIL on HTTP 200, got pass: %+v", res)
	}
	if res.Got != "HTTP 200" {
		t.Fatalf("expected Got == HTTP 200, got %q", res.Got)
	}

	// Also verify connection/TLS errors fail the spoof check (must be 403).
	closedLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen closed: %v", err)
	}
	closedTCP, ok := closedLn.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected *net.TCPAddr, got %T", closedLn.Addr())
	}
	if err := closedLn.Close(); err != nil {
		t.Fatalf("close closedLn: %v", err)
	}
	errRes := checkSNIHostSpoof(context.Background(), probeConfig{
		AllowHost:      "allow.example.test",
		DenyHost:       "spoof.example.test",
		WrongIP:        "127.0.0.1",
		AllowHTTPSPort: closedTCP.Port,
		RootCAs:        pool,
		Timeout:        2 * time.Second,
	})
	t.Logf("error-bypass result: %+v", errRes)
	if errRes.Pass {
		t.Fatalf("expected sni_host_spoof to FAIL on connection error, got pass: %+v", errRes)
	}
}

func TestBypassDNSRefusedAnswered(t *testing.T) {
	udpPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		servePermissiveMockDNS(udpPC, [4]byte{198, 18, 0, 55})
	}()
	defer func() {
		if cErr := udpPC.Close(); cErr != nil {
			t.Errorf("close udp: %v", cErr)
		}
		<-done
	}()

	cfg := probeConfig{
		AllowHost:  "allow.example.test",
		DenyHost:   "denied.example.test",
		FakePrefix: netip.MustParsePrefix("198.18.0.0/15"),
		DNSServer:  udpPC.LocalAddr().String(),
		Timeout:    2 * time.Second,
	}
	ctx := context.Background()
	cases := []struct {
		name  string
		qname string
		qtype uint16
	}{
		{"dns_refused_txt", cfg.AllowHost, qtypeTXT},
		{"dns_refused_mx", cfg.AllowHost, qtypeMX},
		{"dns_refused_ns", cfg.AllowHost, qtypeNS},
		{"dns_refused_srv", cfg.AllowHost, qtypeSRV},
		{"dns_refused_cname", cfg.AllowHost, qtypeCNAME},
		{"dns_refused_non_allowlisted", cfg.DenyHost, qtypeA},
	}
	for _, tc := range cases {
		res := checkDNSRefused(ctx, tc.name, cfg.DNSServer, tc.qname, tc.qtype, cfg.Timeout)
		t.Logf("bypass result: %+v", res)
		if res.Pass {
			t.Errorf("expected %s to FAIL when mock answers NOERROR+answer, got pass: %+v", tc.name, res)
		}
	}
}

func TestBypassDNSAllowNonFakeIP(t *testing.T) {
	udpPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		servePermissiveMockDNS(udpPC, [4]byte{93, 184, 216, 34})
	}()
	defer func() {
		if cErr := udpPC.Close(); cErr != nil {
			t.Errorf("close udp: %v", cErr)
		}
		<-done
	}()

	res := checkDNSFakeIP(
		context.Background(),
		"dns_allow_a_control",
		"udp",
		udpPC.LocalAddr().String(),
		"allow.example.test",
		netip.MustParsePrefix("198.18.0.0/15"),
		nil,
		2*time.Second,
	)
	t.Logf("bypass result: %+v", res)
	if res.Pass {
		t.Fatalf("expected dns_allow_a_control to FAIL for non-fake IP 93.184.216.34, got pass: %+v", res)
	}
	if !strings.Contains(res.Got, "93.184.216.34") {
		t.Fatalf("expected got to include returned IP, got %q", res.Got)
	}
}

func TestBypassPort80Returns200(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, wErr := io.WriteString(w, "metadata leaked"); wErr != nil {
			return
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if sErr := srv.Serve(ln); sErr != nil && sErr != http.ErrServerClosed {
			return
		}
	}()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if sErr := srv.Shutdown(shutCtx); sErr != nil {
			t.Errorf("shutdown http: %v", sErr)
		}
	}()

	res := checkUnreachableHTTP(context.Background(), "unreachable_metadata", ln.Addr().String(), "169.254.169.254", 2*time.Second)
	t.Logf("bypass result: %+v", res)
	if res.Pass {
		t.Fatalf("expected port-80 check to FAIL on HTTP 200, got pass: %+v", res)
	}
	if res.Got != "HTTP 200" {
		t.Fatalf("expected Got == HTTP 200, got %q", res.Got)
	}

	// Positive control: a mock returning gateway's 403 passes.
	denyLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen deny tcp: %v", err)
	}
	denyMux := http.NewServeMux()
	denyMux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "egress denied: ip-literal-host", http.StatusForbidden)
	})
	denySrv := &http.Server{Handler: denyMux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if sErr := denySrv.Serve(denyLn); sErr != nil && sErr != http.ErrServerClosed {
			return
		}
	}()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if sErr := denySrv.Shutdown(shutCtx); sErr != nil {
			t.Errorf("shutdown deny http: %v", sErr)
		}
	}()

	okRes := checkUnreachableHTTP(context.Background(), "unreachable_metadata", denyLn.Addr().String(), "169.254.169.254", 2*time.Second)
	if !okRes.Pass {
		t.Fatalf("expected gateway 403 to PASS port-80 unreachable check, got: %+v", okRes)
	}
}

func servePermissiveMockDNS(pc net.PacketConn, aIP [4]byte) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 12 {
			continue
		}
		pkt := buf[:n]
		_, next, err := decodeMockQName(pkt, 12)
		if err != nil || next+4 > len(pkt) {
			continue
		}
		qtype := binary.BigEndian.Uint16(pkt[next : next+2])
		resp := make([]byte, len(pkt))
		copy(resp, pkt)
		binary.BigEndian.PutUint16(resp[2:4], 0x8180) // QR=1, NOERROR
		binary.BigEndian.PutUint16(resp[6:8], 1)      // ANCOUNT=1
		var rdata []byte
		if qtype == qtypeA {
			rdata = aIP[:]
		} else {
			rdata = []byte{0x04, 'b', 'y', 'p', 's'}
		}
		rr := []byte{
			0xc0, 0x0c,
			byte(qtype >> 8), byte(qtype),
			0x00, 0x01,
			0x00, 0x00, 0x00, 0x3c,
			byte(len(rdata) >> 8), byte(len(rdata)),
		}
		resp = append(resp, rr...)
		resp = append(resp, rdata...)
		if _, wErr := pc.WriteTo(resp, addr); wErr != nil {
			return
		}
	}
}
