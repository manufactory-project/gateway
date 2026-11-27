package dns_test

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"go.uber.org/goleak"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/config"
	gwdns "github.com/manufactory-project/gateway/internal/dns"
	"github.com/manufactory-project/gateway/internal/policy"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func freePort(t *testing.T, ip string) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp4", ip+":0")
	if err != nil {
		t.Fatalf("pick free port on %s: %v", ip, err)
	}
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected addr type %T", ln.Addr())
	}
	port := uint16(tcpAddr.Port)
	if err := ln.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}
	return port
}

func queryDNS(t *testing.T, netProto, addr, name string, qtype uint16) *mdns.Msg {
	t.Helper()
	c := &mdns.Client{Net: netProto, Timeout: 2 * time.Second}
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(name), qtype)
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("DNS %s query %s %s: %v", netProto, name, mdns.TypeToString[qtype], err)
	}
	return r
}

func TestFakeIPDNSWireInvariantsAndFailClosedAudit(t *testing.T) {
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	dnsPort := freePort(t, "127.0.11.1")

	cfgYAML := `
ca:
  cert_path: /tmp/ca.crt
  key_path: /tmp/ca.key
audit:
  dir: ` + auditDir + `
  max_file_bytes: 200
dns:
  fake_cidr: 198.18.0.0/15
  ttl_seconds: 60
links:
  - name: sbx0
    principal: worker-claude
    subnet: 127.0.11.0/28
    gateway_ip: 127.0.11.1
    dns_port: ` + strconv.Itoa(int(dnsPort)) + `
    https_port: 18443
    http_port: 18080
rules:
  - id: allow-anthropic
    principal: worker-claude
    effect: allow
    hosts: [api.anthropic.com, "*.allowed.example"]
    ports: [443]
`
	cfgPath := filepath.Join(dir, "gatewayd.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	store, err := config.NewStore(cfgPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	aw, err := audit.NewWriter(audit.Options{
		Dir:          auditDir,
		MaxFileBytes: 200,
	})
	if err != nil {
		t.Fatalf("audit.NewWriter: %v", err)
	}
	t.Cleanup(func() {
		if err := aw.Close(); err != nil {
			t.Errorf("audit close: %v", err)
		}
	})

	alloc, err := gwdns.NewAllocator(store.Current().Config.FakePrefix)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	ev := policy.NewEvaluator(store)
	srv, err := gwdns.NewServer(gwdns.ServerOptions{
		Link:      store.Current().Config.Links[0],
		Store:     store,
		Evaluator: ev,
		Audit:     aw,
		Allocator: alloc,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})

	fakePrefix := netip.MustParsePrefix("198.18.0.0/15")

	// Positive control: allowlisted exact host gets stable fake IPv4 over both UDP and TCP.
	rUDP := queryDNS(t, "udp", srv.UDPAddr(), "api.anthropic.com", mdns.TypeA)
	if rUDP.Rcode != mdns.RcodeSuccess || len(rUDP.Answer) != 1 {
		t.Fatalf("UDP A api.anthropic.com: rcode=%d answers=%d", rUDP.Rcode, len(rUDP.Answer))
	}
	aRec, ok := rUDP.Answer[0].(*mdns.A)
	if !ok {
		t.Fatalf("expected *dns.A, got %T", rUDP.Answer[0])
	}
	ip1, ok := netip.AddrFromSlice(aRec.A.To4())
	if !ok || !fakePrefix.Contains(ip1) {
		t.Fatalf("fake IP %v outside %s", aRec.A, fakePrefix)
	}

	rTCP := queryDNS(t, "tcp", srv.TCPAddr(), "api.anthropic.com", mdns.TypeA)
	if rTCP.Rcode != mdns.RcodeSuccess || len(rTCP.Answer) != 1 {
		t.Fatalf("TCP A api.anthropic.com: rcode=%d answers=%d", rTCP.Rcode, len(rTCP.Answer))
	}
	aTCP, ok := rTCP.Answer[0].(*mdns.A)
	if !ok {
		t.Fatalf("expected *dns.A over TCP, got %T", rTCP.Answer[0])
	}
	if !aTCP.A.Equal(aRec.A) {
		t.Fatalf("TCP fake IP %v != UDP fake IP %v", aTCP.A, aRec.A)
	}

	// Positive control: NODATA (NOERROR, 0 answers) for AAAA, HTTPS, SVCB on allowlisted host.
	for _, qt := range []uint16{mdns.TypeAAAA, mdns.TypeHTTPS, mdns.TypeSVCB} {
		r := queryDNS(t, "udp", srv.UDPAddr(), "api.anthropic.com", qt)
		if r.Rcode != mdns.RcodeSuccess || len(r.Answer) != 0 {
			t.Fatalf("allowlisted %s: got rcode=%d answers=%d, want NOERROR/0", mdns.TypeToString[qt], r.Rcode, len(r.Answer))
		}
	}

	// Containment: TXT, MX, NS, SRV, CNAME refused BOTH inside allowlisted zones AND outside.
	for _, qt := range []uint16{mdns.TypeTXT, mdns.TypeMX, mdns.TypeNS, mdns.TypeSRV, mdns.TypeCNAME} {
		for _, host := range []string{"api.anthropic.com", "sub.allowed.example", "evil.exfil.example"} {
			r := queryDNS(t, "udp", srv.UDPAddr(), host, qt)
			if r.Rcode != mdns.RcodeRefused || len(r.Answer) != 0 {
				t.Fatalf("%s %s: got rcode=%d answers=%d, want REFUSED/0", host, mdns.TypeToString[qt], r.Rcode, len(r.Answer))
			}
		}
	}

	// Containment: non-allowlisted host refused for A and AAAA.
	for _, qt := range []uint16{mdns.TypeA, mdns.TypeAAAA} {
		r := queryDNS(t, "udp", srv.UDPAddr(), "blocked.example.com", qt)
		if r.Rcode != mdns.RcodeRefused || len(r.Answer) != 0 {
			t.Fatalf("blocked.example.com %s: got rcode=%d answers=%d, want REFUSED/0", mdns.TypeToString[qt], r.Rcode, len(r.Answer))
		}
	}

	// Audit completeness check: every query above produced an audit record.
	events, err := audit.Query(auditDir, audit.QueryOptions{})
	if err != nil {
		t.Fatalf("audit.Query: %v", err)
	}
	// 2 (A udp+tcp) + 3 (AAAA/HTTPS/SVCB) + 15 (5 qtypes * 3 hosts) + 2 (blocked A/AAAA) = 22.
	if len(events) != 22 {
		t.Fatalf("expected 22 audited DNS events, got %d", len(events))
	}

	// Containment: fail closed when audit sink becomes unwritable (must NOT return an A answer).
	if err := os.RemoveAll(auditDir); err != nil {
		t.Fatalf("remove auditDir: %v", err)
	}
	if err := os.WriteFile(auditDir, []byte("blocked"), 0o600); err != nil {
		t.Fatalf("replace auditDir with file: %v", err)
	}
	// Force rotation by querying until the 200-byte segment triggers openSegmentLocked on broken auditDir.
	rFail := queryDNS(t, "udp", srv.UDPAddr(), "api.anthropic.com", mdns.TypeA)
	if rFail.Rcode == mdns.RcodeSuccess {
		// One more query if previous line hadn't crossed 200B boundary yet.
		rFail = queryDNS(t, "udp", srv.UDPAddr(), "api.anthropic.com", mdns.TypeA)
	}
	if rFail.Rcode != mdns.RcodeServerFailure || len(rFail.Answer) != 0 {
		t.Fatalf("expected SERVFAIL with 0 answers on unwritable audit sink, got rcode=%d answers=%d", rFail.Rcode, len(rFail.Answer))
	}
}
