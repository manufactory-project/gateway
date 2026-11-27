package dns_test

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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

func freePorts(t *testing.T, ip string, n int) []uint16 {
	t.Helper()
	lns := make([]net.Listener, 0, n)
	ports := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp4", ip+":0")
		if err != nil {
			for _, prev := range lns {
				if cErr := prev.Close(); cErr != nil {
					t.Errorf("close prev listener: %v", cErr)
				}
			}
			t.Fatalf("freePorts %s[%d]: %v", ip, i, err)
		}
		tcpAddr, ok := ln.Addr().(*net.TCPAddr)
		if !ok {
			t.Fatalf("unexpected addr type %T", ln.Addr())
		}
		lns = append(lns, ln)
		ports = append(ports, uint16(tcpAddr.Port))
	}
	for _, ln := range lns {
		if err := ln.Close(); err != nil {
			t.Fatalf("close probe listener: %v", err)
		}
	}
	return ports
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
	ports := freePorts(t, "127.0.11.1", 3)
	dnsPort, httpsPort, httpPort := ports[0], ports[1], ports[2]
	dnsAddr := net.JoinHostPort("127.0.11.1", strconv.Itoa(int(dnsPort)))

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
    https_port: ` + strconv.Itoa(int(httpsPort)) + `
    http_port: ` + strconv.Itoa(int(httpPort)) + `
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
	rUDP := queryDNS(t, "udp", dnsAddr, "api.anthropic.com", mdns.TypeA)
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

	rTCP := queryDNS(t, "tcp", dnsAddr, "api.anthropic.com", mdns.TypeA)
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
		r := queryDNS(t, "udp", dnsAddr, "api.anthropic.com", qt)
		if r.Rcode != mdns.RcodeSuccess || len(r.Answer) != 0 {
			t.Fatalf("allowlisted %s: got rcode=%d answers=%d, want NOERROR/0", mdns.TypeToString[qt], r.Rcode, len(r.Answer))
		}
	}

	// Containment: TXT, MX, NS, SRV, CNAME refused BOTH inside allowlisted zones AND outside.
	for _, qt := range []uint16{mdns.TypeTXT, mdns.TypeMX, mdns.TypeNS, mdns.TypeSRV, mdns.TypeCNAME} {
		for _, host := range []string{"api.anthropic.com", "sub.allowed.example", "evil.exfil.example"} {
			r := queryDNS(t, "udp", dnsAddr, host, qt)
			if r.Rcode != mdns.RcodeRefused || len(r.Answer) != 0 {
				t.Fatalf("%s %s: got rcode=%d answers=%d, want REFUSED/0", host, mdns.TypeToString[qt], r.Rcode, len(r.Answer))
			}
		}
	}

	// Containment: non-allowlisted host refused for A and AAAA.
	for _, qt := range []uint16{mdns.TypeA, mdns.TypeAAAA} {
		r := queryDNS(t, "udp", dnsAddr, "blocked.example.com", qt)
		if r.Rcode != mdns.RcodeRefused || len(r.Answer) != 0 {
			t.Fatalf("blocked.example.com %s: got rcode=%d answers=%d, want REFUSED/0", mdns.TypeToString[qt], r.Rcode, len(r.Answer))
		}
	}

	// Containment (Item 4): len(Question) != 1 (0 and 2 questions) -> REFUSED and audited;
	// non-QUERY Opcode -> NOTIMP and audited; non-IN Class (CHAOS) -> REFUSED and audited.
	rawClient := &mdns.Client{Net: "udp", Timeout: 2 * time.Second}

	mZero := new(mdns.Msg)
	mZero.Id = mdns.Id()
	mZero.Opcode = mdns.OpcodeQuery
	rZero, _, err := rawClient.Exchange(mZero, dnsAddr)
	if err != nil || rZero.Rcode != mdns.RcodeRefused {
		t.Fatalf("0-question query: rcode=%v err=%v, want REFUSED", rZero, err)
	}

	mTwo := new(mdns.Msg)
	mTwo.Id = mdns.Id()
	mTwo.Opcode = mdns.OpcodeQuery
	mTwo.Question = []mdns.Question{
		{Name: "api.anthropic.com.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET},
		{Name: "api.anthropic.com.", Qtype: mdns.TypeAAAA, Qclass: mdns.ClassINET},
	}
	rTwo, _, err := rawClient.Exchange(mTwo, dnsAddr)
	if err != nil || rTwo.Rcode != mdns.RcodeRefused {
		t.Fatalf("2-question query: rcode=%v err=%v, want REFUSED", rTwo, err)
	}

	mUpdate := new(mdns.Msg)
	mUpdate.Id = mdns.Id()
	mUpdate.Opcode = mdns.OpcodeUpdate
	mUpdate.Question = []mdns.Question{{Name: "api.anthropic.com.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET}}
	rUpd, _, err := rawClient.Exchange(mUpdate, dnsAddr)
	if err != nil || rUpd.Rcode != mdns.RcodeNotImplemented {
		t.Fatalf("OpcodeUpdate query: rcode=%v err=%v, want NOTIMP", rUpd, err)
	}

	mChaos := new(mdns.Msg)
	mChaos.Id = mdns.Id()
	mChaos.Opcode = mdns.OpcodeQuery
	mChaos.Question = []mdns.Question{{Name: "api.anthropic.com.", Qtype: mdns.TypeA, Qclass: mdns.ClassCHAOS}}
	rChaos, _, err := rawClient.Exchange(mChaos, dnsAddr)
	if err != nil || rChaos.Rcode != mdns.RcodeRefused {
		t.Fatalf("ClassCHAOS query: rcode=%v err=%v, want REFUSED", rChaos, err)
	}

	// DNS response packet (QR=1) must NOT be answered, and must still be audited.
	mResp := new(mdns.Msg)
	mResp.Id = mdns.Id()
	mResp.Response = true
	mResp.Opcode = mdns.OpcodeQuery
	mResp.Question = []mdns.Question{{Name: "api.anthropic.com.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET}}
	rawRespPkt, err := mResp.Pack()
	if err != nil {
		t.Fatalf("pack QR=1 msg: %v", err)
	}
	rawUDP, err := net.Dial("udp4", dnsAddr)
	if err != nil {
		t.Fatalf("dial udp4 for QR=1: %v", err)
	}
	if _, err := rawUDP.Write(rawRespPkt); err != nil {
		if cErr := rawUDP.Close(); cErr != nil {
			t.Errorf("close rawUDP: %v", cErr)
		}
		t.Fatalf("write QR=1 packet: %v", err)
	}
	if err := rawUDP.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		if cErr := rawUDP.Close(); cErr != nil {
			t.Errorf("close rawUDP: %v", cErr)
		}
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var replyBuf [512]byte
	if n, rErr := rawUDP.Read(replyBuf[:]); rErr == nil {
		if cErr := rawUDP.Close(); cErr != nil {
			t.Errorf("close rawUDP: %v", cErr)
		}
		t.Fatalf("expected DNS server to ignore QR=1 response packet, got %d-byte reply", n)
	} else if ne, ok := rErr.(net.Error); !ok || !ne.Timeout() {
		if cErr := rawUDP.Close(); cErr != nil {
			t.Errorf("close rawUDP: %v", cErr)
		}
		t.Fatalf("unexpected read error waiting on ignored QR=1 packet: %v", rErr)
	}
	if err := rawUDP.Close(); err != nil {
		t.Fatalf("close rawUDP: %v", err)
	}

	// Audit completeness check: every packet above (incl. malformed/opcode/class/QR=1) produced an audit record.
	var events []audit.Event
	var sawQRIgnored bool
	deadline := time.Now().Add(time.Second)
	for {
		events = readAuditEvents(t, auditDir)
		for _, ev := range events {
			if ev.Reason == "response-packet-ignored" && ev.Effect == audit.EffectDeny {
				sawQRIgnored = true
				break
			}
		}
		if sawQRIgnored && len(events) == 27 {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// 2 (A udp+tcp) + 3 (AAAA/HTTPS/SVCB) + 15 (5 qtypes * 3 hosts) + 2 (blocked A/AAAA) + 5 (0q, 2q, update, chaos, QR=1) = 27.
	if len(events) != 27 || !sawQRIgnored {
		t.Fatalf("expected 27 audited DNS events including response-packet-ignored, got len=%d sawQRIgnored=%v", len(events), sawQRIgnored)
	}

	// Containment: fail closed when audit sink becomes unwritable (must NOT return an A answer).
	if err := os.RemoveAll(auditDir); err != nil {
		t.Fatalf("remove auditDir: %v", err)
	}
	if err := os.WriteFile(auditDir, []byte("blocked"), 0o600); err != nil {
		t.Fatalf("replace auditDir with file: %v", err)
	}
	// Force rotation by querying until the 200-byte segment triggers openSegmentLocked on broken auditDir.
	rFail := queryDNS(t, "udp", dnsAddr, "api.anthropic.com", mdns.TypeA)
	if rFail.Rcode == mdns.RcodeSuccess {
		// One more query if previous line hadn't crossed 200B boundary yet.
		rFail = queryDNS(t, "udp", dnsAddr, "api.anthropic.com", mdns.TypeA)
	}
	if rFail.Rcode != mdns.RcodeServerFailure || len(rFail.Answer) != 0 {
		t.Fatalf("expected SERVFAIL with 0 answers on unwritable audit sink, got rcode=%d answers=%d", rFail.Rcode, len(rFail.Answer))
	}
}

func readAuditEvents(t *testing.T, dir string) []audit.Event {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var out []audit.Event
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("ReadFile %s: %v", name, err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var ev audit.Event
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				t.Fatalf("unmarshal %s: %v", name, err)
			}
			out = append(out, ev)
		}
	}
	return out
}
