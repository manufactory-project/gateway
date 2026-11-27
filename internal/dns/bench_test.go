package dns_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/config"
	gwdns "github.com/manufactory-project/gateway/internal/dns"
	"github.com/manufactory-project/gateway/internal/policy"
)

func BenchmarkFakeIPDNSAnswer(b *testing.B) {
	dir := b.TempDir()
	auditDir := filepath.Join(dir, "audit")

	ln, err := net.Listen("tcp4", "127.0.39.1:0")
	if err != nil {
		b.Fatalf("listen free port: %v", err)
	}
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		b.Fatalf("unexpected addr type %T", ln.Addr())
	}
	dnsPort := uint16(tcpAddr.Port)
	if err := ln.Close(); err != nil {
		b.Fatalf("close probe listener: %v", err)
	}

	cfgYAML := fmt.Sprintf(`
ca:
  cert_path: /tmp/ca.crt
  key_path: /tmp/ca.key
audit:
  dir: %s
links:
  - name: sbx0
    principal: worker-bench
    subnet: 127.0.39.0/28
    gateway_ip: 127.0.39.1
    dns_port: %d
rules:
  - id: allow-bench
    principal: worker-bench
    effect: allow
    hosts: [api.anthropic.com]
    ports: [443]
`, auditDir, dnsPort)
	cfgPath := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		b.Fatalf("write config: %v", err)
	}
	store, err := config.NewStore(cfgPath)
	if err != nil {
		b.Fatalf("NewStore: %v", err)
	}
	aw, err := audit.NewWriter(audit.Options{Dir: auditDir})
	if err != nil {
		b.Fatalf("audit.NewWriter: %v", err)
	}
	b.Cleanup(func() {
		if err := aw.Close(); err != nil {
			b.Errorf("audit close: %v", err)
		}
	})
	alloc, err := gwdns.NewAllocator(store.Current().Config.FakePrefix)
	if err != nil {
		b.Fatalf("NewAllocator: %v", err)
	}
	srv, err := gwdns.NewServer(gwdns.ServerOptions{
		Link:      store.Current().Config.Links[0],
		Store:     store,
		Evaluator: policy.NewEvaluator(store),
		Audit:     aw,
		Allocator: alloc,
	})
	if err != nil {
		b.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		b.Fatalf("Start: %v", err)
	}
	b.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			b.Errorf("Shutdown: %v", err)
		}
	})

	dnsAddr := net.JoinHostPort("127.0.39.1", strconv.Itoa(int(dnsPort)))
	client := &mdns.Client{Net: "udp", Timeout: 2 * time.Second}
	conn, err := client.Dial(dnsAddr)
	if err != nil {
		b.Fatalf("dial dns: %v", err)
	}
	b.Cleanup(func() {
		if err := conn.Close(); err != nil {
			b.Errorf("close dns conn: %v", err)
		}
	})

	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn("api.anthropic.com"), mdns.TypeA)

	// Warm up fake-IP allocation.
	if r, _, err := client.ExchangeWithConn(msg, conn); err != nil || r.Rcode != mdns.RcodeSuccess {
		b.Fatalf("warmup exchange: r=%v err=%v", r, err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, _, err := client.ExchangeWithConn(msg, conn)
		if err != nil {
			b.Fatalf("ExchangeWithConn: %v", err)
		}
		if r.Rcode != mdns.RcodeSuccess || len(r.Answer) != 1 {
			b.Fatalf("unexpected DNS answer: rcode=%d answers=%d", r.Rcode, len(r.Answer))
		}
	}
	b.StopTimer()
}
