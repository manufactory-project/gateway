// SPDX-License-Identifier: AGPL-3.0-or-later

package dns_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/config"
	gwdns "github.com/manufactory-project/gateway/internal/dns"
	"github.com/manufactory-project/gateway/internal/policy"
)

// exchangeOn sends one query over an open DNS connection and returns the read error, if any.
func exchangeOn(c *mdns.Conn) error {
	if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	m := new(mdns.Msg)
	m.SetQuestion("api.example.com.", mdns.TypeA)
	if err := c.WriteMsg(m); err != nil {
		return err
	}
	_, err := c.ReadMsg()
	return err
}

func TestTCPConnectionsPerLinkAreCapped(t *testing.T) {
	dir := t.TempDir()
	ports := freePorts(t, "127.0.13.1", 3)
	addr := net.JoinHostPort("127.0.13.1", strconv.Itoa(int(ports[0])))
	cfgYAML := `
ca: {cert_path: /tmp/ca.crt, key_path: /tmp/ca.key}
audit: {dir: ` + filepath.Join(dir, "audit") + `}
dataplane:
  ready_file: /run/gateway-dataplane/dataplane.ready
  dhcp: {user: dnsmasq, lease_file: /var/lib/gateway/dnsmasq.leases}
http:
  max_conns_per_link: 2
links:
  - name: sbx0
    interface: t213
    ct_zone: 213
    route_table: 213
    principal: worker
    subnet: 127.0.13.0/28
    gateway_ip: 127.0.13.1
    dns_port: ` + strconv.Itoa(int(ports[0])) + `
    https_port: ` + strconv.Itoa(int(ports[1])) + `
    http_port: ` + strconv.Itoa(int(ports[2])) + `
rules:
  - id: allow
    principal: worker
    effect: allow
    hosts: [api.example.com]
`
	cfgPath := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	store, err := config.NewStore(cfgPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	aw, err := audit.NewWriter(audit.Options{Dir: filepath.Join(dir, "audit")})
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
	var rejected atomic.Int32
	srv, err := gwdns.NewServer(gwdns.ServerOptions{
		Link:      store.Current().Config.Links[0],
		Store:     store,
		Evaluator: policy.NewEvaluator(store),
		Audit:     aw,
		Allocator: alloc,
		OnConnRejected: func(link string) {
			if link == "sbx0" {
				rejected.Add(1)
			}
		},
		OnServeError: func(err error) { t.Errorf("serve: %v", err) },
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

	dial := func() *mdns.Conn {
		t.Helper()
		c, err := mdns.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() {
			if err := c.Close(); err != nil {
				t.Logf("close: %v", err)
			}
		})
		return c
	}

	// Positive control: connections up to the limit are answered and stay open.
	first, second := dial(), dial()
	for i, c := range []*mdns.Conn{first, second} {
		if err := exchangeOn(c); err != nil {
			t.Fatalf("connection %d within the limit: %v", i+1, err)
		}
	}
	if err := exchangeOn(dial()); err == nil {
		t.Fatal("a third TCP connection was answered with the link limit at 2")
	}
	if got := rejected.Load(); got != 1 {
		t.Fatalf("rejected connections reported = %d, want 1", got)
	}
	// UDP service is not affected by held TCP connections.
	if r := queryDNS(t, "udp", addr, "api.example.com", mdns.TypeA); r.Rcode != mdns.RcodeSuccess {
		t.Fatalf("UDP rcode with TCP full = %d, want NOERROR", r.Rcode)
	}

	// A closed connection frees its slot once the server has read the close.
	if err := first.Close(); err != nil {
		t.Fatalf("close first: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for err = exchangeOn(dial()); err != nil; err = exchangeOn(dial()) {
		if time.Now().After(deadline) {
			t.Fatalf("no connection accepted after a slot was released: %v", err)
		}
	}
}
