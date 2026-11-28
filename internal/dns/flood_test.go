// SPDX-License-Identifier: AGPL-3.0-only

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

const (
	floodQueryRate = 5
	floodPackets   = 100
	// A query rate of 5/s refills well under one token per test run; the slack
	// keeps a slow -race run from flaking without letting an unbounded flood pass.
	floodAnswerSlack = 5
)

// floodGateway runs two links that share one store and one audit writer, like the
// daemon does, with dns.max_queries_per_second at floodQueryRate.
type floodGateway struct {
	addr    [2]string
	auditor string
	limited [2]chan struct{}
	servers [2]*gwdns.Server
	drops   [2]atomic.Int32
}

func newFloodGateway(t *testing.T, ipBase string) *floodGateway {
	t.Helper()
	dir := t.TempDir()
	gw := &floodGateway{auditor: filepath.Join(dir, "audit")}
	ips := [2]string{ipBase + ".1", ipBase + ".17"}
	var ports [2][]uint16
	for i := range ips {
		ports[i] = freePorts(t, ips[i], 3)
		gw.addr[i] = net.JoinHostPort(ips[i], strconv.Itoa(int(ports[i][0])))
	}
	cfgYAML := `
ca: {cert_path: /tmp/ca.crt, key_path: /tmp/ca.key}
audit: {dir: ` + gw.auditor + `}
dns: {max_queries_per_second: ` + strconv.Itoa(floodQueryRate) + `}
dataplane:
  ready_file: /run/gateway-dataplane/dataplane.ready
  dhcp: {user: dnsmasq, lease_file: /var/lib/gateway/dnsmasq.leases}
links:
`
	for i := range ips {
		n := strconv.Itoa(i)
		cfgYAML += `  - name: sbx` + n + `
    interface: t` + n + `
    ct_zone: ` + strconv.Itoa(300+i) + `
    route_table: ` + strconv.Itoa(300+i) + `
    principal: worker` + n + `
    subnet: ` + ips[i] + `/28
    gateway_ip: ` + ips[i] + `
    dns_port: ` + strconv.Itoa(int(ports[i][0])) + `
    https_port: ` + strconv.Itoa(int(ports[i][1])) + `
    http_port: ` + strconv.Itoa(int(ports[i][2])) + `
`
	}
	cfgYAML += `rules:
  - {id: allow0, principal: worker0, effect: allow, hosts: [api.example.com]}
  - {id: allow1, principal: worker1, effect: allow, hosts: [api.example.com]}
`
	cfgPath := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	store, err := config.NewStore(cfgPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	aw, err := audit.NewWriter(audit.Options{Dir: gw.auditor})
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
	for i := range ips {
		gw.limited[i] = make(chan struct{}, floodPackets*2)
		srv, err := gwdns.NewServer(gwdns.ServerOptions{
			Link:      store.Current().Config.Links[i],
			Store:     store,
			Evaluator: policy.NewEvaluator(store),
			Audit:     aw,
			Allocator: alloc,
			OnLimited: func(_, reason string) {
				if reason != gwdns.ReasonRateLimited {
					t.Errorf("limit reason = %q, want %q", reason, gwdns.ReasonRateLimited)
				}
				gw.drops[i].Add(1)
				gw.limited[i] <- struct{}{}
			},
			OnServeError: func(err error) { t.Errorf("serve: %v", err) },
		})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		if err := srv.Start(); err != nil {
			t.Fatalf("Start: %v", err)
		}
		gw.servers[i] = srv
	}
	return gw
}

// shutdown stops both servers, which flushes the pending rate-limit summaries.
func (g *floodGateway) shutdown(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, srv := range g.servers {
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	}
}

// querier sends queries one at a time over one connection and learns the fate of
// each from the server: an answer on the wire, or an OnLimited call. Exactly one
// of the two happens per query, so no sleep or timeout is needed.
type querier struct {
	conn    *mdns.Conn
	replies chan *mdns.Msg
	limited chan struct{}
}

func (g *floodGateway) dial(t *testing.T, link int, proto string) *querier {
	t.Helper()
	c, err := mdns.Dial(proto, g.addr[link])
	if err != nil {
		t.Fatalf("dial %s: %v", proto, err)
	}
	q := &querier{conn: c, replies: make(chan *mdns.Msg, floodPackets), limited: g.limited[link]}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			m, err := c.ReadMsg()
			if err != nil {
				return
			}
			q.replies <- m
		}
	}()
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Logf("close: %v", err)
		}
		<-done
	})
	return q
}

// ask returns the answer's rcode, or -1 when the server dropped the query.
func (q *querier) ask(t *testing.T) int {
	t.Helper()
	m := new(mdns.Msg)
	m.SetQuestion("api.example.com.", mdns.TypeA)
	if err := q.conn.WriteMsg(m); err != nil {
		t.Fatalf("write query: %v", err)
	}
	select {
	case r := <-q.replies:
		return r.Rcode
	case <-q.limited:
		return -1
	}
}

func TestDNSFloodIsRateLimitedPerLink(t *testing.T) {
	for _, tc := range []struct{ proto, ipBase string }{
		{"udp", "127.0.14"},
		{"tcp", "127.0.15"},
	} {
		t.Run(tc.proto, func(t *testing.T) {
			gw := newFloodGateway(t, tc.ipBase)
			flooder := gw.dial(t, 0, tc.proto)
			victim := gw.dial(t, 1, tc.proto)

			answered := 0
			for i := range floodPackets {
				if flooder.ask(t) == mdns.RcodeSuccess {
					answered++
				}
				// Positive control and isolation: another link's queries within its
				// own budget are answered while link 0 is flooded.
				if i%40 == 0 {
					if rc := victim.ask(t); rc != mdns.RcodeSuccess {
						t.Fatalf("victim link query %d during flood: rcode %d, want NOERROR", i, rc)
					}
				}
			}
			if answered < floodQueryRate {
				t.Fatalf("flooding link answered %d queries, want at least its budget of %d", answered, floodQueryRate)
			}
			if answered > floodQueryRate+floodAnswerSlack {
				t.Fatalf("flooding link answered %d of %d queries; budget is %d/s", answered, floodPackets, floodQueryRate)
			}
			if dropped := int(gw.drops[0].Load()); dropped != floodPackets-answered {
				t.Fatalf("dropped = %d, want %d", dropped, floodPackets-answered)
			}
			if gw.drops[1].Load() != 0 {
				t.Fatalf("victim link was limited %d times, want 0", gw.drops[1].Load())
			}

			gw.shutdown(t)
			var queries, summaries, summed int
			for _, ev := range readAuditEvents(t, gw.auditor) {
				if ev.Link != "sbx0" {
					continue
				}
				switch ev.Reason {
				case gwdns.ReasonRateLimited:
					summaries++
					summed += int(ev.Count)
				default:
					queries++
				}
			}
			// The flood cost one audit record per answered query plus one summary,
			// not one record per packet; the summary accounts for every dropped one.
			if queries != answered {
				t.Fatalf("audited %d queries for link 0, want %d (one per answered query)", queries, answered)
			}
			if summaries != 1 || summed != floodPackets-answered {
				t.Fatalf("summaries = %d covering %d queries, want 1 covering %d", summaries, summed, floodPackets-answered)
			}
		})
	}
}
