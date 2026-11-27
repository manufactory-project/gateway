// Package metrics exposes gateway's Prometheus /metrics endpoint on an explicit
// non-wildcard IP:port listener.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Collector owns gateway's isolated Prometheus registry and metric instruments.
type Collector struct {
	registry                  *prometheus.Registry
	auditWriteErrors          prometheus.Counter
	auditSizePrunedBytesTotal prometheus.Counter
	requestsTotal             *prometheus.CounterVec
	dnsQueriesTotal           *prometheus.CounterVec
	reloadsTotal              *prometheus.CounterVec
	revocationsTotal          prometheus.Counter
	connsRejectedTotal        *prometheus.CounterVec
}

// Options wires dynamic gauges into a Collector.
type Options struct {
	ActiveFlows  func() int
	ActiveGrants func() int
}

// NewCollector creates a dedicated Prometheus registry with all gateway metrics registered.
func NewCollector(opts Options) *Collector {
	reg := prometheus.NewRegistry()

	c := &Collector{
		registry: reg,
		auditWriteErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "gateway_audit_write_errors_total",
			Help: "Total number of failed fail-closed audit sink writes.",
		}),
		auditSizePrunedBytesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "gateway_audit_size_pruned_bytes_total",
			Help: "Total bytes removed from closed audit segments by max_total_bytes pruning.",
		}),
		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gateway_requests_total",
			Help: "Total HTTP/TLS/WebSocket requests handled by gateway.",
		}, []string{"principal", "effect", "status", "reason"}),
		dnsQueriesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gateway_dns_queries_total",
			Help: "Total fake-IP DNS queries handled by gateway.",
		}, []string{"principal", "effect"}),
		reloadsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gateway_reloads_total",
			Help: "Total configuration reloads attempted by gateway.",
		}, []string{"result"}),
		revocationsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "gateway_revocations_total",
			Help: "Total live flows torn down by revocation or reload.",
		}),
		connsRejectedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gateway_conns_rejected_total",
			Help: "Total guest connections closed because a link reached http.max_conns_per_link.",
		}, []string{"link"}),
	}

	reg.MustRegister(
		c.auditWriteErrors,
		c.auditSizePrunedBytesTotal,
		c.requestsTotal,
		c.dnsQueriesTotal,
		c.reloadsTotal,
		c.revocationsTotal,
		c.connsRejectedTotal,
	)

	if opts.ActiveFlows != nil {
		reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "gateway_active_flows",
			Help: "Number of currently active in-flight flows.",
		}, func() float64 { return float64(opts.ActiveFlows()) }))
	}
	if opts.ActiveGrants != nil {
		reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "gateway_active_grants",
			Help: "Number of currently active in-memory TTL grants.",
		}, func() float64 { return float64(opts.ActiveGrants()) }))
	}
	return c
}

// IncAuditWriteError increments gateway_audit_write_errors_total.
func (c *Collector) IncAuditWriteError() {
	c.auditWriteErrors.Inc()
}

// ObserveAuditSizePruned adds bytesRemoved to gateway_audit_size_pruned_bytes_total.
func (c *Collector) ObserveAuditSizePruned(bytesRemoved int64) {
	if bytesRemoved > 0 {
		c.auditSizePrunedBytesTotal.Add(float64(bytesRemoved))
	}
}

// IncConnRejected increments gateway_conns_rejected_total for link.
func (c *Collector) IncConnRejected(link string) {
	c.connsRejectedTotal.WithLabelValues(link).Inc()
}

// knownRequestReasons bounds the Prometheus reason label to a fixed set of
// deny and completion reason tokens so free-form text can never explode cardinality.
var knownRequestReasons = map[string]struct{}{
	"ok":                               {},
	"rule-allow":                       {},
	"grant-allow":                      {},
	"rule-deny":                        {},
	"default-deny":                     {},
	"port-denied":                      {},
	"invalid-host":                     {},
	"invalid-path":                     {},
	"missing-sni":                      {},
	"ip-literal-sni":                   {},
	"connect-forbidden":                {},
	"asterisk-target-forbidden":        {},
	"absolute-uri-forbidden":           {},
	"non-origin-form-target":           {},
	"escaped-path-separator":           {},
	"backslash-in-path":                {},
	"path-traversal":                   {},
	"non-canonical-path":               {},
	"h2-host-header":                   {},
	"missing-host":                     {},
	"host-port-mismatch":               {},
	"ip-literal-host":                  {},
	"missing-tls":                      {},
	"sni-host-mismatch":                {},
	"invalid-websocket-upgrade":        {},
	"upgrade-forbidden":                {},
	"websocket-not-allowed":            {},
	"websocket-upgrade-with-body":      {},
	"body-too-large":                   {},
	"secret-unresolved":                {},
	"build-request-failed":             {},
	"grant-revoked":                    {},
	"binding-rule-changed":             {},
	"audit-unavailable":                {},
	"revoked":                          {},
	"grant-expired":                    {},
	"reload":                           {},
	"client-canceled":                  {},
	"ws-egress-cap-exceeded":           {},
	"compressed-response-on-bound-host": {},
	"redaction-secret-unresolved":      {},
	"unexpected-101":                   {},
	"unexpected-101-non-websocket":     {},
	"upstream-error":                   {},
}

func boundedRequestReason(reason string) string {
	if _, ok := knownRequestReasons[reason]; ok {
		return reason
	}
	return "other"
}

// ObserveRequest increments gateway_requests_total with a bounded reason label.
func (c *Collector) ObserveRequest(principal, effect string, status int, reason string) {
	c.requestsTotal.WithLabelValues(principal, effect, strconv.Itoa(status), boundedRequestReason(reason)).Inc()
}

// ObserveDNSQuery increments gateway_dns_queries_total.
func (c *Collector) ObserveDNSQuery(principal, effect string) {
	c.dnsQueriesTotal.WithLabelValues(principal, effect).Inc()
}

// ObserveReload increments gateway_reloads_total.
func (c *Collector) ObserveReload(ok bool) {
	if ok {
		c.reloadsTotal.WithLabelValues("ok").Inc()
		return
	}
	c.reloadsTotal.WithLabelValues("error").Inc()
}

// AddRevocations adds n to gateway_revocations_total.
func (c *Collector) AddRevocations(n int) {
	if n > 0 {
		c.revocationsTotal.Add(float64(n))
	}
}

// Handler returns the HTTP handler serving Prometheus exposition format.
func (c *Collector) Handler() http.Handler {
	return promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{})
}

// Server serves /metrics over an explicit non-wildcard IP:port TCP listener.
type Server struct {
	listenAddr string
	collector  *Collector

	ln  net.Listener
	srv *http.Server
	wg  sync.WaitGroup
}

// NewServer validates listenAddr is an explicit IP:port (never wildcard) and constructs Server.
func NewServer(listenAddr string, collector *Collector) (*Server, error) {
	if collector == nil {
		return nil, errors.New("metrics: collector is required")
	}
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("metrics: invalid listen address %q: %w", listenAddr, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("metrics: wildcard or non-IP listen address %q is forbidden", listenAddr)
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() {
		return nil, fmt.Errorf("metrics: wildcard or non-IP listen address %q is forbidden", listenAddr)
	}
	return &Server{
		listenAddr: listenAddr,
		collector:  collector,
	}, nil
}

// Start binds the explicit TCP listener and serves /metrics.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("metrics: listen %s: %w", s.listenAddr, err)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", s.collector.Handler())

	s.ln = ln
	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return
		}
	}()
	return nil
}

// Shutdown gracefully stops the metrics HTTP server and waits for its goroutine.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	err := s.srv.Shutdown(ctx)
	s.wg.Wait()
	return err
}
