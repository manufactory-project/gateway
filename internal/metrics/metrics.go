// Package metrics exposes gatewayd's Prometheus /metrics endpoint on an explicit
// non-wildcard IP:port listener (NOW.md:38, 66).
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

// Collector owns gatewayd's isolated Prometheus registry and metric instruments.
type Collector struct {
	registry         *prometheus.Registry
	auditWriteErrors prometheus.Counter
	requestsTotal    *prometheus.CounterVec
	dnsQueriesTotal  *prometheus.CounterVec
	reloadsTotal     *prometheus.CounterVec
	revocationsTotal prometheus.Counter
}

// Options wires dynamic gauges into a Collector.
type Options struct {
	ActiveFlows  func() int
	ActiveGrants func() int
}

// NewCollector creates a dedicated Prometheus registry with all gatewayd metrics registered.
func NewCollector(opts Options) *Collector {
	reg := prometheus.NewRegistry()

	c := &Collector{
		registry: reg,
		auditWriteErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "gatewayd_audit_write_errors_total",
			Help: "Total number of failed fail-closed audit sink writes.",
		}),
		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatewayd_requests_total",
			Help: "Total HTTP/TLS/WebSocket requests handled by gatewayd.",
		}, []string{"principal", "effect", "status"}),
		dnsQueriesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatewayd_dns_queries_total",
			Help: "Total fake-IP DNS queries handled by gatewayd.",
		}, []string{"principal", "effect"}),
		reloadsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gatewayd_reloads_total",
			Help: "Total configuration reloads attempted by gatewayd.",
		}, []string{"result"}),
		revocationsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "gatewayd_revocations_total",
			Help: "Total live flows torn down by revocation or reload.",
		}),
	}

	reg.MustRegister(
		c.auditWriteErrors,
		c.requestsTotal,
		c.dnsQueriesTotal,
		c.reloadsTotal,
		c.revocationsTotal,
	)

	if opts.ActiveFlows != nil {
		reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "gatewayd_active_flows",
			Help: "Number of currently active in-flight flows.",
		}, func() float64 { return float64(opts.ActiveFlows()) }))
	}
	if opts.ActiveGrants != nil {
		reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "gatewayd_active_grants",
			Help: "Number of currently active in-memory TTL grants.",
		}, func() float64 { return float64(opts.ActiveGrants()) }))
	}
	return c
}

// IncAuditWriteError increments gatewayd_audit_write_errors_total.
func (c *Collector) IncAuditWriteError() {
	c.auditWriteErrors.Inc()
}

// ObserveRequest increments gatewayd_requests_total.
func (c *Collector) ObserveRequest(principal, effect string, status int) {
	c.requestsTotal.WithLabelValues(principal, effect, strconv.Itoa(status)).Inc()
}

// ObserveDNSQuery increments gatewayd_dns_queries_total.
func (c *Collector) ObserveDNSQuery(principal, effect string) {
	c.dnsQueriesTotal.WithLabelValues(principal, effect).Inc()
}

// ObserveReload increments gatewayd_reloads_total.
func (c *Collector) ObserveReload(ok bool) {
	if ok {
		c.reloadsTotal.WithLabelValues("ok").Inc()
		return
	}
	c.reloadsTotal.WithLabelValues("error").Inc()
}

// AddRevocations adds n to gatewayd_revocations_total.
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
	if err != nil || ip.IsUnspecified() {
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

// Addr returns the bound TCP address.
func (s *Server) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
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
