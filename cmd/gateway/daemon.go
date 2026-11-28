// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/manufactory-project/gateway/internal/admin"
	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/ca"
	"github.com/manufactory-project/gateway/internal/config"
	gwdns "github.com/manufactory-project/gateway/internal/dns"
	"github.com/manufactory-project/gateway/internal/metrics"
	"github.com/manufactory-project/gateway/internal/netguard"
	"github.com/manufactory-project/gateway/internal/netsetup"
	"github.com/manufactory-project/gateway/internal/policy"
	"github.com/manufactory-project/gateway/internal/proxy"
)

func runNetsetup(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("gateway netsetup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to gateway YAML config")
	dryRun := fs.Bool("dry-run", false, "print generated nftables, sysctls, ip commands, and dnsmasq config without applying")
	release := fs.String("release", "", "stop blocking an interface that was removed from links")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: gateway netsetup --config <path> [--dry-run | --release <interface>] (unexpected arguments: %s)", strings.Join(fs.Args(), " "))
	}
	if *cfgPath == "" {
		return errors.New("netsetup: --config is required")
	}
	if *dryRun && *release != "" {
		return errors.New("netsetup: --dry-run and --release cannot be combined")
	}

	cfg, _, err := config.LoadFile(*cfgPath)
	if err != nil {
		return err
	}

	if *dryRun {
		retired, cleanup, err := netsetup.RetiredPlan(cfg)
		if err != nil {
			return err
		}
		nft, err := netsetup.RenderNftables(cfg, retired...)
		if err != nil {
			return err
		}
		dm, err := netsetup.RenderDnsmasq(cfg)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(stdout, "# --- nftables ---"); err != nil {
			return err
		}
		if _, err := fmt.Fprint(stdout, nft); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(stdout, "# --- sysctls ---"); err != nil {
			return err
		}
		for _, sc := range netsetup.DesiredSysctls(cfg) {
			if _, err := fmt.Fprintf(stdout, "%s = %s\n", sc.Key, sc.Value); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(stdout, "# --- ip commands ---"); err != nil {
			return err
		}
		for _, cmd := range append(cleanup, netsetup.IPCommands(cfg)...) {
			if _, err := fmt.Fprintln(stdout, strings.Join(cmd.Args, " ")); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(stdout, "# --- dnsmasq ---"); err != nil {
			return err
		}
		if _, err := fmt.Fprint(stdout, dm); err != nil {
			return err
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if *release != "" {
		return netsetup.Release(ctx, cfg, *release)
	}
	return netsetup.Apply(ctx, cfg)
}

func runDaemon(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("gateway run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to gateway YAML config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: gateway run --config <path> (unexpected arguments: %s)", strings.Join(fs.Args(), " "))
	}
	if *cfgPath == "" {
		return errors.New("--config is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serveDaemon(ctx, *cfgPath, "/proc/sys", stdout, stderr)
}

type daemonRuntime struct {
	dnsServers   []*gwdns.Server
	proxyServers []*proxy.Server
	adminSrv     *admin.Server
	metricsSrv   *metrics.Server
	auditWriter  *audit.Writer
	serveErrCh   chan error
}

func newDaemonRuntime(auditWriter *audit.Writer) *daemonRuntime {
	return &daemonRuntime{
		auditWriter: auditWriter,
		serveErrCh:  make(chan error, 1),
	}
}

func (rt *daemonRuntime) reportServeErr(err error) {
	select {
	case rt.serveErrCh <- err:
	default:
	}
}

func (rt *daemonRuntime) shutdownAll() error {
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var errs error
	if rt.adminSrv != nil {
		errs = errors.Join(errs, rt.adminSrv.Shutdown(shutCtx))
	}
	if rt.metricsSrv != nil {
		errs = errors.Join(errs, rt.metricsSrv.Shutdown(shutCtx))
	}
	for _, ps := range rt.proxyServers {
		errs = errors.Join(errs, ps.Shutdown(shutCtx))
	}
	for _, ds := range rt.dnsServers {
		errs = errors.Join(errs, ds.Shutdown(shutCtx))
	}
	if rt.auditWriter != nil {
		errs = errors.Join(errs, rt.auditWriter.Close())
	}
	return errs
}

func verifyStartupDataplane(cfg *config.Config, procSysRoot string) error {
	// Startup dataplane checks (unprivileged; zero CAP_NET_ADMIN required).
	if err := netsetup.VerifySysctls(procSysRoot, cfg); err != nil {
		return fmt.Errorf("startup sysctl check failed: %w", err)
	}
	if _, err := os.Stat(cfg.Dataplane.ReadyFile); err != nil {
		return fmt.Errorf("dataplane ready_file %s missing (run ExecStartPre=+ gateway netsetup first): %w", cfg.Dataplane.ReadyFile, err)
	}
	return nil
}

func (rt *daemonRuntime) startLinks(
	cfg *config.Config,
	store *config.Store,
	eval *policy.Evaluator,
	alloc *gwdns.Allocator,
	leaves *ca.LeafCache,
	dialer *netguard.Dialer,
	flows *proxy.FlowRegistry,
	collector *metrics.Collector,
	onServeErr func(error),
) error {
	for _, link := range cfg.Links {
		ds, err := gwdns.NewServer(gwdns.ServerOptions{
			Link:           link,
			Store:          store,
			Evaluator:      eval,
			Audit:          rt.auditWriter,
			Allocator:      alloc,
			OnQuery:        collector.ObserveDNSQuery,
			OnConnRejected: collector.IncConnRejected,
			OnServeError:   onServeErr,
		})
		if err != nil {
			return err
		}
		if err := ds.Start(); err != nil {
			return err
		}
		rt.dnsServers = append(rt.dnsServers, ds)

		ps, err := proxy.NewServer(proxy.Options{
			Link:           link,
			Store:          store,
			Evaluator:      eval,
			Audit:          rt.auditWriter,
			Leaves:         leaves,
			Dialer:         dialer,
			Flows:          flows,
			OnRequest:      collector.ObserveRequest,
			OnConnRejected: collector.IncConnRejected,
			OnServeError:   onServeErr,
		})
		if err != nil {
			return err
		}
		if err := ps.Start(); err != nil {
			return err
		}
		rt.proxyServers = append(rt.proxyServers, ps)
	}
	return nil
}

func (rt *daemonRuntime) startControl(cfg *config.Config, store *config.Store, flows *proxy.FlowRegistry, collector *metrics.Collector, onServeErr func(error)) error {
	if cfg.Admin.Socket != "" {
		srv, err := admin.NewServer(admin.Options{
			SocketPath:   cfg.Admin.Socket,
			SocketGroup:  cfg.Admin.SocketGroup,
			Store:        store,
			Flows:        adminFlowAdapter{flows: flows},
			Audit:        rt.auditWriter,
			Metrics:      collector,
			OnServeError: onServeErr,
		})
		if err != nil {
			return err
		}
		if err := srv.Start(); err != nil {
			return err
		}
		rt.adminSrv = srv
	}
	if cfg.Metrics.Listen != "" {
		srv, err := metrics.NewServer(cfg.Metrics.Listen, collector, onServeErr)
		if err != nil {
			return err
		}
		if err := srv.Start(); err != nil {
			return err
		}
		rt.metricsSrv = srv
	}
	return nil
}

func logf(w io.Writer, format string, args ...any) {
	// Diagnostic stderr writes are best-effort; nothing actionable if stderr is closed.
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		return
	}
}

func auditBestEffort(w *audit.Writer, ev audit.Event) {
	// WriteSync already notifies OnWriteError on sink failure.
	if err := w.WriteSync(ev); err != nil {
		return
	}
}

func handleSIGHUPReload(snap *config.Snapshot, revokedFlows int, reloadErr error, collector *metrics.Collector, auditWriter *audit.Writer, stderr io.Writer) {
	if reloadErr != nil {
		collector.ObserveReload(false)
		if aErr := auditWriter.WriteSync(audit.Event{
			Kind:   audit.KindLifecycle,
			Reason: "sighup-reload-failed",
			Error:  reloadErr.Error(),
		}); aErr != nil {
			logf(stderr, "gateway: SIGHUP reload failed (audit error: %v): %v\n", aErr, reloadErr)
			return
		}
		logf(stderr, "gateway: SIGHUP reload failed (keeping prior config): %v\n", reloadErr)
		return
	}
	collector.ObserveReload(true)
	auditBestEffort(auditWriter, audit.Event{
		Kind:         audit.KindLifecycle,
		Reason:       "sighup-reload",
		ConfigHash:   snap.Hash,
		RevokedFlows: &revokedFlows,
	})
}

func serveDaemon(ctx context.Context, cfgPath, procSysRoot string, stdout, stderr io.Writer) error {
	store, err := config.NewStore(cfgPath)
	if err != nil {
		return err
	}
	cfg := store.Current().Config
	if err := verifyStartupDataplane(cfg, procSysRoot); err != nil {
		return err
	}
	mitmCA, err := ca.Load(cfg.CA.CertPath, cfg.CA.KeyPath)
	if err != nil {
		return err
	}

	flows := proxy.NewFlowRegistry()
	collector := metrics.NewCollector(metrics.Options{
		ActiveFlows:  flows.Count,
		ActiveGrants: func() int { return len(store.ActiveGrants()) },
	})
	flows.SetOnRevoke(collector.AddRevocations)

	var auditStdout io.Writer
	if cfg.Audit.StdoutJSON {
		auditStdout = stdout
	}
	auditWriter, err := audit.NewWriter(audit.Options{
		Dir:           cfg.Audit.Dir,
		RetainDays:    cfg.Audit.RetainDays,
		MaxFileBytes:  cfg.Audit.MaxFileBytes,
		MaxTotalBytes: cfg.Audit.MaxTotalBytes,
		Stdout:        auditStdout,
		Diag:          stderr,
		OnWriteError:  collector.IncAuditWriteError,
		OnSizePrune:   collector.ObserveAuditSizePruned,
	})
	if err != nil {
		return err
	}

	rt := newDaemonRuntime(auditWriter)
	alloc, err := gwdns.NewAllocator(cfg.FakePrefix)
	if err != nil {
		return errors.Join(err, rt.shutdownAll())
	}
	eval := policy.NewEvaluator(store)
	leaves := ca.NewLeafCache(mitmCA)
	dialer := netguard.NewDialer(netguard.Options{Store: store})

	if err := rt.startLinks(cfg, store, eval, alloc, leaves, dialer, flows, collector, rt.reportServeErr); err != nil {
		return errors.Join(err, rt.shutdownAll())
	}
	registerDaemonCallbacks(store, eval, flows, rt.proxyServers, auditWriter, stderr)
	if err := rt.startControl(cfg, store, flows, collector, rt.reportServeErr); err != nil {
		return errors.Join(err, rt.shutdownAll())
	}
	if err := auditWriter.WriteSync(audit.Event{
		Kind:       audit.KindLifecycle,
		Reason:     "started",
		ConfigHash: store.Current().Hash,
	}); err != nil {
		return errors.Join(err, rt.shutdownAll())
	}

	runCtx, runCancel := context.WithCancel(ctx)
	var bgWG sync.WaitGroup
	bgWG.Add(2)
	go func() {
		defer bgWG.Done()
		store.RunGrantPruner(runCtx, 50*time.Millisecond)
	}()
	go func() {
		defer bgWG.Done()
		store.WatchSIGHUP(runCtx, func(snap *config.Snapshot, _ []string, revokedFlows int, reloadErr error) {
			handleSIGHUPReload(snap, revokedFlows, reloadErr, collector, auditWriter, stderr)
		})
	}()

	return rt.waitAndShutdown(ctx, runCancel, &bgWG, stderr)
}

func (rt *daemonRuntime) waitAndShutdown(
	ctx context.Context,
	runCancel context.CancelFunc,
	bgWG *sync.WaitGroup,
	stderr io.Writer,
) error {
	var listenerErr error
	select {
	case <-ctx.Done():
	case listenerErr = <-rt.serveErrCh:
		logf(stderr, "gateway: fatal listener error: %v\n", listenerErr)
		auditBestEffort(rt.auditWriter, audit.Event{
			Kind:   audit.KindLifecycle,
			Reason: "listener-error",
			Error:  listenerErr.Error(),
		})
	}
	runCancel()
	bgWG.Wait()

	if listenerErr != nil {
		return errors.Join(listenerErr, rt.shutdownAll())
	}
	if aErr := rt.auditWriter.WriteSync(audit.Event{
		Kind:   audit.KindLifecycle,
		Reason: "stopped",
	}); aErr != nil {
		logf(stderr, "gateway: stopped audit write failed: %v\n", aErr)
	}
	return rt.shutdownAll()
}

func registerDaemonCallbacks(store *config.Store, eval *policy.Evaluator, flows *proxy.FlowRegistry, servers []*proxy.Server, auditWriter *audit.Writer, stderr io.Writer) {
	registerFlowLifecycleCallbacks(store, eval, flows, servers)
	registerGrantExpiredAudit(store, auditWriter, stderr)
}

func registerFlowLifecycleCallbacks(store *config.Store, eval *policy.Evaluator, flows *proxy.FlowRegistry, servers []*proxy.Server) {
	store.OnReload(func(_, _ *config.Snapshot, wipedGrantIDs []string) int {
		n := proxy.RevokeReloadedFlows(flows, eval, wipedGrantIDs)
		for _, ps := range servers {
			ps.CloseIdleConnections()
		}
		return n
	})
	store.OnGrantExpired(func(g config.Grant) {
		flows.RevokeByGrant(g.ID, proxy.TeardownGrantExpired)
	})
}

func registerGrantExpiredAudit(store *config.Store, auditWriter *audit.Writer, stderr io.Writer) {
	store.OnGrantExpired(func(g config.Grant) {
		if aErr := auditWriter.WriteSync(audit.Event{
			Kind:      audit.KindGrant,
			Principal: g.Principal,
			Host:      g.Host,
			Port:      int(g.Port),
			GrantID:   g.ID,
			ExpiresAt: g.ExpiresAt.UTC().Format(time.RFC3339),
			Reason:    "grant-expired",
		}); aErr != nil {
			logf(stderr, "gateway: grant-expired audit write failed: %v\n", aErr)
		}
	})
}

type adminFlowAdapter struct {
	flows *proxy.FlowRegistry
}

func (a adminFlowAdapter) ListFlows() []admin.FlowInfo {
	src := a.flows.List()
	out := make([]admin.FlowInfo, len(src))
	for i, f := range src {
		out[i] = admin.FlowInfo{
			ID:        f.ID,
			Principal: f.Principal,
			Link:      f.Link,
			Host:      f.Host,
			Port:      f.Port,
			Method:    f.Method,
			Path:      f.Path,
			RuleID:    f.RuleID,
			GrantID:   f.GrantID,
			Protocol:  f.Protocol,
			StartedAt: f.StartedAt,
		}
	}
	return out
}

func (a adminFlowAdapter) CountFlows() int {
	return a.flows.Count()
}

func (a adminFlowAdapter) RevokeByID(flowID string) int {
	return a.flows.RevokeByID(flowID)
}

func (a adminFlowAdapter) RevokeByGrant(grantID string) int {
	return a.flows.RevokeByGrant(grantID, proxy.TeardownRevoked)
}

func (a adminFlowAdapter) RevokeByPrincipal(principal, host string) int {
	return a.flows.RevokeByPrincipal(principal, host)
}
