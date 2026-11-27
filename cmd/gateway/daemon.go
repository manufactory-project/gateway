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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return errors.New("netsetup: --config is required")
	}

	cfg, _, err := config.LoadFile(*cfgPath)
	if err != nil {
		return err
	}

	if *dryRun {
		nft, err := netsetup.RenderNftables(cfg)
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
		for _, cmd := range netsetup.IPCommands(cfg) {
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
	return netsetup.Apply(ctx, cfg)
}

func runDaemon(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("gateway run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to gateway YAML config")
	procSysRoot := fs.String("proc-sys-root", "/proc/sys", "root directory for sysctl verification")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return errors.New("--config is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serveDaemon(ctx, *cfgPath, *procSysRoot, stdout, stderr)
}

type daemonRuntime struct {
	dnsServers   []*gwdns.Server
	proxyServers []*proxy.Server
	adminSrv     *admin.Server
	metricsSrv   *metrics.Server
	auditWriter  *audit.Writer
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
	if cfg.ShouldVerifySysctls() {
		if err := netsetup.VerifySysctls(procSysRoot, cfg); err != nil {
			return fmt.Errorf("startup sysctl check failed: %w", err)
		}
	}
	if cfg.Dataplane.ReadyFile != "" {
		if _, err := os.Stat(cfg.Dataplane.ReadyFile); err != nil {
			return fmt.Errorf("dataplane ready_file %s missing (run ExecStartPre=+ gateway netsetup first): %w", cfg.Dataplane.ReadyFile, err)
		}
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
) error {
	for _, link := range cfg.Links {
		ds, err := gwdns.NewServer(gwdns.ServerOptions{
			Link:      link,
			Store:     store,
			Evaluator: eval,
			Audit:     rt.auditWriter,
			Allocator: alloc,
			OnQuery:   collector.ObserveDNSQuery,
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

func (rt *daemonRuntime) startControl(cfg *config.Config, store *config.Store, flows *proxy.FlowRegistry, collector *metrics.Collector) error {
	if cfg.Admin.Socket != "" {
		srv, err := admin.NewServer(admin.Options{
			SocketPath:  cfg.Admin.Socket,
			SocketGroup: cfg.Admin.SocketGroup,
			Store:       store,
			Flows:       adminFlowAdapter{flows: flows},
			Audit:       rt.auditWriter,
			Metrics:     collector,
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
		srv, err := metrics.NewServer(cfg.Metrics.Listen, collector)
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

func handleSIGHUPReload(snap *config.Snapshot, reloadErr error, collector *metrics.Collector, auditWriter *audit.Writer, stderr io.Writer) {
	if reloadErr != nil {
		collector.ObserveReload(false)
		if aErr := auditWriter.WriteSync(audit.Event{
			Kind:   audit.KindLifecycle,
			Reason: "sighup-reload-failed",
			Error:  reloadErr.Error(),
		}); aErr != nil {
			if _, wErr := fmt.Fprintf(stderr, "gateway: SIGHUP reload failed (audit error: %v): %v\n", aErr, reloadErr); wErr != nil {
				return
			}
			return
		}
		if _, wErr := fmt.Fprintf(stderr, "gateway: SIGHUP reload failed (keeping prior config): %v\n", reloadErr); wErr != nil {
			return
		}
		return
	}
	collector.ObserveReload(true)
	if aErr := auditWriter.WriteSync(audit.Event{
		Kind:       audit.KindLifecycle,
		Reason:     "sighup-reload",
		ConfigHash: snap.Hash,
	}); aErr != nil {
		return
	}
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
	registerGrantExpiredAudit(store, auditWriter, stderr)

	rt := &daemonRuntime{auditWriter: auditWriter}
	alloc, err := gwdns.NewAllocator(cfg.FakePrefix)
	if err != nil {
		return errors.Join(err, rt.shutdownAll())
	}
	eval := policy.NewEvaluator(store)
	leaves := ca.NewLeafCache(mitmCA)
	dialer := netguard.NewDialer(netguard.Options{Store: store})

	if err := rt.startLinks(cfg, store, eval, alloc, leaves, dialer, flows, collector); err != nil {
		return errors.Join(err, rt.shutdownAll())
	}
	if err := rt.startControl(cfg, store, flows, collector); err != nil {
		return errors.Join(err, rt.shutdownAll())
	}
	if err := auditWriter.WriteSync(audit.Event{
		Kind:       audit.KindLifecycle,
		Reason:     "started",
		ConfigHash: store.Current().Hash,
	}); err != nil {
		return errors.Join(err, rt.shutdownAll())
	}

	var bgWG sync.WaitGroup
	bgWG.Add(2)
	go func() {
		defer bgWG.Done()
		store.RunGrantPruner(ctx, 50*time.Millisecond)
	}()
	go func() {
		defer bgWG.Done()
		store.WatchSIGHUP(ctx, func(snap *config.Snapshot, _ []string, reloadErr error) {
			handleSIGHUPReload(snap, reloadErr, collector, auditWriter, stderr)
		})
	}()

	<-ctx.Done()
	bgWG.Wait()

	if aErr := auditWriter.WriteSync(audit.Event{
		Kind:   audit.KindLifecycle,
		Reason: "stopped",
	}); aErr != nil {
		if _, wErr := fmt.Fprintf(stderr, "gateway: stopped audit write failed: %v\n", aErr); wErr != nil {
			return rt.shutdownAll()
		}
	}
	return rt.shutdownAll()
}

func registerGrantExpiredAudit(store *config.Store, auditWriter *audit.Writer, stderr io.Writer) {
	store.SetOnGrantExpired(func(g config.Grant) {
		if aErr := auditWriter.WriteSync(audit.Event{
			Kind:      audit.KindGrant,
			Principal: g.Principal,
			Host:      g.Host,
			Port:      int(g.Port),
			GrantID:   g.ID,
			ExpiresAt: g.ExpiresAt.UTC().Format(time.RFC3339),
			Reason:    "grant-expired",
		}); aErr != nil {
			if _, wErr := fmt.Fprintf(stderr, "gateway: grant-expired audit write failed: %v\n", aErr); wErr != nil {
				return
			}
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
	return a.flows.RevokeByGrant(grantID)
}

func (a adminFlowAdapter) RevokeByPrincipal(principal, host string) int {
	return a.flows.RevokeByPrincipal(principal, host)
}
