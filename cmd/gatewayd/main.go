// Command gatewayd runs the headless, egress-only network gateway daemon,
// or (as root in ExecStartPre=+) `gatewayd netsetup --config <path>` to apply
// the Linux nftables, sysctls, per-link ip routing, and DHCP-only dnsmasq config.
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

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if _, wErr := fmt.Fprintf(os.Stderr, "gatewayd: %v\n", err); wErr != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "netsetup" {
		return runNetsetup(args[1:], stdout, stderr)
	}
	return runDaemon(args, stdout, stderr)
}

func runNetsetup(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("gatewayd netsetup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to gatewayd YAML config")
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
	fs := flag.NewFlagSet("gatewayd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to gatewayd YAML config")
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

func serveDaemon(ctx context.Context, cfgPath, procSysRoot string, stdout, stderr io.Writer) error {
	store, err := config.NewStore(cfgPath)
	if err != nil {
		return err
	}
	cfg := store.Current().Config

	// Startup dataplane checks (unprivileged; zero CAP_NET_ADMIN required).
	if cfg.ShouldVerifySysctls() {
		if err := netsetup.VerifySysctls(procSysRoot, cfg); err != nil {
			return fmt.Errorf("startup sysctl check failed: %w", err)
		}
	}
	if cfg.Dataplane.ReadyFile != "" {
		if _, err := os.Stat(cfg.Dataplane.ReadyFile); err != nil {
			return fmt.Errorf("dataplane ready_file %s missing (run ExecStartPre=+ gatewayd netsetup first): %w", cfg.Dataplane.ReadyFile, err)
		}
	}

	// Strictly load operator-supplied MITM CA (fail closed if missing or mismatched).
	mitmCA, err := ca.Load(cfg.CA.CertPath, cfg.CA.KeyPath)
	if err != nil {
		return err
	}

	flows := proxy.NewFlowRegistry()
	collector := metrics.NewCollector(metrics.Options{
		ActiveFlows:  flows.Count,
		ActiveGrants: func() int { return len(store.ActiveGrants()) },
	})

	var auditStdout io.Writer
	if cfg.Audit.StdoutJSON {
		auditStdout = stdout
	}
	auditWriter, err := audit.NewWriter(audit.Options{
		Dir:          cfg.Audit.Dir,
		RetainDays:   cfg.Audit.RetainDays,
		MaxFileBytes: cfg.Audit.MaxFileBytes,
		Stdout:       auditStdout,
		Diag:         stderr,
		OnWriteError: collector.IncAuditWriteError,
	})
	if err != nil {
		return err
	}

	eval := policy.NewEvaluator(store)
	alloc, err := gwdns.NewAllocator(cfg.FakePrefix)
	if err != nil {
		return errors.Join(err, auditWriter.Close())
	}
	leaves := ca.NewLeafCache(mitmCA)
	sniLim := ca.NewDeniedSNILimiter(cfg.HTTP.DeniedSNIRatePerSec, cfg.HTTP.DeniedSNIBurst)
	dialer := netguard.NewDialer(netguard.Options{Store: store})

	var (
		dnsServers   []*gwdns.Server
		proxyServers []*proxy.Server
		adminSrv     *admin.Server
		metricsSrv   *metrics.Server
	)

	shutdownAll := func() error {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var errs error
		if adminSrv != nil {
			errs = errors.Join(errs, adminSrv.Shutdown(shutCtx))
		}
		if metricsSrv != nil {
			errs = errors.Join(errs, metricsSrv.Shutdown(shutCtx))
		}
		for _, ps := range proxyServers {
			errs = errors.Join(errs, ps.Shutdown(shutCtx))
		}
		for _, ds := range dnsServers {
			errs = errors.Join(errs, ds.Shutdown(shutCtx))
		}
		errs = errors.Join(errs, auditWriter.Close())
		return errs
	}

	for _, link := range cfg.Links {
		ds, err := gwdns.NewServer(gwdns.ServerOptions{
			Link:      link,
			Store:     store,
			Evaluator: eval,
			Audit:     auditWriter,
			Allocator: alloc,
			OnQuery:   collector.ObserveDNSQuery,
		})
		if err != nil {
			return errors.Join(err, shutdownAll())
		}
		if err := ds.Start(); err != nil {
			return errors.Join(err, shutdownAll())
		}
		dnsServers = append(dnsServers, ds)

		ps, err := proxy.NewServer(proxy.Options{
			Link:       link,
			Store:      store,
			Evaluator:  eval,
			Audit:      auditWriter,
			Leaves:     leaves,
			SNILimiter: sniLim,
			Dialer:     dialer,
			Flows:      flows,
			OnRequest:  collector.ObserveRequest,
		})
		if err != nil {
			return errors.Join(err, shutdownAll())
		}
		if err := ps.Start(); err != nil {
			return errors.Join(err, shutdownAll())
		}
		proxyServers = append(proxyServers, ps)
	}

	if cfg.Admin.Socket != "" {
		adminSrv, err = admin.NewServer(admin.Options{
			SocketPath:  cfg.Admin.Socket,
			SocketGroup: cfg.Admin.SocketGroup,
			Store:       store,
			Flows:       flows,
			Audit:       auditWriter,
			Metrics:     collector,
		})
		if err != nil {
			return errors.Join(err, shutdownAll())
		}
		if err := adminSrv.Start(); err != nil {
			return errors.Join(err, shutdownAll())
		}
	}

	if cfg.Metrics.Listen != "" {
		metricsSrv, err = metrics.NewServer(cfg.Metrics.Listen, collector)
		if err != nil {
			return errors.Join(err, shutdownAll())
		}
		if err := metricsSrv.Start(); err != nil {
			return errors.Join(err, shutdownAll())
		}
	}

	if err := auditWriter.WriteSync(audit.Event{
		Kind:       audit.KindLifecycle,
		Reason:     "started",
		ConfigHash: store.Current().Hash,
	}); err != nil {
		return errors.Join(err, shutdownAll())
	}

	var sighupWG sync.WaitGroup
	sighupWG.Add(1)
	go func() {
		defer sighupWG.Done()
		store.WatchSIGHUP(ctx, func(snap *config.Snapshot, _ []string, reloadErr error) {
			if reloadErr != nil {
				collector.ObserveReload(false)
				if _, wErr := fmt.Fprintf(stderr, "gatewayd: SIGHUP reload failed (keeping prior config): %v\n", reloadErr); wErr != nil {
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
		})
	}()

	<-ctx.Done()
	sighupWG.Wait()

	if aErr := auditWriter.WriteSync(audit.Event{
		Kind:   audit.KindLifecycle,
		Reason: "stopped",
	}); aErr != nil {
		// Still proceed with graceful shutdown.
		if _, wErr := fmt.Fprintf(stderr, "gatewayd: stopped audit write failed: %v\n", aErr); wErr != nil {
			return shutdownAll()
		}
	}
	return shutdownAll()
}
