// Command gwctl controls a running gatewayd over its local Unix domain socket
// and provides offline `ca init` and root `dataplane check` subcommands.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/manufactory-project/gateway/internal/admin"
	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/ca"
	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/netsetup"
)

const defaultSocket = "/run/gatewayd/admin.sock"

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if _, wErr := fmt.Fprintf(os.Stderr, "gwctl: %v\n", err); wErr != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	args, trailingJSON := stripJSONFlag(args)

	fs := flag.NewFlagSet("gwctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socketPath := fs.String("socket", defaultSocket, "path to gatewayd admin Unix socket")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	jsonOut := *asJSON || trailingJSON
	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("usage: gwctl [--socket PATH] [--json] <status|reload|flows|revoke|grants|grant|audit|ca|dataplane>")
	}

	cmd := rest[0]
	cmdArgs := rest[1:]

	switch cmd {
	case "ca":
		return runCA(cmdArgs, jsonOut, stdout, stderr)
	case "dataplane":
		return runDataplane(ctx, cmdArgs, jsonOut, stdout, stderr)
	}

	client := admin.NewClient(*socketPath)
	defer client.Close()

	switch cmd {
	case "status":
		st, err := client.Status(ctx)
		if err != nil {
			return err
		}
		if jsonOut {
			return printJSON(stdout, st)
		}
		_, err = fmt.Fprintf(stdout, "config_hash=%s active_flows=%d active_grants=%d audit_healthy=%v audit_write_errors=%d\n",
			st.ConfigHash, st.ActiveFlows, st.ActiveGrants, st.AuditHealthy, st.AuditWriteErrors)
		return err

	case "reload":
		res, err := client.Reload(ctx)
		if err != nil {
			return err
		}
		if jsonOut {
			return printJSON(stdout, res)
		}
		_, err = fmt.Fprintf(stdout, "reloaded config_hash=%s wiped_grants=%d\n", res.ConfigHash, len(res.WipedGrants))
		return err

	case "flows":
		flows, err := client.Flows(ctx)
		if err != nil {
			return err
		}
		if jsonOut {
			return printJSON(stdout, flows)
		}
		for _, f := range flows {
			if _, err := fmt.Fprintf(stdout, "%s principal=%s host=%s:%d proto=%s rule=%s grant=%s\n",
				f.ID, f.Principal, f.Host, f.Port, f.Protocol, f.RuleID, f.GrantID); err != nil {
				return err
			}
		}
		return nil

	case "revoke":
		rfs := flag.NewFlagSet("gwctl revoke", flag.ContinueOnError)
		rfs.SetOutput(stderr)
		flowID := rfs.String("flow", "", "flow ID to revoke")
		grantID := rfs.String("grant", "", "grant ID to revoke")
		principal := rfs.String("principal", "", "principal whose flows to revoke")
		host := rfs.String("host", "", "optional host filter with --principal")
		if err := rfs.Parse(cmdArgs); err != nil {
			return err
		}
		res, err := client.Revoke(ctx, admin.RevokeRequest{
			FlowID:    *flowID,
			GrantID:   *grantID,
			Principal: *principal,
			Host:      *host,
		})
		if err != nil {
			return err
		}
		if jsonOut {
			return printJSON(stdout, res)
		}
		_, err = fmt.Fprintf(stdout, "revoked_flows=%d revoked_grant=%v\n", res.RevokedFlows, res.RevokedGrant)
		return err

	case "grants":
		grants, err := client.Grants(ctx)
		if err != nil {
			return err
		}
		if jsonOut {
			return printJSON(stdout, grants)
		}
		for _, g := range grants {
			if _, err := fmt.Fprintf(stdout, "%s principal=%s host=%s:%d expires=%s\n",
				g.ID, g.Principal, g.Host, g.Port, g.ExpiresAt.Format(time.RFC3339)); err != nil {
				return err
			}
		}
		return nil

	case "grant":
		if len(cmdArgs) > 0 && cmdArgs[0] == "revoke" {
			if len(cmdArgs) != 2 {
				return errors.New("usage: gwctl grant revoke <id>")
			}
			res, err := client.DeleteGrant(ctx, cmdArgs[1])
			if err != nil {
				return err
			}
			if jsonOut {
				return printJSON(stdout, res)
			}
			_, err = fmt.Fprintf(stdout, "revoked_grant=%v revoked_flows=%d\n", res.RevokedGrant, res.RevokedFlows)
			return err
		}
		gfs := flag.NewFlagSet("gwctl grant", flag.ContinueOnError)
		gfs.SetOutput(stderr)
		principal := gfs.String("principal", "", "principal name")
		host := gfs.String("host", "", "exact hostname")
		port := gfs.Uint("port", 443, "destination port (80 or 443)")
		methodsCSV := gfs.String("methods", "", "comma-separated HTTP methods")
		pathsCSV := gfs.String("paths", "", "comma-separated path globs")
		ttl := gfs.String("ttl", "5m", "grant TTL duration")
		if err := gfs.Parse(cmdArgs); err != nil {
			return err
		}
		if *port > 65535 {
			return fmt.Errorf("grant: port %d exceeds 65535", *port)
		}
		g, err := client.CreateGrant(ctx, admin.GrantRequest{
			Principal: *principal,
			Host:      *host,
			Port:      uint16(*port),
			Methods:   splitCSV(*methodsCSV),
			Paths:     splitCSV(*pathsCSV),
			TTL:       *ttl,
		})
		if err != nil {
			return err
		}
		if jsonOut {
			return printJSON(stdout, g)
		}
		_, err = fmt.Fprintf(stdout, "granted %s principal=%s host=%s:%d expires=%s\n",
			g.ID, g.Principal, g.Host, g.Port, g.ExpiresAt.Format(time.RFC3339))
		return err

	case "audit":
		afs := flag.NewFlagSet("gwctl audit", flag.ContinueOnError)
		afs.SetOutput(stderr)
		tail := afs.Int("tail", 0, "return last N matching records")
		follow := afs.Bool("follow", false, "stream new records")
		principal := afs.String("principal", "", "filter by principal")
		host := afs.String("host", "", "filter by host")
		effect := afs.String("effect", "", "filter by effect (allow|deny)")
		since := afs.String("since", "", "filter by duration or RFC3339 timestamp")
		if err := afs.Parse(cmdArgs); err != nil {
			return err
		}
		return client.StreamAudit(ctx, admin.AuditParams{
			Tail:      *tail,
			Follow:    *follow,
			Principal: *principal,
			Host:      *host,
			Effect:    *effect,
			Since:     *since,
		}, func(ev audit.Event) error {
			if jsonOut {
				return printJSON(stdout, ev)
			}
			_, err := fmt.Fprintf(stdout, "%s kind=%s principal=%s host=%s effect=%s reason=%s status=%d\n",
				ev.Time.Format(time.RFC3339), ev.Kind, ev.Principal, ev.Host, ev.Effect, ev.Reason, ev.Status)
			return err
		})

	default:
		return fmt.Errorf("unknown subcommand %q", cmd)
	}
}

// stripJSONFlag allows --json to appear anywhere on the command line (before or after
// any subcommand), honoring "--" to stop flag scanning.
func stripJSONFlag(args []string) ([]string, bool) {
	out := make([]string, 0, len(args))
	found := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			out = append(out, args[i:]...)
			break
		}
		switch a {
		case "--json", "-json", "--json=true", "-json=true":
			found = true
			continue
		case "--json=false", "-json=false":
			found = false
			continue
		}
		out = append(out, a)
	}
	return out, found
}

func runCA(args []string, asJSON bool, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "init" {
		return errors.New("usage: gwctl ca init --cert <path> --key <path>")
	}
	fs := flag.NewFlagSet("gwctl ca init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	certPath := fs.String("cert", "", "output CA certificate path")
	keyPath := fs.String("key", "", "output CA key path")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if _, err := ca.Init(*certPath, *keyPath); err != nil {
		return err
	}
	if asJSON {
		return printJSON(stdout, map[string]string{"cert_path": *certPath, "key_path": *keyPath})
	}
	_, err := fmt.Fprintf(stdout, "initialized CA cert=%s key=%s\n", *certPath, *keyPath)
	return err
}

func runDataplane(ctx context.Context, args []string, asJSON bool, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "check" {
		return errors.New("usage: gwctl dataplane check --config <path>")
	}
	fs := flag.NewFlagSet("gwctl dataplane check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to gatewayd YAML config")
	procSysRoot := fs.String("proc-sys-root", "/proc/sys", "root directory for sysctl check")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *cfgPath == "" {
		return errors.New("dataplane check: --config is required")
	}
	cfg, _, err := config.LoadFile(*cfgPath)
	if err != nil {
		return err
	}
	if err := netsetup.CheckNftTable(ctx); err != nil {
		return err
	}
	if cfg.ShouldVerifySysctls() {
		if err := netsetup.VerifySysctls(*procSysRoot, cfg); err != nil {
			return err
		}
	}
	if cfg.Dataplane.ReadyFile != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.Dataplane.ReadyFile), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(cfg.Dataplane.ReadyFile, []byte("ok\n"), 0o644); err != nil {
			return err
		}
	}
	if asJSON {
		return printJSON(stdout, map[string]string{"status": "ok", "table": "inet " + netsetup.NftTableName})
	}
	_, err = fmt.Fprintf(stdout, "dataplane ok (table inet %s + sysctls verified)\n", netsetup.NftTableName)
	return err
}

func printJSON(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v)
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
