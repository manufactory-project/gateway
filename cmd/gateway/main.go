// Command gateway runs the headless, egress-only network gateway daemon and
// provides its operator CLI subcommands (`run`, `netsetup`, `status`, `reload`,
// `flows`, `revoke`, `grant`, `grants`, `ca init`, and `dataplane check`).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/manufactory-project/gateway/internal/admin"
	"github.com/manufactory-project/gateway/internal/ca"
	"github.com/manufactory-project/gateway/internal/config"
	"github.com/manufactory-project/gateway/internal/netsetup"
)

const defaultSocket = "/run/gateway/admin.sock"

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if _, wErr := fmt.Fprintf(os.Stderr, "gateway: %v\n", err); wErr != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	args, trailingJSON := stripJSONFlag(args)

	fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socketPath := fs.String("socket", defaultSocket, "path to gateway admin Unix socket")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	jsonOut := *asJSON || trailingJSON
	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("usage: gateway [--socket PATH] [--json] <run|netsetup|status|reload|flows|revoke|grants|grant|ca|dataplane>")
	}

	cmd := rest[0]
	cmdArgs := rest[1:]

	switch cmd {
	case "run":
		return runDaemon(cmdArgs, stdout, stderr)
	case "netsetup":
		return runNetsetup(cmdArgs, stdout, stderr)
	case "ca":
		return runCA(cmdArgs, jsonOut, stdout, stderr)
	case "dataplane":
		return runDataplane(ctx, cmdArgs, jsonOut, stdout, stderr)
	default:
		return runAdminCmd(ctx, *socketPath, cmd, cmdArgs, jsonOut, stdout, stderr)
	}
}

func runAdminCmd(ctx context.Context, socketPath, cmd string, cmdArgs []string, jsonOut bool, stdout, stderr io.Writer) error {
	client := admin.NewClient(socketPath)
	defer client.Close()

	switch cmd {
	case "status":
		return runStatus(ctx, client, jsonOut, stdout)
	case "reload":
		return runReload(ctx, client, jsonOut, stdout)
	case "flows":
		return runFlows(ctx, client, jsonOut, stdout)
	case "revoke":
		return runRevoke(ctx, client, cmdArgs, jsonOut, stdout, stderr)
	case "grants":
		return runGrants(ctx, client, jsonOut, stdout)
	case "grant":
		return runGrant(ctx, client, cmdArgs, jsonOut, stdout, stderr)
	default:
		return fmt.Errorf("unknown subcommand %q", cmd)
	}
}

func runStatus(ctx context.Context, client *admin.Client, jsonOut bool, stdout io.Writer) error {
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
}

func runReload(ctx context.Context, client *admin.Client, jsonOut bool, stdout io.Writer) error {
	res, err := client.Reload(ctx)
	if err != nil {
		return err
	}
	if jsonOut {
		return printJSON(stdout, res)
	}
	_, err = fmt.Fprintf(stdout, "reloaded config_hash=%s wiped_grants=%d\n", res.ConfigHash, len(res.WipedGrants))
	return err
}

func runFlows(ctx context.Context, client *admin.Client, jsonOut bool, stdout io.Writer) error {
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
}

func runRevoke(ctx context.Context, client *admin.Client, cmdArgs []string, jsonOut bool, stdout, stderr io.Writer) error {
	rfs := flag.NewFlagSet("gateway revoke", flag.ContinueOnError)
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
}

func runGrants(ctx context.Context, client *admin.Client, jsonOut bool, stdout io.Writer) error {
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
}

func runGrant(ctx context.Context, client *admin.Client, cmdArgs []string, jsonOut bool, stdout, stderr io.Writer) error {
	if len(cmdArgs) > 0 && cmdArgs[0] == "revoke" {
		if len(cmdArgs) != 2 {
			return errors.New("usage: gateway grant revoke <id>")
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
	gfs := flag.NewFlagSet("gateway grant", flag.ContinueOnError)
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
		return errors.New("usage: gateway ca init --cert <path> --key <path>")
	}
	fs := flag.NewFlagSet("gateway ca init", flag.ContinueOnError)
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
		return errors.New("usage: gateway dataplane check --config <path>")
	}
	fs := flag.NewFlagSet("gateway dataplane check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to gateway YAML config")
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
