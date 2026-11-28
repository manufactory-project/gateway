// SPDX-License-Identifier: AGPL-3.0-or-later

package netsetup

// Interfaces removed from the config may still have a guest attached. netsetup
// therefore records every interface it has managed in dataplane.state_file and
// drops all traffic on the ones that are no longer configured ("retired").

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/manufactory-project/gateway/internal/config"
)

const stateVersion = 1

// The nftables sets in table inet gw that name sandbox interfaces.
const (
	sandboxSet = "sandbox_ifs"
	retiredSet = "retired_ifs"
)

// record is the content of dataplane.state_file.
type record struct {
	Version    int                `json:"version"`
	Interfaces []managedInterface `json:"interfaces"`
}

type managedInterface struct {
	Name string `json:"name"`
	// Assignments is every address and route table netsetup has configured on
	// the interface. It is empty for an interface adopted from the live table.
	Assignments []assignment `json:"assignments,omitempty"`
}

type assignment struct {
	GatewayIP  netip.Addr `json:"gateway_ip"`
	PrefixBits int        `json:"prefix_bits"`
	RouteTable int        `json:"route_table"`
}

// RetiredPlan reports, from dataplane.state_file alone, which interfaces Apply
// would block and the cleanup commands it would run for them. It changes nothing.
func RetiredPlan(cfg *config.Config) ([]string, []IPCommand, error) {
	return retiredPlan(cfg, 0)
}

func retiredPlan(cfg *config.Config, expectedUID uint32) ([]string, []IPCommand, error) {
	rec, err := loadRecord(cfg.Dataplane.StateFile, expectedUID)
	if err != nil {
		return nil, nil, err
	}
	retired := retiredInterfaces(mergeRecord(rec, nil, cfg), cfg)
	return interfaceNames(retired), cleanupCommands(retired), nil
}

func loadRecord(path string, expectedUID uint32) (record, error) {
	empty := record{Version: stateVersion}
	fail := func(err error) (record, error) {
		return record{}, fmt.Errorf("netsetup: state_file %s: %w", path, err)
	}
	if err := verifyOwnedDir(filepath.Dir(path), expectedUID); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return empty, nil
		}
		return fail(err)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return fail(err)
	}
	if !info.Mode().IsRegular() {
		return fail(errors.New("not a regular file"))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fail(err)
	}

	var rec record
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return fail(fmt.Errorf("decode: %w", err))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fail(errors.New("unexpected data after the record"))
	}
	if rec.Version != stateVersion {
		return fail(fmt.Errorf("unsupported version %d", rec.Version))
	}
	// Names and addresses end up in the nft ruleset and ip commands.
	for _, m := range rec.Interfaces {
		if !config.IsValidInterfaceName(m.Name) {
			return fail(fmt.Errorf("invalid interface name %q", m.Name))
		}
		for _, a := range m.Assignments {
			if !a.GatewayIP.Is4() || a.PrefixBits < 0 || a.PrefixBits > 32 || a.RouteTable <= 0 {
				return fail(fmt.Errorf("invalid assignment on interface %q", m.Name))
			}
		}
	}
	return rec, nil
}

func saveRecord(path string, rec record, expectedUID uint32) error {
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("netsetup: encode state_file: %w", err)
	}
	if err := writeOwnedFile(path, append(raw, '\n'), expectedUID); err != nil {
		return fmt.Errorf("netsetup: write state_file %s: %w", path, err)
	}
	return nil
}

// liveInterfaces returns the sandbox interfaces named by the loaded table inet gw.
// It covers a table loaded before any record existed.
func liveInterfaces(ctx context.Context) ([]string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "nft", "-j", "list", "sets", "inet")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("netsetup: nft list sets failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var listing struct {
		Nftables []struct {
			Set *struct {
				Table string          `json:"table"`
				Name  string          `json:"name"`
				Elem  json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &listing); err != nil {
		return nil, fmt.Errorf("netsetup: decode nft list sets output: %w", err)
	}
	var names []string
	for _, object := range listing.Nftables {
		s := object.Set
		if s == nil || s.Table != NftTableName || (s.Name != sandboxSet && s.Name != retiredSet) || s.Elem == nil {
			continue
		}
		var elems []string
		if err := json.Unmarshal(s.Elem, &elems); err != nil {
			return nil, fmt.Errorf("netsetup: decode nft set %s: %w", s.Name, err)
		}
		for _, name := range elems {
			if !config.IsValidInterfaceName(name) {
				return nil, fmt.Errorf("netsetup: nft set %s holds invalid interface name %q", s.Name, name)
			}
		}
		names = append(names, elems...)
	}
	return names, nil
}

// mergeRecord returns prev extended with the live interfaces and configured
// links, sorted by interface name. Nothing in prev is dropped.
func mergeRecord(prev record, live []string, cfg *config.Config) record {
	byName := make(map[string][]assignment)
	add := func(name string, assignments ...assignment) {
		have := byName[name]
		for _, a := range assignments {
			if !slices.Contains(have, a) {
				have = append(have, a)
			}
		}
		byName[name] = have
	}
	for _, m := range prev.Interfaces {
		add(m.Name, m.Assignments...)
	}
	for _, name := range live {
		add(name)
	}
	for _, l := range cfg.Links {
		add(l.Interface, assignment{
			GatewayIP:  l.ParsedGatewayIP,
			PrefixBits: l.ParsedSubnet.Bits(),
			RouteTable: l.RouteTable,
		})
	}

	out := record{Version: stateVersion}
	for name, assignments := range byName {
		out.Interfaces = append(out.Interfaces, managedInterface{Name: name, Assignments: assignments})
	}
	slices.SortFunc(out.Interfaces, func(a, b managedInterface) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func isConfigured(cfg *config.Config, name string) bool {
	return slices.ContainsFunc(cfg.Links, func(l config.LinkConfig) bool { return l.Interface == name })
}

func retiredInterfaces(rec record, cfg *config.Config) []managedInterface {
	var retired []managedInterface
	for _, m := range rec.Interfaces {
		if !isConfigured(cfg, m.Name) {
			retired = append(retired, m)
		}
	}
	return retired
}

func interfaceNames(interfaces []managedInterface) []string {
	var names []string
	for _, m := range interfaces {
		names = append(names, m.Name)
	}
	return names
}

// cleanupCommands removes exactly what netsetup added to retired interfaces.
// They are optional because the address, route, rule or interface may already be
// gone; blocking does not depend on them. They must run before IPCommands, which
// may configure the same address or rule for another link.
func cleanupCommands(retired []managedInterface) []IPCommand {
	var cmds []IPCommand
	for _, m := range retired {
		for _, a := range m.Assignments {
			table := strconv.Itoa(a.RouteTable)
			for _, args := range [][]string{
				{"ip", "rule", "del", "from", a.GatewayIP.String() + "/32", "lookup", table},
				{"ip", "route", "del", "default", "dev", m.Name, "scope", "link", "table", table},
				{"ip", "addr", "del", netip.PrefixFrom(a.GatewayIP, a.PrefixBits).String(), "dev", m.Name},
			} {
				cmds = append(cmds, IPCommand{Args: args, Optional: true})
			}
		}
	}
	return cmds
}
