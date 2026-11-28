// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/manufactory-project/gateway/internal/audit"
)

const defaultAuditDir = "/var/log/gateway/audit"

// runAudit implements `gateway audit tail` and `gateway audit query`, which read
// the JSONL segments directly (the daemon has no query API).
func runAudit(ctx context.Context, args []string, jsonOut bool, stdout, stderr io.Writer) error {
	if len(args) == 0 || (args[0] != "tail" && args[0] != "query") {
		return errors.New("usage: gateway audit <tail [-f] [-n N] | query [--principal P] [--host H] [--decision allow|deny] [--since DUR|RFC3339] [--limit N]> [--dir PATH]")
	}
	fs := flag.NewFlagSet("gateway audit "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", defaultAuditDir, "audit directory")
	follow := fs.Bool("f", false, "tail: keep printing new records")
	last := fs.Int("n", 20, "tail: number of most recent records first")
	principal := fs.String("principal", "", "query: only this principal")
	host := fs.String("host", "", "query: only this host")
	decision := fs.String("decision", "", "query: only this effect (allow or deny)")
	since := fs.String("since", "", "query: only records after this duration ago (1h) or RFC3339 time")
	limit := fs.Int("limit", 0, "query: stop after this many records (0 = all)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("gateway audit %s: unexpected arguments: %s", args[0], strings.Join(fs.Args(), " "))
	}
	out := func(raw []byte, ev audit.Event) error {
		if jsonOut {
			_, err := fmt.Fprintf(stdout, "%s\n", raw)
			return err
		}
		_, err := fmt.Fprintf(stdout, "%s %s principal=%s host=%s:%d effect=%s status=%d reason=%s error=%s\n",
			ev.Time.Format(time.RFC3339), ev.Kind, ev.Principal, ev.Host, ev.Port, ev.Effect, ev.Status, ev.Reason, ev.Error)
		return err
	}
	if args[0] == "tail" {
		return auditTail(ctx, *dir, *last, *follow, out)
	}
	cutoff, err := parseSince(*since, time.Now())
	if err != nil {
		return err
	}
	matched := 0
	return scanAudit(*dir, func(raw []byte, ev audit.Event) (bool, error) {
		if (*principal != "" && ev.Principal != *principal) || (*host != "" && ev.Host != *host) ||
			(*decision != "" && string(ev.Effect) != *decision) || ev.Time.Before(cutoff) {
			return true, nil
		}
		matched++
		if err := out(raw, ev); err != nil {
			return false, err
		}
		return *limit == 0 || matched < *limit, nil
	})
}

func parseSince(s string, now time.Time) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return now.Add(-d), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("--since %q: want a duration such as 1h or an RFC3339 time", s)
	}
	return t, nil
}

// scanAudit calls fn for every record, oldest first, until fn returns false.
func scanAudit(dir string, fn func(raw []byte, ev audit.Event) (bool, error)) error {
	segs, err := audit.Segments(dir)
	if err != nil {
		return err
	}
	for _, p := range segs {
		_, more, err := scanFile(p, 0, fn)
		if err != nil || !more {
			return err
		}
	}
	return nil
}

// scanFile reads whole records of one segment from offset, returning the offset
// after the last one and whether fn wanted more. A trailing partial line (being
// written) is left unread.
func scanFile(path string, offset int64, fn func([]byte, audit.Event) (bool, error)) (int64, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return offset, false, err
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset, false, errors.Join(err, f.Close())
	}
	r := bufio.NewReader(f)
	more := true
	for more {
		line, rerr := r.ReadBytes('\n')
		if rerr != nil { // EOF: a line without its newline is still being written
			err = errors.Join(err, ignoreEOF(rerr))
			break
		}
		offset += int64(len(line))
		var ev audit.Event
		if jerr := json.Unmarshal(line, &ev); jerr != nil {
			err = fmt.Errorf("%s: malformed record: %w", path, jerr)
			break
		}
		if more, err = fn(bytes.TrimSuffix(line, []byte{10}), ev); err != nil {
			break
		}
	}
	return offset, more, errors.Join(err, f.Close())
}

func ignoreEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// auditTail prints the last n records and, with follow, every record written after.
func auditTail(ctx context.Context, dir string, n int, follow bool, out func([]byte, audit.Event) error) error {
	type rec struct {
		raw []byte
		ev  audit.Event
	}
	var ring []rec
	if err := scanAudit(dir, func(raw []byte, ev audit.Event) (bool, error) {
		ring = append(ring, rec{raw, ev})
		if len(ring) > n {
			ring = ring[1:]
		}
		return true, nil
	}); err != nil {
		return err
	}
	for _, r := range ring {
		if err := out(r.raw, r.ev); err != nil {
			return err
		}
	}
	if !follow {
		return nil
	}
	segs, err := audit.Segments(dir)
	if err != nil || len(segs) == 0 {
		return err
	}
	cur, offset := segs[len(segs)-1], int64(0)
	if fi, err := os.Stat(cur); err == nil {
		offset = fi.Size()
	} else {
		return err
	}
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		segs, err := audit.Segments(dir)
		if err != nil {
			return err
		}
		reached := !slices.Contains(segs, cur) // pruned away: everything listed is new
		for _, p := range segs {
			switch {
			case !reached && p != cur:
				continue
			case p != cur:
				cur, offset = p, 0
			}
			reached = true
			emit := func(raw []byte, ev audit.Event) (bool, error) { return true, out(raw, ev) }
			if offset, _, err = scanFile(p, offset, emit); err != nil {
				return err
			}
		}
	}
}
