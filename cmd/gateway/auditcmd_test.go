// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/audit"
)

type lineSink struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	wrote chan struct{}
}

func (s *lineSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.buf.Write(p)
	select {
	case s.wrote <- struct{}{}:
	default:
	}
	return n, err
}

func (s *lineSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// seedAudit writes 12 records, one per rotated segment (so segments .1 to .11 sort
// wrongly as plain strings), alternating principal and effect.
func seedAudit(t *testing.T, dir string, base time.Time) *audit.Writer {
	t.Helper()
	w, err := audit.NewWriter(audit.Options{Dir: dir, MaxFileBytes: 1})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	for i := 0; i < 12; i++ {
		ev := audit.Event{Kind: audit.KindRequest, Time: base.Add(time.Duration(i) * time.Minute), Principal: "p-even", Host: "a.example.com", Port: 443, Effect: audit.EffectAllow, Status: 200}
		if i%2 == 1 {
			ev.Principal, ev.Host, ev.Effect, ev.Status, ev.Reason = "p-odd", "b.example.com", audit.EffectDeny, 403, "no-rule"
		}
		ev.Path = "/n" + string(rune('a'+i))
		if err := w.WriteSync(ev); err != nil {
			t.Fatalf("WriteSync: %v", err)
		}
	}
	return w
}

func runAuditCLI(t *testing.T, args ...string) []audit.Event {
	t.Helper()
	var out, errb bytes.Buffer
	if err := run(context.Background(), append([]string{"--json", "audit"}, args...), &out, &errb); err != nil {
		t.Fatalf("audit %v: %v (%s)", args, err, errb.String())
	}
	var evs []audit.Event
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var ev audit.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("not JSON %q: %v", line, err)
		}
		evs = append(evs, ev)
	}
	return evs
}

func TestAuditQueryAndTail(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Minute)
	seedAudit(t, dir, base)

	all := runAuditCLI(t, "query", "--dir", dir)
	if len(all) != 12 {
		t.Fatalf("query returned %d records, want 12", len(all))
	}
	for i, ev := range all {
		if ev.Path != "/n"+string(rune('a'+i)) {
			t.Fatalf("record %d is %s: segments read out of order", i, ev.Path)
		}
	}
	if got := runAuditCLI(t, "query", "--dir", dir, "--principal", "p-odd"); len(got) != 6 || got[0].Path != "/nb" {
		t.Fatalf("--principal p-odd: %d records, first %v", len(got), got)
	}
	if got := runAuditCLI(t, "query", "--dir", dir, "--host", "a.example.com"); len(got) != 6 {
		t.Fatalf("--host: %d records, want 6", len(got))
	}
	if got := runAuditCLI(t, "query", "--dir", dir, "--decision", "deny"); len(got) != 6 || got[0].Effect != audit.EffectDeny {
		t.Fatalf("--decision deny: %d records", len(got))
	}
	if got := runAuditCLI(t, "query", "--dir", dir, "--since", base.Add(9*time.Minute).Format(time.RFC3339)); len(got) != 3 {
		t.Fatalf("--since: %d records, want 3", len(got))
	}
	if got := runAuditCLI(t, "query", "--dir", dir, "--since", "2h"); len(got) != 12 {
		t.Fatalf("--since 2h: %d records, want all 12", len(got))
	}
	if got := runAuditCLI(t, "query", "--dir", dir, "--limit", "2", "--principal", "p-even"); len(got) != 2 || got[1].Path != "/nc" {
		t.Fatalf("--limit 2: %v", got)
	}
	if got := runAuditCLI(t, "tail", "--dir", dir, "-n", "3"); len(got) != 3 || got[0].Path != "/nj" || got[2].Path != "/nl" {
		t.Fatalf("tail -n 3: %v", got)
	}

	var out, errb bytes.Buffer
	if err := run(context.Background(), []string{"audit", "query", "--dir", dir, "--decision", "deny", "--limit", "1"}, &out, &errb); err != nil {
		t.Fatalf("text query: %v", err)
	}
	if !strings.Contains(out.String(), "principal=p-odd host=b.example.com:443 effect=deny") {
		t.Fatalf("text output = %q", out.String())
	}
	if err := run(context.Background(), []string{"audit", "bogus"}, &out, &errb); err == nil {
		t.Fatal("unknown audit verb accepted")
	}
}

func TestAuditTailFollowsNewRecords(t *testing.T) {
	dir := t.TempDir()
	w := seedAudit(t, dir, time.Now().UTC().Add(-time.Hour).Truncate(time.Minute))
	sink := &lineSink{wrote: make(chan struct{}, 16)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"--json", "audit", "tail", "--dir", dir, "-n", "1", "-f"}, sink, &bytes.Buffer{})
	}()
	<-sink.wrote // the initial last record: the follower is now running

	if err := w.WriteSync(audit.Event{Kind: audit.KindRequest, Principal: "p-new", Host: "new.example.com", Path: "/followed"}); err != nil {
		t.Fatalf("WriteSync: %v", err)
	}
	deadline := time.After(10 * time.Second)
	for !strings.Contains(sink.String(), "/followed") {
		select {
		case <-sink.wrote:
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("tail -f never printed the new record; got %q", sink.String())
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("tail -f: %v", err)
	}
}
