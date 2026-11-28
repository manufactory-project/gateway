// SPDX-License-Identifier: AGPL-3.0-only

package secret_test

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/secret"
)

// TestFileResolverRefusesUnsafeFiles pins that a secret file must be a plain,
// bounded regular file that is not world-accessible: a symlink, a FIFO (which
// would stall every request to the host), an oversize file, a world-readable
// file, a directory and a device all fail closed.
func TestFileResolverRefusesUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	res := secret.FileResolver{}
	write := func(name string, data []byte, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, mode); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatalf("chmod %s: %v", name, err)
		}
		return p
	}

	good := write("good", []byte("tok\n"), 0o600)
	if got, err := res.Resolve(good); err != nil || got != "tok" {
		t.Fatalf("control: Resolve = (%q, %v), want tok", got, err)
	}
	if _, err := res.Resolve(write("group", []byte("tok"), 0o640)); err != nil {
		t.Fatalf("control: group-readable 0640 must resolve: %v", err)
	}
	if _, err := res.Resolve(write("atcap", []byte(strings.Repeat("a", 64<<10)), 0o600)); err != nil {
		t.Fatalf("control: a file exactly at the cap must resolve: %v", err)
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	// A FIFO that holds data would read like a file if its type were not checked.
	fifoRW, err := os.OpenFile(fifo, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open fifo: %v", err)
	}
	t.Cleanup(func() {
		if err := fifoRW.Close(); err != nil {
			t.Errorf("close fifo: %v", err)
		}
	})
	if _, err := fifoRW.WriteString("tok\n"); err != nil {
		t.Fatalf("fill fifo: %v", err)
	}
	for name, p := range map[string]string{
		"symlink":        link,
		"fifo":           fifo,
		"oversize":       write("big", []byte(strings.Repeat("a", 64<<10+1)), 0o600),
		"world-readable": write("world", []byte("tok"), 0o644),
		"directory":      dir,
		"device":         "/dev/zero",
	} {
		// Without the regular-file check a FIFO that holds data blocks the read
		// forever, so the call is guarded and a hang is reported as that failure.
		type result struct {
			val string
			err error
		}
		ch := make(chan result, 1)
		go func() {
			v, err := res.Resolve(p)
			ch <- result{v, err}
		}()
		select {
		case r := <-ch:
			if r.err == nil {
				t.Errorf("%s: Resolve = %q, want an error", name, r.val)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: Resolve blocked on a non-regular secret file; it must be refused before reading", name)
		}
	}
}
