package netsetup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteOwnedFileSafety(t *testing.T) {
	uid := uint32(os.Getuid())

	t.Run("creates missing dir 0755 and writes 0644 atomically", func(t *testing.T) {
		targetDir := filepath.Join(t.TempDir(), "dataplane")
		target := filepath.Join(targetDir, "dnsmasq.conf")
		if err := writeOwnedFile(target, []byte("port=0\n"), uid); err != nil {
			t.Fatalf("writeOwnedFile: %v", err)
		}
		dirInfo, err := os.Lstat(targetDir)
		if err != nil {
			t.Fatalf("lstat dir: %v", err)
		}
		if dirInfo.Mode().Perm() != 0o755 {
			t.Fatalf("dir mode = %04o, want 0755", dirInfo.Mode().Perm())
		}
		fileInfo, err := os.Lstat(target)
		if err != nil {
			t.Fatalf("lstat file: %v", err)
		}
		if fileInfo.Mode().Perm() != 0o644 {
			t.Fatalf("file mode = %04o, want 0644", fileInfo.Mode().Perm())
		}
		got, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("read file: %v", err)
		}
		if string(got) != "port=0\n" {
			t.Fatalf("content = %q, want %q", got, "port=0\n")
		}
	})

	t.Run("refuses wrong owner uid", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "owned")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		err := writeOwnedFile(filepath.Join(dir, "f"), []byte("x"), uid+1)
		if err == nil || !strings.Contains(err.Error(), "owned by uid") {
			t.Fatalf("expected ownership error, got %v", err)
		}
	})

	t.Run("refuses group-writable dir", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "grp")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Chmod(dir, 0o775); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		err := writeOwnedFile(filepath.Join(dir, "f"), []byte("x"), uid)
		if err == nil || !strings.Contains(err.Error(), "unsafe mode") {
			t.Fatalf("expected unsafe mode error for 0775, got %v", err)
		}
	})

	t.Run("refuses other-writable dir", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "oth")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Chmod(dir, 0o757); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		err := writeOwnedFile(filepath.Join(dir, "f"), []byte("x"), uid)
		if err == nil || !strings.Contains(err.Error(), "unsafe mode") {
			t.Fatalf("expected unsafe mode error for 0757, got %v", err)
		}
	})

	t.Run("refuses symlinked directory", func(t *testing.T) {
		base := t.TempDir()
		realDir := filepath.Join(base, "real")
		if err := os.Mkdir(realDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		symDir := filepath.Join(base, "sym")
		if err := os.Symlink(realDir, symDir); err != nil {
			t.Fatalf("symlink dir: %v", err)
		}
		err := writeOwnedFile(filepath.Join(symDir, "f"), []byte("x"), uid)
		if err == nil || !strings.Contains(err.Error(), "symlink parent directory") {
			t.Fatalf("expected symlink dir error, got %v", err)
		}
	})

	t.Run("refuses symlinked destination file", func(t *testing.T) {
		base := t.TempDir()
		dir := filepath.Join(base, "dp")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		victim := filepath.Join(base, "victim")
		if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
			t.Fatalf("write victim: %v", err)
		}
		link := filepath.Join(dir, "dnsmasq.conf")
		if err := os.Symlink(victim, link); err != nil {
			t.Fatalf("symlink file: %v", err)
		}
		err := writeOwnedFile(link, []byte("overwrite"), uid)
		if err == nil || !strings.Contains(err.Error(), "symlink destination") {
			t.Fatalf("expected symlink destination error, got %v", err)
		}
		got, rErr := os.ReadFile(victim)
		if rErr != nil || string(got) != "keep" {
			t.Fatalf("victim file altered: %q (err=%v)", got, rErr)
		}
	})
}
