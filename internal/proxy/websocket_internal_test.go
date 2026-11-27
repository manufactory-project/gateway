package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestPerformWSHandshakeDeadlineFires(t *testing.T) {
	t.Run("timeout on silent upstream", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			closeQuietly(clientConn)
			closeQuietly(serverConn)
		})

		drained := make(chan struct{})
		go func() {
			defer close(drained)
			req, err := http.ReadRequest(bufio.NewReader(serverConn))
			if err != nil {
				return
			}
			closeQuietly(req.Body)
			// Never respond; hold open until closed.
			var buf [1]byte
			if _, err := serverConn.Read(buf[:]); err != nil {
				return
			}
		}()

		req, err := http.NewRequest(http.MethodGet, "http://ws.example.com/chat", http.NoBody)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")

		start := time.Now()
		_, _, hsErr := performWSHandshake(context.Background(), clientConn, req, 80*time.Millisecond)
		elapsed := time.Since(start)
		if hsErr == nil {
			t.Fatal("expected handshake deadline error, got nil")
		}
		var ne net.Error
		if !errors.As(hsErr, &ne) || !ne.Timeout() {
			t.Fatalf("expected timeout net.Error, got %v", hsErr)
		}
		if elapsed > 2*time.Second {
			t.Fatalf("handshake took %v, expected prompt timeout near 80ms", elapsed)
		}
		closeQuietly(clientConn)
		closeQuietly(serverConn)
		<-drained
	})

	t.Run("clears deadline after 101", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			closeQuietly(clientConn)
			closeQuietly(serverConn)
		})

		done := make(chan struct{})
		go func() {
			defer close(done)
			req, err := http.ReadRequest(bufio.NewReader(serverConn))
			if err != nil {
				return
			}
			closeQuietly(req.Body)
			if _, err := io.WriteString(serverConn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
				return
			}
			// Wait past the 80ms handshake timeout before sending post-upgrade data.
			time.Sleep(130 * time.Millisecond)
			if _, err := io.WriteString(serverConn, "ok"); err != nil {
				return
			}
		}()

		req, err := http.NewRequest(http.MethodGet, "http://ws.example.com/chat", http.NoBody)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")

		upReader, resp, err := performWSHandshake(context.Background(), clientConn, req, 80*time.Millisecond)
		if err != nil {
			t.Fatalf("performWSHandshake: %v", err)
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("status = %d, want 101", resp.StatusCode)
		}
		buf := make([]byte, 2)
		if _, err := io.ReadFull(upReader, buf); err != nil {
			t.Fatalf("post-handshake read failed (deadline not cleared?): %v", err)
		}
		if string(buf) != "ok" {
			t.Fatalf("post-handshake data = %q, want ok", buf)
		}
		<-done
	})
}
