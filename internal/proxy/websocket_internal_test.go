// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestDialWebSocketUpstreamBoundsTLSHandshake(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	var accepted []net.Conn
	var mu sync.Mutex
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			mu.Lock()
			accepted = append(accepted, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		if cErr := ln.Close(); cErr != nil {
			t.Errorf("close listener: %v", cErr)
		}
		wg.Wait()
		mu.Lock()
		for _, c := range accepted {
			if cErr := c.Close(); cErr != nil {
				t.Errorf("close accepted conn: %v", cErr)
			}
		}
		mu.Unlock()
	})

	srv := &Server{
		dialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, ln.Addr().String())
		},
	}

	parentCtx, parentCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer parentCancel()

	conn, dialErr := srv.dialWebSocketUpstreamWithTimeout(parentCtx, "stall.example.com", 443, 60*time.Millisecond)
	if conn != nil {
		if cErr := conn.Close(); cErr != nil {
			t.Errorf("close conn: %v", cErr)
		}
	}
	if !errors.Is(dialErr, context.DeadlineExceeded) {
		t.Fatalf("dialWebSocketUpstreamWithTimeout err = %v, want context.DeadlineExceeded", dialErr)
	}
	if parentCtx.Err() != nil {
		t.Fatalf("parentCtx was canceled (%v); HandshakeContext did not honor tlsTimeout", parentCtx.Err())
	}
}
