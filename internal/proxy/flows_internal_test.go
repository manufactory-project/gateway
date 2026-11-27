package proxy

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestActiveFlowSetUpstreamConnAfterTeardownClosesImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	guestA, guestB := net.Pipe()
	t.Cleanup(func() {
		closeQuietly(guestA)
		closeQuietly(guestB)
	})
	upA, upB := net.Pipe()
	t.Cleanup(func() {
		closeQuietly(upA)
		closeQuietly(upB)
	})

	reg := NewFlowRegistry()
	af := reg.register(FlowInfo{Principal: "p1", Host: "example.com", Port: 443}, cancel, guestA)

	if err := upB.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	// Teardown runs BEFORE upstream connection is attached.
	af.teardown()
	if ctx.Err() == nil {
		t.Fatal("teardown did not cancel flow context")
	}

	// Now upstream dial finishes and calls setUpstreamConn -> MUST close upA immediately!
	af.setUpstreamConn(upA)

	var buf [1]byte
	if _, err := upB.Read(buf[:]); err == nil {
		t.Fatal("expected upB read to see EOF/closed after setUpstreamConn on torn-down flow")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("upstream conn was NOT closed by setUpstreamConn after teardown")
	}
}
