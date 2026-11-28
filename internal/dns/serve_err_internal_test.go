// SPDX-License-Identifier: AGPL-3.0-or-later

package dns

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"

	mdns "github.com/miekg/dns"
)

type failingListener struct {
	err error
}

func (f failingListener) Accept() (net.Conn, error) { return nil, f.err }
func (f failingListener) Close() error              { return nil }
func (f failingListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestServeDNSUntilClosedReportsPermanentAcceptError(t *testing.T) {
	permErr := errors.New("dns permanent accept failure")
	var shuttingDown atomic.Bool
	var got error
	srv := &mdns.Server{Listener: failingListener{err: permErr}}
	serveDNSUntilClosed(srv, &shuttingDown, func(err error) {
		got = err
	})
	if !errors.Is(got, permErr) {
		t.Fatalf("onServeError = %v, want %v", got, permErr)
	}

	shuttingDown.Store(true)
	var afterShutdown error
	serveDNSUntilClosed(&mdns.Server{Listener: failingListener{err: permErr}}, &shuttingDown, func(err error) {
		afterShutdown = err
	})
	if afterShutdown != nil {
		t.Fatalf("expected nil onServeError during shutdown, got %v", afterShutdown)
	}
}
