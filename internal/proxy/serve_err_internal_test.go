package proxy

import (
	"errors"
	"net"
	"net/http"
	"testing"
)

type failingListener struct {
	err error
}

func (f failingListener) Accept() (net.Conn, error) { return nil, f.err }
func (f failingListener) Close() error              { return nil }
func (f failingListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestServeUntilClosedReportsPermanentAcceptError(t *testing.T) {
	permErr := errors.New("permanent accept failure")
	var got error
	serveUntilClosed(&http.Server{}, failingListener{err: permErr}, func(err error) {
		got = err
	})
	if !errors.Is(got, permErr) {
		t.Fatalf("onServeError = %v, want %v", got, permErr)
	}

	var closedGot error
	serveUntilClosed(&http.Server{}, failingListener{err: http.ErrServerClosed}, func(err error) {
		closedGot = err
	})
	if closedGot != nil {
		t.Fatalf("expected nil onServeError for http.ErrServerClosed, got %v", closedGot)
	}
}
