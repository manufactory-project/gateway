// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

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
func (f failingListener) Addr() net.Addr            { return &net.UnixAddr{Name: "test", Net: "unix"} }

func TestServeUntilClosedReportsPermanentAcceptError(t *testing.T) {
	permErr := errors.New("admin permanent accept failure")
	var got error
	serveUntilClosed(&http.Server{}, failingListener{err: permErr}, func(err error) {
		got = err
	})
	if !errors.Is(got, permErr) {
		t.Fatalf("onServeError = %v, want %v", got, permErr)
	}
}
