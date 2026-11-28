// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"errors"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

// A streaming response (SSE, LLM tokens) may legitimately run for hours, so the
// server has no overall read or write timeout. These wrappers bound only the
// time the gateway sits waiting on the guest: each blocking read of the request
// body, and each write of the response, gets a fresh deadline of idle. A guest
// that dribbles a body, or never reads its response, is cut off after idle
// without a byte moving, while a stream that keeps moving is never cut.
//
// The deadline is cleared after a success so it can never fire while the
// connection is idle or the response streams. After a timeout it is left
// expired, so the server's own post-handler body drain fails at once instead of
// waiting on the same guest again.

// guestIdleTimeout is the completion error recorded for a guest cut off by
// either wrapper.
const guestIdleTimeout = "guest-idle-timeout"

// idleBody is a request body whose every Read must make progress within idle.
type idleBody struct {
	io.ReadCloser
	rc      *http.ResponseController
	idle    time.Duration
	expired atomic.Bool
}

func (b *idleBody) Read(p []byte) (int, error) {
	if err := b.rc.SetReadDeadline(time.Now().Add(b.idle)); err != nil {
		return 0, err
	}
	n, err := b.ReadCloser.Read(p)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		b.expired.Store(true)
	}
	if err == nil || errors.Is(err, io.EOF) {
		if clearErr := b.rc.SetReadDeadline(time.Time{}); clearErr != nil {
			return n, clearErr
		}
	}
	return n, err
}

// idleWriter is a response writer whose every Write and Flush must make
// progress within idle.
type idleWriter struct {
	http.ResponseWriter
	rc   *http.ResponseController
	idle time.Duration
}

func (w idleWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w idleWriter) Write(p []byte) (int, error) {
	var n int
	err := w.withDeadline(func() (err error) {
		n, err = w.ResponseWriter.Write(p)
		return err
	})
	return n, err
}

// FlushError makes http.ResponseController.Flush use the deadline too.
func (w idleWriter) FlushError() error { return w.withDeadline(w.rc.Flush) }

func (w idleWriter) withDeadline(op func() error) error {
	if err := w.rc.SetWriteDeadline(time.Now().Add(w.idle)); err != nil {
		return err
	}
	if err := op(); err != nil {
		return err
	}
	return w.rc.SetWriteDeadline(time.Time{})
}
