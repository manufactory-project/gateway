package proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"syscall"
	"testing"

	"github.com/manufactory-project/gateway/internal/netguard"
)

func TestUpstreamErrorTextClassifiesByTypeAndNeverQuotesAfterDial(t *testing.T) {
	const quoted = "sk-reflected-secret"
	wrap := func(err error) error { return fmt.Errorf("transport broken near %q: %w", quoted, err) }
	dial := &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
	blocked := fmt.Errorf("guard: %w", netguard.ErrBlockedAddress)
	for _, tc := range []struct {
		err  error
		want string
	}{
		{dial, dial.Error()},
		{blocked, blocked.Error()},
		{wrap(os.ErrDeadlineExceeded), "upstream-error: timeout"},
		{wrap(tls.AlertError(40)), "upstream-error: tls"},
		{wrap(tls.RecordHeaderError{Msg: quoted}), "upstream-error: tls"},
		{wrap(io.EOF), "upstream-error: connection-closed"},
		{wrap(io.ErrUnexpectedEOF), "upstream-error: connection-closed"},
		{wrap(&net.OpError{Op: "read", Err: syscall.ECONNRESET}), "upstream-error: connection-closed"},
		{wrap(textproto.ProtocolError(quoted)), "upstream-error: malformed-response"},
		{wrap(errors.New(quoted)), "upstream-error"},
	} {
		if got := upstreamErrorText(tc.err); got != tc.want {
			t.Errorf("upstreamErrorText(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}
