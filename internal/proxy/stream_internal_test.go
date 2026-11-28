package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/manufactory-project/gateway/internal/secret"
)

// steppedBody calls one step per Read, so a test can inspect what the guest has
// received at the moment the proxy goes back to the upstream for more.
type steppedBody struct {
	steps []func(p []byte) int
}

func (b *steppedBody) Read(p []byte) (int, error) {
	if len(b.steps) == 0 {
		return 0, io.EOF
	}
	step := b.steps[0]
	b.steps = b.steps[1:]
	return step(p), nil
}

func (b *steppedBody) Close() error { return nil }

func TestBoundResponseIsDeliveredBeforeTheNextUpstreamRead(t *testing.T) {
	const event = "data: first\n\n"
	redactor := secret.NewRedactor([]secret.Pair{{Placeholder: "mf_ph_key", Value: "sk-a-much-longer-secret-than-the-event"}})
	rec := httptest.NewRecorder()
	body := &steppedBody{steps: []func([]byte) int{
		func(p []byte) int {
			if !rec.Flushed {
				t.Error("headers not flushed before the first body read")
			}
			return copy(p, event)
		},
		func([]byte) int {
			if got := rec.Body.String(); got != event {
				t.Errorf("delivered before the second read = %q, want %q", got, event)
			}
			return 0
		},
	}}

	resp := &http.Response{StatusCode: http.StatusOK, ContentLength: -1, Header: http.Header{}, Body: body}
	if _, err := writeProxiedResponse(rec, resp, redactor); err != nil {
		t.Fatalf("writeProxiedResponse: %v", err)
	}
}
