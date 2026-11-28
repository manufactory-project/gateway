// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestShutdownRefusesNewRequests pins that once Shutdown has begun a request is
// refused before it can admit or register a flow.
func TestShutdownRefusesNewRequests(t *testing.T) {
	s := &Server{flows: NewFlowRegistry(), transport: &http.Transport{}}
	if !s.enter() {
		t.Fatal("control: a request before Shutdown must be admitted")
	}
	s.handlers.Done()

	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if s.enter() {
		t.Fatal("request admitted after Shutdown began")
	}
	rec := httptest.NewRecorder()
	s.serveHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil), 443)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("serveHTTP after Shutdown = %d, want 503", rec.Code)
	}
	if n := s.flows.Count(); n != 0 {
		t.Fatalf("flows after Shutdown = %d, want 0", n)
	}
}
