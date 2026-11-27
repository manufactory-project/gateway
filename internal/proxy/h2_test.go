package proxy_test

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTP2GRPCTrailersAndSSEFlush(t *testing.T) {
	sseGate := make(chan struct{})
	var seenUpH2 atomic.Bool

	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"api.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor == 2 {
				seenUpH2.Store(true)
			}
			switch r.URL.Path {
			case "/v1/grpc":
				w.Header().Set("Trailer", "Grpc-Status")
				w.Header().Set("Content-Type", "application/grpc")
				w.WriteHeader(http.StatusOK)
				if _, err := io.WriteString(w, "grpc-payload"); err != nil {
					return
				}
				w.Header().Set("Grpc-Status", "0")
			case "/v1/sse":
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				rc := http.NewResponseController(w)
				if _, err := io.WriteString(w, "data: chunk1\n\n"); err != nil {
					return
				}
				if err := rc.Flush(); err != nil {
					return
				}
				<-sseGate
				if _, err := io.WriteString(w, "data: chunk2\n\n"); err != nil {
					return
				}
				if err := rc.Flush(); err != nil {
					return
				}
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}),
		RulesYAML: `
  - id: allow-api
    principal: worker-test
    effect: allow
    hosts: [api.example.com]
    ports: [443]
    methods: [GET, POST]
    paths: ["/v1/**"]
`,
	})

	// 1. HTTP/2 end-to-end with gRPC trailer forwarding.
	rH2, err := gw.H2Client(t, "api.example.com").Get("https://api.example.com/v1/grpc")
	if err != nil {
		t.Fatalf("H2 gRPC request: %v", err)
	}
	h2Body, err := io.ReadAll(rH2.Body)
	if err != nil {
		t.Fatalf("read H2 body: %v", err)
	}
	if err := rH2.Body.Close(); err != nil {
		t.Fatalf("close H2 body: %v", err)
	}
	if rH2.ProtoMajor != 2 || !seenUpH2.Load() {
		t.Fatalf("expected HTTP/2 end-to-end (client=%s upstreamH2=%v)", rH2.Proto, seenUpH2.Load())
	}
	if string(h2Body) != "grpc-payload" || rH2.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("H2 trailer mismatch: body=%q trailer=%v", h2Body, rH2.Trailer)
	}

	// 2. SSE per-chunk flushing before upstream EOF.
	rSSE, err := gw.H1Client(t, "api.example.com").Get("https://api.example.com/v1/sse")
	if err != nil {
		t.Fatalf("GET SSE: %v", err)
	}
	sseReader := bufio.NewReader(rSSE.Body)
	line1, err := sseReader.ReadString('\n')
	if err != nil {
		t.Fatalf("read SSE chunk1 before EOF: %v", err)
	}
	if line1 != "data: chunk1\n" {
		t.Fatalf("SSE chunk1 = %q", line1)
	}
	close(sseGate)
	restSSE, err := io.ReadAll(sseReader)
	if err != nil {
		t.Fatalf("read rest SSE: %v", err)
	}
	if err := rSSE.Body.Close(); err != nil {
		t.Fatalf("close SSE: %v", err)
	}
	if !strings.Contains(string(restSSE), "data: chunk2") {
		t.Fatalf("SSE missing chunk2: %q", restSSE)
	}
}

func TestHTTP2AuthorityAndPortMismatch(t *testing.T) {
	var httpsHits atomic.Int32
	gw := newTestGateway(t, testGatewaySpec{
		Hosts: []string{"h2a.example.com", "h2b.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			httpsHits.Add(1)
			w.WriteHeader(http.StatusOK)
			if _, err := io.WriteString(w, "ok"); err != nil {
				return
			}
		}),
		RulesYAML: `
  - id: allow-h2
    principal: worker-test
    effect: allow
    hosts: [h2a.example.com, h2b.example.com]
    ports: [443]
`,
	})

	cH2A := gw.H2Client(t, "h2a.example.com")
	for _, badAuth := range []string{"h2b.example.com", "h2a.example.com:8443"} {
		req, err := http.NewRequest(http.MethodGet, "https://h2a.example.com/ok", nil)
		if err != nil {
			t.Fatalf("NewRequest H2 %s: %v", badAuth, err)
		}
		req.Host = badAuth
		r, err := cH2A.Do(req)
		if err != nil {
			t.Fatalf("Do H2 %s: %v", badAuth, err)
		}
		if err := r.Body.Close(); err != nil {
			t.Fatalf("close H2 %s: %v", badAuth, err)
		}
		if r.ProtoMajor != 2 || r.StatusCode != http.StatusForbidden {
			t.Fatalf("H2 :authority=%q got proto=%s status=%d, want HTTP/2 403", badAuth, r.Proto, r.StatusCode)
		}
	}
	if httpsHits.Load() != 0 {
		t.Fatalf("H2 :authority/port mismatch hit upstream: %d != 0", httpsHits.Load())
	}

	// Positive control over H2 with matching :authority and explicit :443.
	reqOK, err := http.NewRequest(http.MethodGet, "https://h2a.example.com/ok", nil)
	if err != nil {
		t.Fatalf("NewRequest H2 ok: %v", err)
	}
	reqOK.Host = "h2a.example.com:443"
	rOK, err := cH2A.Do(reqOK)
	if err != nil {
		t.Fatalf("Do H2 ok: %v", err)
	}
	if err := rOK.Body.Close(); err != nil {
		t.Fatalf("close H2 ok: %v", err)
	}
	if rOK.ProtoMajor != 2 || rOK.StatusCode != http.StatusOK {
		t.Fatalf("H2 matching :authority:443 got proto=%s status=%d", rOK.Proto, rOK.StatusCode)
	}
}

func TestHTTP2GrantIsolationAcrossConnections(t *testing.T) {
	streamOpenCh := make(chan string, 8)
	releaseHold := make(chan struct{})
	releaseC := make(chan struct{})

	gw := newTestGateway(t, testGatewaySpec{
		OnCleanupFirst: func() { close(releaseHold) },
		Hosts:          []string{"h2grant.example.com"},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			rc := http.NewResponseController(w)
			if r.URL.Path == "/stream-c" {
				if _, err := io.WriteString(w, "data: c-start\n\n"); err != nil {
					return
				}
				if err := rc.Flush(); err != nil {
					return
				}
				streamOpenCh <- r.URL.Path
				<-releaseC
				if _, err := io.WriteString(w, "data: c-done\n\n"); err != nil {
					return
				}
				if err := rc.Flush(); err != nil {
					return
				}
				return
			}
			if _, err := io.WriteString(w, "data: "+r.URL.Path+"\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			streamOpenCh <- r.URL.Path
			<-releaseHold
		}),
	})

	gA, err := gw.Store.AddGrant("worker-test", "h2grant.example.com", 443, []string{"GET"}, []string{"/stream-a"}, 5*time.Minute, false)
	if err != nil {
		t.Fatalf("AddGrant gA: %v", err)
	}
	gB, err := gw.Store.AddGrant("worker-test", "h2grant.example.com", 443, []string{"GET"}, []string{"/stream-b"}, 5*time.Minute, false)
	if err != nil {
		t.Fatalf("AddGrant gB: %v", err)
	}
	gC, err := gw.Store.AddGrant("worker-test", "h2grant.example.com", 443, []string{"GET"}, []string{"/stream-c"}, 5*time.Minute, false)
	if err != nil {
		t.Fatalf("AddGrant gC: %v", err)
	}

	cMux := gw.H2Client(t, "h2grant.example.com")
	cSep := gw.H2Client(t, "h2grant.example.com")

	rA, err := cMux.Get("https://h2grant.example.com/stream-a")
	if err != nil {
		t.Fatalf("GET /stream-a: %v", err)
	}
	<-streamOpenCh
	rB, err := cMux.Get("https://h2grant.example.com/stream-b")
	if err != nil {
		t.Fatalf("GET /stream-b: %v", err)
	}
	<-streamOpenCh
	rC, err := cSep.Get("https://h2grant.example.com/stream-c")
	if err != nil {
		t.Fatalf("GET /stream-c: %v", err)
	}
	<-streamOpenCh

	// All three distinct grant IDs are tracked independently without overwriting per connection.
	seenGrants := make(map[string]bool)
	for _, f := range gw.Flows.List() {
		seenGrants[f.GrantID] = true
	}
	if !seenGrants[gA.ID] || !seenGrants[gB.ID] || !seenGrants[gC.ID] {
		t.Fatalf("missing distinct grantIDs in active flows: got %v, want %s/%s/%s", seenGrants, gA.ID, gB.ID, gC.ID)
	}

	// Revoke gA: tears down stream A while leaving separate connection stream C intact.
	gw.Store.RevokeGrant(gA.ID)
	if n := gw.Flows.RevokeByGrant(gA.ID); n != 1 {
		t.Fatalf("RevokeByGrant(gA) = %d, want 1", n)
	}
	doneA := make(chan error, 1)
	go func() {
		_, rErr := io.ReadAll(rA.Body)
		doneA <- rErr
	}()
	select {
	case <-doneA:
	case <-time.After(2 * time.Second):
		t.Fatal("stream A was not torn down on gA revoke")
	}
	if err := rA.Body.Close(); err != nil {
		t.Logf("close rA: %v", err)
	}
	if err := rB.Body.Close(); err != nil {
		t.Logf("close rB: %v", err)
	}

	// Separate connection stream C survives and completes cleanly once releaseC closes.
	close(releaseC)
	bodyC, err := io.ReadAll(rC.Body)
	if err != nil {
		t.Fatalf("separate conn stream C broke when gA was revoked: %v", err)
	}
	if err := rC.Body.Close(); err != nil {
		t.Fatalf("close rC: %v", err)
	}
	if !strings.Contains(string(bodyC), "c-done") {
		t.Fatalf("stream C did not complete cleanly: %q", bodyC)
	}
}
