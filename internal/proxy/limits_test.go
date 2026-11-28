// SPDX-License-Identifier: AGPL-3.0-only

package proxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/proxy"
)

const (
	// guard bounds how long a test waits for the gateway to cut a guest off. It
	// only turns a missing limit into a failed assertion instead of a hung test;
	// a working gateway answers in milliseconds to a few hundred.
	guard = 5 * time.Second
	// A limit of N per second is spent after N events; refill during a test run is
	// well under this many more even with -race.
	budgetSlack = 5
)

func allowRule(hosts ...string) string {
	return fmt.Sprintf(`
  - id: allow-test
    principal: %%s
    effect: allow
    hosts: [%s]
    ports: [443]
`, strings.Join(hosts, ", "))
}

// newPeer starts a second link of the same daemon: its own store, listeners and
// limits, but the same audit writer as gw.
func newPeer(t *testing.T, gw *testGateway, host string) *testGateway {
	t.Helper()
	return newTestGateway(t, testGatewaySpec{
		Principal:      "worker-peer",
		ShareAuditWith: gw,
		Hosts:          []string{host},
		RulesYAML:      fmt.Sprintf(allowRule(host), "worker-peer"),
	})
}

func mustGet(t *testing.T, gw *testGateway, host string) {
	t.Helper()
	resp, err := gw.H1Client(t, host).Get("https://" + host + "/")
	if err != nil {
		t.Fatalf("GET %s: %v", host, err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", host, resp.StatusCode)
	}
}

func shutdownProxy(t *testing.T, gw *testGateway) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := gw.Server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

var limitedMetric = regexp.MustCompile(`gateway_limited_total\{link="sbx0",reason="([^"]+)"\} (\d+)`)

func limitedCount(gw *testGateway, reason string) int {
	for _, m := range limitedMetric.FindAllStringSubmatch(scrapeMetrics(gw), -1) {
		if m[1] == reason {
			n, err := strconv.Atoi(m[2])
			if err != nil {
				return -1
			}
			return n
		}
	}
	return 0
}

// summaryCount returns the sum of Count over the summary records with reason.
func summaryCount(t *testing.T, gw *testGateway, reason string) (records int, total int) {
	t.Helper()
	for _, ev := range gw.AuditEvents(t) {
		if ev.Reason == reason {
			records++
			total += int(ev.Count)
		}
	}
	return records, total
}

func TestDeniedHandshakeFloodIsRateLimited(t *testing.T) {
	const (
		rate  = 3
		flood = 60
	)
	gw := newTestGateway(t, testGatewaySpec{
		Hosts:         []string{"ok.example.com"},
		HTTPBlockYAML: fmt.Sprintf("http:\n  max_denied_handshakes_per_second: %d\n", rate),
		RulesYAML:     fmt.Sprintf(allowRule("ok.example.com"), "worker-test"),
	})
	peer := newPeer(t, gw, "ok.example.com")

	for i := range flood {
		conn, err := tls.Dial("tcp", gw.HTTPSAddr, &tls.Config{
			ServerName: fmt.Sprintf("denied-%d.example.net", i),
			RootCAs:    gw.MITMRoots,
			MinVersion: tls.VersionTLS12,
		})
		if err == nil {
			if cErr := conn.Close(); cErr != nil {
				t.Logf("close: %v", cErr)
			}
			t.Fatalf("handshake %d for a denied SNI succeeded", i)
		}
	}

	// Positive controls: an allowed name on the flooded link, and the peer link,
	// are served while the denied flood is being dropped.
	mustGet(t, gw, "ok.example.com")
	mustGet(t, peer, "ok.example.com")

	audited := 0
	for _, ev := range gw.AuditEvents(t) {
		if ev.Protocol == "tls" && strings.HasPrefix(ev.Host, "denied-") {
			audited++
		}
	}
	if audited < rate || audited > rate+budgetSlack {
		t.Fatalf("denied handshakes audited = %d of %d, want between %d and %d", audited, flood, rate, rate+budgetSlack)
	}
	limited := limitedCount(gw, proxy.ReasonDeniedHandshakeLimited)
	if audited+limited != flood {
		t.Fatalf("audited %d + limited %d != %d handshakes: some were neither recorded nor counted", audited, limited, flood)
	}

	shutdownProxy(t, gw)
	if records, total := summaryCount(t, gw, proxy.ReasonDeniedHandshakeLimited); records != 1 || total != limited {
		t.Fatalf("summary records = %d covering %d, want 1 covering %d", records, total, limited)
	}
}

func TestLeafMintFloodIsRateLimited(t *testing.T) {
	const (
		rate  = 3
		flood = 40
	)
	gw := newTestGateway(t, testGatewaySpec{
		CountCASigns:  true,
		HTTPBlockYAML: fmt.Sprintf("http:\n  max_new_leaves_per_second: %d\n", rate),
		RulesYAML:     fmt.Sprintf(allowRule(`"*.zone.example"`), "worker-test"),
	})
	handshake := func(name string) error {
		conn, err := tls.Dial("tcp", gw.HTTPSAddr, &tls.Config{ServerName: name, RootCAs: gw.MITMRoots, MinVersion: tls.VersionTLS12})
		if err != nil {
			return err
		}
		return conn.Close()
	}

	var minted []string
	for i := range flood {
		name := fmt.Sprintf("l%d.zone.example", i)
		if err := handshake(name); err == nil {
			minted = append(minted, name)
		}
	}
	if len(minted) < rate || len(minted) > rate+budgetSlack {
		t.Fatalf("leaves minted for %d random allowed names = %d, want between %d and %d", flood, len(minted), rate, rate+budgetSlack)
	}
	if signs := int(gw.CASigns.signs.Load()); signs != len(minted) {
		t.Fatalf("CA signatures = %d, want %d (one per minted leaf)", signs, len(minted))
	}
	if got := limitedCount(gw, proxy.ReasonLeafMintLimited); got != flood-len(minted) {
		t.Fatalf("leaf-mint limited = %d, want %d", got, flood-len(minted))
	}

	// Positive control: with the mint budget spent, a name already cached is
	// still served, without another signature.
	if err := handshake(minted[0]); err != nil {
		t.Fatalf("cached leaf %s refused after the mint budget was spent: %v", minted[0], err)
	}
	if signs := int(gw.CASigns.signs.Load()); signs != len(minted) {
		t.Fatalf("CA signatures after a cache hit = %d, want %d", signs, len(minted))
	}
}

func TestInflightRequestsPerLinkAreCapped(t *testing.T) {
	const (
		limit = 4
		burst = 12
	)
	arrived := make(chan struct{}, burst)
	release := make(chan struct{})
	gw := newTestGateway(t, testGatewaySpec{
		Hosts:         []string{"hold.example.com"},
		HTTPBlockYAML: fmt.Sprintf("http:\n  max_inflight_per_link: %d\n", limit),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/hold" {
				arrived <- struct{}{}
				<-release
			}
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: fmt.Sprintf(allowRule("hold.example.com"), "worker-test"),
	})
	peer := newPeer(t, gw, "ok.example.com")
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseAll)

	// One H2 connection carries the whole burst, as a guest multiplexing streams would.
	client := gw.H2Client(t, "hold.example.com")
	statuses := make(chan int, burst)
	for range burst {
		go func() {
			resp, err := client.Get("https://hold.example.com/hold")
			if err != nil {
				statuses <- -1
				return
			}
			if err := resp.Body.Close(); err != nil {
				statuses <- -2
				return
			}
			statuses <- resp.StatusCode
		}()
	}
	// The refused requests answer at once; the admitted ones are held upstream.
	for range burst - limit {
		select {
		case got := <-statuses:
			if got != http.StatusServiceUnavailable {
				t.Fatalf("request over the in-flight cap: status %d, want 503", got)
			}
		case <-time.After(guard):
			t.Fatal("requests over the in-flight cap were held instead of refused")
		}
	}
	for range limit {
		<-arrived
	}

	// Another link is unaffected while this one is at its cap.
	mustGet(t, peer, "ok.example.com")

	releaseAll()
	for range limit {
		if got := <-statuses; got != http.StatusOK {
			t.Fatalf("admitted request: status %d, want 200", got)
		}
	}
	// A freed slot is reusable.
	if resp, err := client.Get("https://hold.example.com/"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("request after the burst drained: %v %v", resp, err)
	}
	if got := limitedCount(gw, proxy.ReasonInflightLimited); got != burst-limit {
		t.Fatalf("inflight limited = %d, want %d", got, burst-limit)
	}
	shutdownProxy(t, gw)
	if records, total := summaryCount(t, gw, proxy.ReasonInflightLimited); records != 1 || total != burst-limit {
		t.Fatalf("summary records = %d covering %d, want 1 covering %d", records, total, burst-limit)
	}
}

// TestHTTP2StreamsPerConnectionAreCapped reads the SETTINGS frame the gateway
// sends a guest: the concurrent-stream cap there is what keeps one connection
// from fanning out into thousands of upstream requests.
func TestHTTP2StreamsPerConnectionAreCapped(t *testing.T) {
	gw := newTestGateway(t, testGatewaySpec{
		Hosts:     []string{"h2.example.com"},
		RulesYAML: fmt.Sprintf(allowRule("h2.example.com"), "worker-test"),
	})
	conn, err := tls.Dial("tcp", gw.HTTPSAddr, &tls.Config{
		ServerName: "h2.example.com",
		RootCAs:    gw.MITMRoots,
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Logf("close: %v", err)
		}
	})
	if got := conn.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("negotiated protocol = %q, want h2", got)
	}
	if err := conn.SetDeadline(time.Now().Add(guard)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	// Client preface and an empty SETTINGS frame.
	if _, err := io.WriteString(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00"); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	const settingsMaxConcurrentStreams = 0x3
	br := bufio.NewReader(conn)
	for {
		var hdr [9]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			t.Fatalf("read frame header: %v", err)
		}
		length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		payload := make([]byte, length)
		if _, err := io.ReadFull(br, payload); err != nil {
			t.Fatalf("read frame payload: %v", err)
		}
		const frameSettings, flagAck = 0x4, 0x1
		if hdr[3] != frameSettings || hdr[4]&flagAck != 0 {
			continue
		}
		for ; len(payload) >= 6; payload = payload[6:] {
			if binary.BigEndian.Uint16(payload) == settingsMaxConcurrentStreams {
				if got := binary.BigEndian.Uint32(payload[2:]); got != 100 {
					t.Fatalf("advertised MAX_CONCURRENT_STREAMS = %d, want 100", got)
				}
				return
			}
		}
		t.Fatal("server SETTINGS carry no MAX_CONCURRENT_STREAMS: the stream cap is unset")
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

func TestSlowHeaderGuestIsCutOff(t *testing.T) {
	gw := newTestGateway(t, testGatewaySpec{
		Hosts:         []string{"slow.example.com"},
		HTTPBlockYAML: "http:\n  read_header_timeout: 300ms\n",
		RulesYAML:     fmt.Sprintf(allowRule("slow.example.com"), "worker-test"),
	})
	peer := newPeer(t, gw, "ok.example.com")

	// waitClosed blocks until the gateway closes conn, failing if only the test's
	// own guard deadline ends the wait.
	waitClosed := func(t *testing.T, conn net.Conn) {
		t.Helper()
		if err := conn.SetReadDeadline(time.Now().Add(guard)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		if _, err := io.Copy(io.Discard, conn); isTimeout(err) {
			t.Fatalf("gateway held a stalled guest connection past its header timeout: %v", err)
		}
	}

	t.Run("stalled TLS handshake", func(t *testing.T) {
		conn, err := net.Dial("tcp4", gw.HTTPSAddr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer func() {
			if err := conn.Close(); err != nil {
				t.Logf("close: %v", err)
			}
		}()
		waitClosed(t, conn)
	})
	t.Run("stalled request headers", func(t *testing.T) {
		conn := gw.DialTLS(t, "slow.example.com")
		defer func() {
			if err := conn.Close(); err != nil {
				t.Logf("close: %v", err)
			}
		}()
		if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: slow.example.com\r\nX-Slow: a"); err != nil {
			t.Fatalf("write partial headers: %v", err)
		}
		waitClosed(t, conn)
	})

	// Positive controls: a prompt request on the same link, and the peer link.
	mustGet(t, gw, "slow.example.com")
	mustGet(t, peer, "ok.example.com")
}

func TestStalledRequestBodyIsCutOff(t *testing.T) {
	var completed atomic.Int32
	gw := newTestGateway(t, testGatewaySpec{
		Hosts:         []string{"body.example.com"},
		HTTPBlockYAML: "http:\n  stream_idle_timeout: 300ms\n",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				return
			}
			completed.Add(1)
			w.WriteHeader(http.StatusOK)
		}),
		RulesYAML: fmt.Sprintf(allowRule("body.example.com"), "worker-test"),
	})
	peer := newPeer(t, gw, "ok.example.com")

	cutRecords := func() (n int) {
		for _, ev := range gw.AuditEvents(t) {
			if ev.Error == "guest-idle-timeout" {
				n++
			}
		}
		return n
	}
	post := func(t *testing.T, c *http.Client, body io.Reader) (*http.Response, error) {
		t.Helper()
		return c.Post("https://body.example.com/", "text/plain", body)
	}

	t.Run("http1", func(t *testing.T) {
		conn := gw.DialTLS(t, "body.example.com")
		defer func() {
			if err := conn.Close(); err != nil {
				t.Logf("close: %v", err)
			}
		}()
		// Promises 100 bytes, sends one, then goes quiet.
		if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: body.example.com\r\nContent-Length: 100\r\n\r\nx"); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(guard)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		if _, err := io.Copy(io.Discard, conn); isTimeout(err) {
			t.Fatalf("gateway held a guest that stalled its request body past the stream idle timeout: %v", err)
		}
		if got := cutRecords(); got != 1 {
			t.Fatalf("completion records with guest-idle-timeout = %d, want 1", got)
		}
	})

	t.Run("http2", func(t *testing.T) {
		client := gw.H2Client(t, "body.example.com")
		pr, pw := io.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), guard)
		defer cancel()
		// Unblocks the test's own request body if the gateway never cuts the guest off.
		context.AfterFunc(ctx, func() { pw.CloseWithError(ctx.Err()) })
		go func() {
			// One byte, then the guest goes quiet with the body still open.
			if _, err := pw.Write([]byte("x")); err != nil {
				return
			}
		}()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://body.example.com/", pr)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp, err := client.Do(req)
		if ctx.Err() != nil {
			t.Fatal("gateway held a guest that stalled its request body past the stream idle timeout")
		}
		if err == nil {
			if cErr := resp.Body.Close(); cErr != nil {
				t.Fatalf("close body: %v", cErr)
			}
			t.Fatalf("stalled body was answered with status %d, want the stream cut", resp.StatusCode)
		}
		if got := cutRecords(); got != 2 {
			t.Fatalf("completion records with guest-idle-timeout = %d, want 2", got)
		}
	})
	if completed.Load() != 0 {
		t.Fatal("upstream saw a complete body from a guest that never finished sending")
	}

	// Positive control: a body that completes is relayed, on both protocols, and
	// the peer link is served.
	for name, c := range map[string]*http.Client{"http1": gw.H1Client(t, "body.example.com"), "http2": gw.H2Client(t, "body.example.com")} {
		resp, err := post(t, c, strings.NewReader("whole body"))
		if err != nil {
			t.Fatalf("complete POST over %s: %v", name, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("close body: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("complete POST over %s: status %d, want 200", name, resp.StatusCode)
		}
	}
	if completed.Load() != 2 {
		t.Fatalf("upstream completed bodies = %d, want 2", completed.Load())
	}
	mustGet(t, peer, "ok.example.com")
}

// anyKeyCache is a client session cache that offers its one session whatever
// server name is asked for, as a guest crafting a resumption would.
type anyKeyCache struct {
	mu    sync.Mutex
	state *tls.ClientSessionState
}

func (c *anyKeyCache) Get(string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state, c.state != nil
}

func (c *anyKeyCache) Put(_ string, s *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = s
}

// TestResumedHandshakeIsPolicyCheckedAndAudited holds a session ticket from an
// allowed name and offers it for a denied one. A resumed handshake never calls
// GetCertificate, so the SNI check, audit record and rate limit would all be
// skipped; the gateway issues no tickets, so every handshake is a full one.
func TestResumedHandshakeIsPolicyCheckedAndAudited(t *testing.T) {
	gw := newTestGateway(t, testGatewaySpec{
		Hosts:     []string{"ok.example.com"},
		RulesYAML: fmt.Sprintf(allowRule("ok.example.com"), "worker-test"),
	})
	cache := &anyKeyCache{}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, gw.HTTPSAddr)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         "ok.example.com",
			RootCAs:            gw.MITMRoots,
			MinVersion:         tls.VersionTLS12,
			ClientSessionCache: cache,
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	resp, err := (&http.Client{Transport: tr}).Get("https://ok.example.com/")
	if err != nil {
		t.Fatalf("GET allowed name: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("allowed name status = %d, want 200", resp.StatusCode)
	}
	if _, ok := cache.Get(""); ok {
		t.Fatal("gateway issued a session ticket; resumed handshakes bypass the SNI check")
	}

	// The denied name is refused and audited, even with a session in hand.
	conn, err := tls.Dial("tcp", gw.HTTPSAddr, &tls.Config{
		ServerName:         "denied.example.net",
		RootCAs:            gw.MITMRoots,
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: cache,
	})
	if err == nil {
		resumed := conn.ConnectionState().DidResume
		if cErr := conn.Close(); cErr != nil {
			t.Logf("close: %v", cErr)
		}
		t.Fatalf("handshake for a denied SNI succeeded (resumed: %v)", resumed)
	}
	denied := 0
	for _, ev := range gw.AuditEvents(t) {
		if ev.Protocol == "tls" && ev.Host == "denied.example.net" && ev.Effect == audit.EffectDeny {
			denied++
		}
	}
	if denied != 1 {
		t.Fatalf("denied-SNI audit records = %d, want 1", denied)
	}
}

// A guest that asks for a large response and never reads it must not hold its
// connection, in-flight slot and upstream stream indefinitely, while one that
// reads steadily gets the whole response however long it takes.
func TestUnreadResponseIsCutOff(t *testing.T) {
	const chunk = 64 << 10
	payload := make([]byte, chunk)
	gw := newTestGateway(t, testGatewaySpec{
		Hosts:         []string{"read.example.com"},
		HTTPBlockYAML: "http:\n  stream_idle_timeout: 300ms\n",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			chunks := 64 // 4 MiB: a guest that reads is served it all
			if r.URL.Path == "/stall" {
				chunks = 4096 // 256 MiB: more than any socket buffer holds
			}
			for range chunks {
				if _, err := w.Write(payload); err != nil {
					return
				}
			}
		}),
		RulesYAML: fmt.Sprintf(allowRule("read.example.com"), "worker-test"),
	})

	// Positive control: a guest that keeps reading receives every byte.
	resp, err := gw.H1Client(t, "read.example.com").Get("https://read.example.com/steady")
	if err != nil {
		t.Fatalf("GET /steady: %v", err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	if cErr := resp.Body.Close(); cErr != nil {
		t.Fatalf("close body: %v", cErr)
	}
	if err != nil || n != 64*chunk {
		t.Fatalf("steady reader got %d bytes, err %v; want %d", n, err, 64*chunk)
	}

	conn := gw.DialTLS(t, "read.example.com")
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("close: %v", err)
		}
	}()
	if _, err := io.WriteString(conn, "GET /stall HTTP/1.1\r\nHost: read.example.com\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	cut := func() bool {
		for _, ev := range gw.AuditEvents(t) {
			if ev.Error == "guest-idle-timeout" {
				return true
			}
		}
		return false
	}
	if !gw.Records.until(guard, cut) {
		t.Fatal("gateway never cut off a guest that does not read its response")
	}
}
