package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/manufactory-project/gateway/internal/audit"
	"github.com/manufactory-project/gateway/internal/policy"
)

var errWSEgressCapExceeded = errors.New("websocket egress byte cap exceeded")

func (s *Server) serveWebSocket(w http.ResponseWriter, r *http.Request, dstPort uint16, host, srcIP string, dec policy.Decision, outHeaders http.Header, af *activeFlow) {
	targetAddr := net.JoinHostPort(host, strconv.Itoa(int(dstPort)))
	rawUpstream, err := s.dialContext(r.Context(), "tcp", targetAddr)
	if err != nil {
		s.auditWebSocket(srcIP, r, dstPort, host, dec, af.info.ID, http.StatusBadGateway, 0, 0, err.Error())
		http.Error(w, "upstream dial failed", http.StatusBadGateway)
		return
	}

	upConn := rawUpstream
	if dstPort == 443 {
		tlsConn := tls.Client(rawUpstream, &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
			RootCAs:    s.upstreamRoots,
			NextProtos: []string{"http/1.1"},
		})
		if err := tlsConn.HandshakeContext(r.Context()); err != nil {
			if closeErr := rawUpstream.Close(); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
			s.auditWebSocket(srcIP, r, dstPort, host, dec, af.info.ID, http.StatusBadGateway, 0, 0, err.Error())
			http.Error(w, "upstream tls handshake failed", http.StatusBadGateway)
			return
		}
		upConn = tlsConn
	}
	af.setUpstreamConn(upConn)
	defer closeQuietly(upConn)

	if r.Context().Err() != nil {
		s.auditWebSocket(srcIP, r, dstPort, host, dec, af.info.ID, http.StatusBadGateway, 0, 0, r.Context().Err().Error())
		return
	}

	// Rebuild clean HTTP/1.1 WebSocket upgrade request with no body.
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.Proto = "HTTP/1.1"
	outReq.ProtoMajor = 1
	outReq.ProtoMinor = 1
	outReq.Host = host
	outReq.Body = http.NoBody
	outReq.ContentLength = 0
	outReq.TransferEncoding = nil
	outReq.Header = outHeaders
	outReq.Header.Set("Connection", "Upgrade")
	outReq.Header.Set("Upgrade", "websocket")

	if err := outReq.Write(upConn); err != nil {
		s.auditWebSocket(srcIP, r, dstPort, host, dec, af.info.ID, http.StatusBadGateway, 0, 0, err.Error())
		http.Error(w, "upstream write failed", http.StatusBadGateway)
		return
	}

	upReader := bufio.NewReader(upConn)
	resp, err := http.ReadResponse(upReader, outReq)
	if err != nil {
		s.auditWebSocket(srcIP, r, dstPort, host, dec, af.info.ID, http.StatusBadGateway, 0, 0, err.Error())
		http.Error(w, "upstream response failed", http.StatusBadGateway)
		return
	}

	// Non-WebSocket responses: never forward a non-WebSocket 101 Switching Protocols.
	if resp.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		defer closeQuietly(resp.Body)
		if resp.StatusCode == http.StatusSwitchingProtocols {
			s.auditWebSocket(srcIP, r, dstPort, host, dec, af.info.ID, http.StatusBadGateway, 0, 0, "unexpected-101-non-websocket")
			http.Error(w, "unexpected protocol upgrade", http.StatusBadGateway)
			return
		}
		copyEndToEndHeaders(w.Header(), resp.Header, false)
		w.WriteHeader(resp.StatusCode)
		bytesIn, copyErr := copyStreaming(w, resp.Body)
		errText := ""
		if copyErr != nil {
			errText = copyErr.Error()
		}
		s.auditWebSocket(srcIP, r, dstPort, host, dec, af.info.ID, resp.StatusCode, 0, bytesIn, errText)
		return
	}

	if r.Context().Err() != nil {
		s.auditWebSocket(srcIP, r, dstPort, host, dec, af.info.ID, http.StatusBadGateway, 0, 0, r.Context().Err().Error())
		return
	}

	rc := http.NewResponseController(w)
	clientConn, clientBuf, err := rc.Hijack()
	if err != nil {
		s.auditWebSocket(srcIP, r, dstPort, host, dec, af.info.ID, http.StatusInternalServerError, 0, 0, err.Error())
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer closeQuietly(clientConn)

	// Write 101 Switching Protocols response back to client.
	var hdr strings.Builder
	hdr.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	respHdr := make(http.Header)
	copyEndToEndHeaders(respHdr, resp.Header, true)
	respHdr.Set("Connection", "Upgrade")
	respHdr.Set("Upgrade", "websocket")
	if err := respHdr.Write(&hdr); err != nil {
		s.auditWebSocket(srcIP, r, dstPort, host, dec, af.info.ID, http.StatusBadGateway, 0, 0, err.Error())
		return
	}
	hdr.WriteString("\r\n")
	if _, err := io.WriteString(clientConn, hdr.String()); err != nil {
		s.auditWebSocket(srcIP, r, dstPort, host, dec, af.info.ID, http.StatusSwitchingProtocols, 0, 0, err.Error())
		return
	}

	egressCap := dec.WSMaxEgressBytes
	if egressCap <= 0 {
		egressCap = s.store.Current().Config.HTTP.WSMaxEgressBytes
	}

	var (
		bytesOut  int64
		bytesIn   int64
		egressErr error
		closeOnce sync.Once
	)
	closeBoth := func() {
		closeOnce.Do(func() {
			closeQuietly(upConn)
			closeQuietly(clientConn)
		})
	}

	// Ensure context cancellation (revoke / reload / TTL expiry) closes both sockets immediately.
	stopWatch := make(chan struct{})
	var watchWG sync.WaitGroup
	watchWG.Add(1)
	go func() {
		defer watchWG.Done()
		select {
		case <-r.Context().Done():
			closeBoth()
		case <-stopWatch:
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Upstream with strict egress byte cap.
	go func() {
		defer wg.Done()
		defer closeBoth()
		cw := &cappedWriter{w: upConn, limit: egressCap}
		n, copyErr := io.Copy(cw, clientBuf)
		bytesOut = n
		if errors.Is(copyErr, errWSEgressCapExceeded) {
			egressErr = errWSEgressCapExceeded
		}
	}()

	// Upstream -> Client.
	go func() {
		defer wg.Done()
		defer closeBoth()
		n, copyErr := io.Copy(clientConn, upReader)
		bytesIn = n
		if copyErr != nil {
			return
		}
	}()

	wg.Wait()
	close(stopWatch)
	watchWG.Wait()

	errText := ""
	if egressErr != nil {
		errText = fmt.Sprintf("ws-egress-cap-exceeded:%d", egressCap)
	}
	s.auditWebSocket(srcIP, r, dstPort, host, dec, af.info.ID, http.StatusSwitchingProtocols, bytesOut, bytesIn, errText)
}

func (s *Server) auditWebSocket(srcIP string, r *http.Request, dstPort uint16, host string, dec policy.Decision, flowID string, status int, bytesOut, bytesIn int64, errText string) {
	ev := audit.Event{
		Kind:      audit.KindWebSocket,
		Principal: s.link.Principal,
		Link:      s.link.Name,
		SrcIP:     srcIP,
		Protocol:  "websocket",
		Host:      host,
		Port:      int(dstPort),
		Method:    r.Method,
		Path:      r.URL.Path,
		HasQuery:  r.URL.RawQuery != "",
		Status:    status,
		Effect:    audit.EffectAllow,
		Reason:    dec.Reason,
		RuleID:    dec.RuleID,
		GrantID:   dec.GrantID,
		FlowID:    flowID,
		BytesOut:  bytesOut,
		BytesIn:   bytesIn,
		Error:     errText,
	}
	if err := s.audit.WriteSync(ev); err != nil {
		return
	}
	if s.onRequest != nil {
		s.onRequest(s.link.Principal, string(audit.EffectAllow), status)
	}
}

func closeQuietly(c io.Closer) {
	if err := c.Close(); err != nil {
		return
	}
}

type cappedWriter struct {
	w       io.Writer
	limit   int64
	written int64
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	rem := c.limit - c.written
	if rem <= 0 {
		return 0, errWSEgressCapExceeded
	}
	if int64(len(p)) > rem {
		n, err := c.w.Write(p[:rem])
		c.written += int64(n)
		if err != nil {
			return n, err
		}
		return n, errWSEgressCapExceeded
	}
	n, err := c.w.Write(p)
	c.written += int64(n)
	return n, err
}
