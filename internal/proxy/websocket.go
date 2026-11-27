package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const wsHandshakeTimeout = 30 * time.Second

var errWSEgressCapExceeded = errors.New("websocket egress byte cap exceeded")

func wsCancelOrErr(af *activeFlow, ctx context.Context, fallback string) (status int, errText string, canceled bool) {
	if reason := af.reason(); reason != "" {
		return http.StatusBadGateway, reason, true
	}
	if ctx.Err() != nil {
		return statusClientClosedRequest, TeardownClientCanceled, true
	}
	return http.StatusBadGateway, fallback, false
}

func (s *Server) serveWebSocket(w http.ResponseWriter, rc *reqContext, af *activeFlow) {
	upConn, err := s.dialWebSocketUpstream(rc.r.Context(), rc.host, rc.dstPort)
	if err != nil {
		status, errText, canceled := wsCancelOrErr(af, rc.r.Context(), err.Error())
		rc.auditCompleted(status, 0, 0, errText)
		if canceled {
			panic(http.ErrAbortHandler)
		}
		http.Error(w, "upstream websocket connect failed", http.StatusBadGateway)
		return
	}
	af.setUpstreamConn(upConn)
	defer closeQuietly(upConn)

	if rc.r.Context().Err() != nil {
		status, errText, _ := wsCancelOrErr(af, rc.r.Context(), rc.r.Context().Err().Error())
		rc.auditCompleted(status, 0, 0, errText)
		panic(http.ErrAbortHandler)
	}

	outReq := buildWSUpgradeRequest(rc)
	upReader, resp, err := performWSHandshake(rc.r.Context(), upConn, outReq, wsHandshakeTimeout)
	if err != nil {
		status, errText, canceled := wsCancelOrErr(af, rc.r.Context(), err.Error())
		rc.auditCompleted(status, 0, 0, errText)
		if canceled {
			panic(http.ErrAbortHandler)
		}
		http.Error(w, "upstream response failed", http.StatusBadGateway)
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		handleNonWSResponse(w, rc, af, resp)
		return
	}
	if rc.r.Context().Err() != nil {
		status, errText, _ := wsCancelOrErr(af, rc.r.Context(), rc.r.Context().Err().Error())
		rc.auditCompleted(status, 0, 0, errText)
		panic(http.ErrAbortHandler)
	}

	clientConn, clientBuf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		rc.auditCompleted(http.StatusInternalServerError, 0, 0, err.Error())
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer closeQuietly(clientConn)

	if err := writeWS101Response(clientConn, resp.Header); err != nil {
		errText := err.Error()
		if reason := af.reason(); reason != "" {
			errText = reason
		}
		rc.auditCompleted(http.StatusSwitchingProtocols, 0, 0, errText)
		return
	}

	egressCap := rc.dec.WSMaxEgressBytes
	if egressCap <= 0 {
		egressCap = s.store.Current().Config.HTTP.WSMaxEgressBytes
	}

	bytesOut, bytesIn, egressErr := bridgeWebSocket(rc.r.Context(), clientConn, clientBuf, upConn, upReader, egressCap)
	errText := ""
	if egressErr != nil {
		errText = fmt.Sprintf("ws-egress-cap-exceeded:%d", egressCap)
	} else if reason := af.reason(); reason != "" {
		errText = reason
	}
	rc.auditCompleted(http.StatusSwitchingProtocols, bytesOut, bytesIn, errText)
}

func (s *Server) dialWebSocketUpstream(ctx context.Context, host string, dstPort uint16) (net.Conn, error) {
	targetAddr := net.JoinHostPort(host, strconv.Itoa(int(dstPort)))
	rawUpstream, err := s.dialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, err
	}
	if dstPort != 443 {
		return rawUpstream, nil
	}
	tlsConn := tls.Client(rawUpstream, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		if closeErr := rawUpstream.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		return nil, err
	}
	return tlsConn, nil
}

func buildWSUpgradeRequest(rc *reqContext) *http.Request {
	outReq := rc.r.Clone(rc.r.Context())
	outReq.RequestURI = ""
	outReq.Proto = "HTTP/1.1"
	outReq.ProtoMajor = 1
	outReq.ProtoMinor = 1
	outReq.Host = rc.host
	outReq.Body = http.NoBody
	outReq.ContentLength = 0
	outReq.TransferEncoding = nil
	outReq.Header = rc.outHeaders
	outReq.Header.Set("Connection", "Upgrade")
	outReq.Header.Set("Upgrade", "websocket")
	return outReq
}

func performWSHandshake(ctx context.Context, upConn net.Conn, outReq *http.Request, timeout time.Duration) (*bufio.Reader, *http.Response, error) {
	stopCancel := context.AfterFunc(ctx, func() {
		closeQuietly(upConn)
	})
	defer stopCancel()

	if err := upConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, err
	}
	if err := outReq.Write(upConn); err != nil {
		return nil, nil, err
	}
	upReader := bufio.NewReader(upConn)
	resp, err := http.ReadResponse(upReader, outReq)
	if err != nil {
		return nil, nil, err
	}
	if err := upConn.SetDeadline(time.Time{}); err != nil {
		closeQuietly(resp.Body)
		return nil, nil, err
	}
	return upReader, resp, nil
}

func handleNonWSResponse(w http.ResponseWriter, rc *reqContext, af *activeFlow, resp *http.Response) {
	defer closeQuietly(resp.Body)
	if resp.StatusCode == http.StatusSwitchingProtocols {
		rc.auditCompleted(http.StatusBadGateway, 0, 0, "unexpected-101-non-websocket")
		http.Error(w, "unexpected protocol upgrade", http.StatusBadGateway)
		return
	}
	copyEndToEndHeaders(w.Header(), resp.Header, false)
	w.WriteHeader(resp.StatusCode)
	bytesIn, copyErr := copyStreaming(w, resp.Body)
	errText := ""
	if reason := af.reason(); reason != "" {
		errText = reason
	} else if copyErr != nil {
		if rc.r.Context().Err() != nil {
			errText = TeardownClientCanceled
		} else {
			errText = copyErr.Error()
		}
	}
	rc.auditCompleted(resp.StatusCode, 0, bytesIn, errText)
	if copyErr != nil {
		panic(http.ErrAbortHandler)
	}
}

func writeWS101Response(clientConn net.Conn, upstreamHeader http.Header) error {
	var hdr strings.Builder
	hdr.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	respHdr := make(http.Header)
	copyEndToEndHeaders(respHdr, upstreamHeader, true)
	respHdr.Set("Connection", "Upgrade")
	respHdr.Set("Upgrade", "websocket")
	if err := respHdr.Write(&hdr); err != nil {
		return err
	}
	hdr.WriteString("\r\n")
	_, err := io.WriteString(clientConn, hdr.String())
	return err
}

func bridgeWebSocket(ctx context.Context, clientConn net.Conn, clientBuf io.Reader, upConn net.Conn, upReader io.Reader, egressCap int64) (bytesOut, bytesIn int64, egressErr error) {
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			closeQuietly(upConn)
			closeQuietly(clientConn)
		})
	}

	stopWatch := make(chan struct{})
	var watchWG sync.WaitGroup
	watchWG.Add(1)
	go func() {
		defer watchWG.Done()
		select {
		case <-ctx.Done():
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
	return bytesOut, bytesIn, egressErr
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
