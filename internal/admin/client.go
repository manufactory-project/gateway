package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/manufactory-project/gateway/internal/config"
)

// Client talks to gateway's Admin API over its local Unix domain socket.
type Client struct {
	httpClient *http.Client
	transport  *http.Transport
}

// NewClient creates a Unix-socket Admin API Client.
func NewClient(socketPath string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{
		httpClient: &http.Client{Transport: tr},
		transport:  tr,
	}
}

// Close closes idle Unix socket connections held by Client.
func (c *Client) Close() {
	c.transport.CloseIdleConnections()
}

// Status calls GET /v1/status.
func (c *Client) Status(ctx context.Context) (StatusResponse, error) {
	var out StatusResponse
	err := c.doJSON(ctx, http.MethodGet, "/v1/status", nil, &out)
	return out, err
}

// Reload calls POST /v1/reload.
func (c *Client) Reload(ctx context.Context) (ReloadResponse, error) {
	var out ReloadResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/reload", nil, &out)
	return out, err
}

// Flows calls GET /v1/flows.
func (c *Client) Flows(ctx context.Context) ([]FlowInfo, error) {
	var out []FlowInfo
	err := c.doJSON(ctx, http.MethodGet, "/v1/flows", nil, &out)
	return out, err
}

// Revoke calls POST /v1/revoke.
func (c *Client) Revoke(ctx context.Context, req RevokeRequest) (RevokeResponse, error) {
	var out RevokeResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/revoke", req, &out)
	return out, err
}

// Grants calls GET /v1/grants.
func (c *Client) Grants(ctx context.Context) ([]config.Grant, error) {
	var out []config.Grant
	err := c.doJSON(ctx, http.MethodGet, "/v1/grants", nil, &out)
	return out, err
}

// CreateGrant calls POST /v1/grants.
func (c *Client) CreateGrant(ctx context.Context, req GrantRequest) (config.Grant, error) {
	var out config.Grant
	err := c.doJSON(ctx, http.MethodPost, "/v1/grants", req, &out)
	return out, err
}

// DeleteGrant calls DELETE /v1/grants/{id}.
func (c *Client) DeleteGrant(ctx context.Context, id string) (RevokeResponse, error) {
	var out RevokeResponse
	err := c.doJSON(ctx, http.MethodDelete, "/v1/grants/"+url.PathEscape(id), nil, &out)
	return out, err
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var bodyReader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = strings.NewReader(string(raw))
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, bodyReader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			return
		}
	}()
	if resp.StatusCode >= 400 {
		rawErr, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("admin: %s %s status %d (read err: %w)", method, path, resp.StatusCode, readErr)
		}
		return fmt.Errorf("admin: %s %s status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(rawErr)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
