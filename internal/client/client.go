package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mmdmcy/homefleet/internal/config"
	"github.com/mmdmcy/homefleet/internal/discover"
	"github.com/mmdmcy/homefleet/internal/server"
)

type Client struct {
	Token      string
	HTTPClient *http.Client
}

func New(token string) *Client {
	return &Client{
		Token: token,
		HTTPClient: &http.Client{
			Timeout: 130 * time.Second,
		},
	}
}

func (c *Client) Healthz(ctx context.Context, baseURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("healthz status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) Peers(ctx context.Context, baseURL string) ([]discover.Peer, error) {
	var out []discover.Peer
	err := c.getJSON(ctx, baseURL, "/v1/peers", &out)
	return out, err
}

func (c *Client) Whoami(ctx context.Context, baseURL string) (server.Whoami, error) {
	var out server.Whoami
	err := c.getJSON(ctx, baseURL, "/v1/whoami", &out)
	return out, err
}

func (c *Client) Exec(ctx context.Context, baseURL string, req server.ExecRequest) (server.ExecResult, error) {
	var out server.ExecResult
	err := c.postJSON(ctx, baseURL, "/v1/exec", req, &out)
	return out, err
}

func (c *Client) getJSON(ctx context.Context, baseURL, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+path, nil)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return json.Unmarshal(body, out)
}

func (c *Client) postJSON(ctx context.Context, baseURL, path string, in any, out any) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return json.Unmarshal(body, out)
}

func ResolveBaseURL(ctx context.Context, cfg config.Config, device, host string, httpPort, beaconPort int) (string, error) {
	if host != "" {
		if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
			return strings.TrimRight(host, "/"), nil
		}
		if strings.Contains(host, ":") && net.ParseIP(host) == nil {
			// host:port without scheme
			return "http://" + host, nil
		}
		port := httpPort
		if port <= 0 {
			port = config.DefaultHTTPPort
		}
		return "http://" + net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
	}
	if device == "" {
		return "", fmt.Errorf("pass --device or --host")
	}
	if beaconPort <= 0 {
		beaconPort = config.DefaultBeaconPort
	}
	peers, err := discover.ListenOnce(ctx, beaconPort, 3*time.Second)
	if err != nil {
		return "", err
	}
	table := discover.NewTable(cfg)
	for _, peer := range peers {
		table.Upsert(peer)
	}
	peer, err := table.Find(device)
	if err == nil {
		return peer.BaseURL(), nil
	}
	if strings.Contains(err.Error(), "multiple peers") {
		return "", err
	}
	// Fallback: treat device as hostname/IP for direct HTTP.
	return ResolveBaseURL(ctx, cfg, "", device, httpPort, beaconPort)
}

func Doctor(ctx context.Context, c *Client, baseURL string) map[string]any {
	report := map[string]any{
		"url": baseURL,
	}
	checks := []map[string]any{}
	add := func(name string, ok bool, detail string) {
		checks = append(checks, map[string]any{"name": name, "ok": ok, "detail": detail})
	}

	if err := c.Healthz(ctx, baseURL); err != nil {
		add("healthz", false, err.Error())
		report["checks"] = checks
		report["conclusion"] = "Agent is not reachable."
		return report
	}
	add("healthz", true, "ok")

	who, err := c.Whoami(ctx, baseURL)
	if err != nil {
		add("auth", false, err.Error())
		report["checks"] = checks
		report["conclusion"] = "Health works, but auth failed. Check HOMEFLEET_TOKEN / DALE_TOKEN on both devices."
		return report
	}
	add("auth", true, "token accepted")
	report["whoami"] = who

	result, err := c.Exec(ctx, baseURL, server.ExecRequest{Command: "hostname", TimeoutSeconds: 10})
	if err != nil {
		add("remote-exec", false, err.Error())
		report["checks"] = checks
		report["conclusion"] = "Auth works. Remote exec is disabled or blocked; set HOMEFLEET_EXEC=1 or DALE_REMOTE_EXEC=1 on the remote device."
		return report
	}
	detail := strings.TrimSpace(result.Stdout + " " + result.Stderr)
	add("remote-exec", result.ExitCode == 0, detail)
	report["checks"] = checks
	if result.ExitCode != 0 {
		report["conclusion"] = "Exec endpoint answered but the smoke command failed."
		return report
	}
	report["conclusion"] = "Health, auth, and remote command execution work."
	return report
}
