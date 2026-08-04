package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mmdmcy/homefleet/internal/config"
)

func TestExecRequiresTokenAndOptIn(t *testing.T) {
	cfg := config.Config{
		Token:       "secret",
		ExecEnabled: true,
		Scope:       "private",
		DeviceID:    "laptop",
		Hostname:    "laptop",
		OS:          "linux",
		HTTPPort:    7350,
	}
	s := New(cfg)

	req := httptest.NewRequest(http.MethodPost, "/v1/exec", bytes.NewBufferString(`{"command":"hostname"}`))
	req.RemoteAddr = "192.168.1.2:1234"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/exec", bytes.NewBufferString(`{"command":"hostname"}`))
	req.RemoteAddr = "192.168.1.2:1234"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var result ExecResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 || result.Stdout == "" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestPublicIPRejected(t *testing.T) {
	cfg := config.Config{Token: "secret", Scope: "private", DeviceID: "x", Hostname: "x", OS: "linux"}
	s := New(cfg)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "8.8.8.8:9"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestExecDisabled(t *testing.T) {
	cfg := config.Config{Token: "secret", ExecEnabled: false, Scope: "private", DeviceID: "x", Hostname: "x", OS: "linux"}
	s := New(cfg)
	req := httptest.NewRequest(http.MethodPost, "/v1/exec", bytes.NewBufferString(`{"command":"hostname"}`))
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}
