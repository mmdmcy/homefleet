package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/mmdmcy/homefleet/internal/approval"
	"github.com/mmdmcy/homefleet/internal/config"
)

func TestExecRequiresTokenAndOptIn(t *testing.T) {
	cfg := config.Config{
		Token:           "secret",
		ExecEnabled:     true,
		Scope:           "private",
		DeviceID:        "laptop",
		Hostname:        "laptop",
		OS:              "linux",
		HTTPPort:        7350,
		RequireApproval: false,
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
	cfg := config.Config{Token: "secret", ExecEnabled: false, Scope: "private", DeviceID: "x", Hostname: "x", OS: "linux", RequireApproval: false}
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

func TestPendingApprovalBlocksRemoteExec(t *testing.T) {
	dir := t.TempDir()
	store, err := approval.Open(filepath.Join(dir, "approval.json"))
	if err != nil {
		t.Fatal(err)
	}
	code, err := store.EnsurePairing()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Token:           "secret",
		ExecEnabled:     true,
		Scope:           "private",
		DeviceID:        "newbox",
		Hostname:        "newbox",
		OS:              "linux",
		RequireApproval: true,
	}
	s := NewWithApproval(cfg, nil, store)

	req := httptest.NewRequest(http.MethodPost, "/v1/exec", bytes.NewBufferString(`{"command":"hostname"}`))
	req.RemoteAddr = "192.168.1.2:9"
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 pending, got %d %s", rec.Code, rec.Body.String())
	}

	// Loopback still works while pending (local smoke tests).
	req = httptest.NewRequest(http.MethodPost, "/v1/exec", bytes.NewBufferString(`{"command":"hostname"}`))
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback exec should work while pending, got %d %s", rec.Code, rec.Body.String())
	}

	body, _ := json.Marshal(ApproveRequest{PairingCode: code, ApproverID: "controller"})
	req = httptest.NewRequest(http.MethodPost, "/v1/approve", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.2:9"
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve failed: %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/exec", bytes.NewBufferString(`{"command":"hostname"}`))
	req.RemoteAddr = "192.168.1.2:9"
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("exec after approve: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPairingCodeLoopbackOnly(t *testing.T) {
	dir := t.TempDir()
	store, err := approval.Open(filepath.Join(dir, "approval.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsurePairing(); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Token: "secret", Scope: "private", DeviceID: "x", Hostname: "x", OS: "linux", RequireApproval: true}
	s := NewWithApproval(cfg, nil, store)

	req := httptest.NewRequest(http.MethodGet, "/v1/pairing", nil)
	req.RemoteAddr = "192.168.1.2:9"
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/pairing", nil)
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestApproveBackoffPerIP(t *testing.T) {
	store, err := approval.Open(filepath.Join(t.TempDir(), "approval.json"))
	if err != nil {
		t.Fatal(err)
	}
	code, err := store.EnsurePairing()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Token: "secret", ExecEnabled: true, Scope: "private", DeviceID: "x", Hostname: "x", OS: "linux", RequireApproval: true}
	s := NewWithApproval(cfg, nil, store)
	now := time.Now()
	s.limiter.now = func() time.Time { return now }

	approve := func(from, code string) int {
		body, _ := json.Marshal(ApproveRequest{PairingCode: code})
		req := httptest.NewRequest(http.MethodPost, "/v1/approve", bytes.NewReader(body))
		req.RemoteAddr = from
		req.Header.Set("Authorization", "Bearer secret")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	if got := approve("192.168.1.2:1", "0000-0000"); got != http.StatusForbidden {
		t.Fatalf("wrong code: expected 403, got %d", got)
	}
	// Same IP is held back even with the right code; another IP is not.
	if got := approve("192.168.1.2:2", code); got != http.StatusTooManyRequests {
		t.Fatalf("expected 429 during backoff, got %d", got)
	}
	if store.Snapshot().Approved {
		t.Fatal("approval must not happen while the IP is backed off")
	}
	now = now.Add(2 * time.Second)
	if got := approve("192.168.1.2:3", "0000-0001"); got != http.StatusForbidden {
		t.Fatalf("second wrong code: expected 403, got %d", got)
	}
	now = now.Add(time.Second) // backoff is 2s now; 1s is not enough
	if got := approve("192.168.1.2:4", code); got != http.StatusTooManyRequests {
		t.Fatalf("expected 429 under doubled backoff, got %d", got)
	}
	if got := approve("192.168.1.3:1", code); got != http.StatusOK {
		t.Fatalf("other IP with right code: expected 200, got %d", got)
	}
}

func TestApproveCodeResetAfterTooManyAttempts(t *testing.T) {
	store, err := approval.Open(filepath.Join(t.TempDir(), "approval.json"))
	if err != nil {
		t.Fatal(err)
	}
	code, err := store.EnsurePairing()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Token: "secret", Scope: "private", DeviceID: "x", Hostname: "x", OS: "linux", RequireApproval: true}
	s := NewWithApproval(cfg, nil, store)
	now := time.Now()
	s.limiter.now = func() time.Time { return now }
	for i := 0; i < approval.MaxCodeAttempts; i++ {
		now = now.Add(2 * maxApproveBackoff)
		body, _ := json.Marshal(ApproveRequest{PairingCode: "0000-0000"})
		req := httptest.NewRequest(http.MethodPost, "/v1/approve", bytes.NewReader(body))
		req.RemoteAddr = "192.168.1.2:9"
		req.Header.Set("Authorization", "Bearer secret")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("attempt %d: expected 403, got %d %s", i, rec.Code, rec.Body.String())
		}
	}
	if fresh := store.PairingCode(); fresh == "" || fresh == code {
		t.Fatal("expected a regenerated pairing code")
	}
}
