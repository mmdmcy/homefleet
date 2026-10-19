package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/mmdmcy/homefleet/internal/approval"
	"github.com/mmdmcy/homefleet/internal/config"
	"github.com/mmdmcy/homefleet/internal/discover"
	"github.com/mmdmcy/homefleet/internal/netpolicy"
)

type PeerLister interface {
	List() []discover.Peer
}

type Server struct {
	cfg      config.Config
	mux      *http.ServeMux
	peers    PeerLister
	approval *approval.Store
	limiter  *approveLimiter
}

// approveLimiter slows pairing-code guessing per source IP: after each wrong
// code the IP must wait 1s, 2s, 4s ... up to maxApproveBackoff before the
// next attempt is even checked. The store's attempt counter (approval.
// MaxCodeAttempts) is the hard stop; this keeps a distributed guesser slow.
type approveLimiter struct {
	mu   sync.Mutex
	now  func() time.Time
	byIP map[string]approveState
}

type approveState struct {
	failures int
	until    time.Time
}

const maxApproveBackoff = 60 * time.Second

func newApproveLimiter() *approveLimiter {
	return &approveLimiter{now: time.Now, byIP: map[string]approveState{}}
}

// allow reports whether ip may attempt a code now, else how long to wait.
func (l *approveLimiter) allow(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.byIP[ip]
	if wait := st.until.Sub(l.now()); wait > 0 {
		return false, wait
	}
	return true, 0
}

func (l *approveLimiter) record(ip string, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if ok {
		delete(l.byIP, ip)
		return
	}
	if len(l.byIP) > 1024 {
		for k, st := range l.byIP {
			if now.After(st.until.Add(maxApproveBackoff)) {
				delete(l.byIP, k)
			}
		}
	}
	st := l.byIP[ip]
	st.failures++
	backoff := time.Second << uint(min(st.failures-1, 6))
	if backoff > maxApproveBackoff {
		backoff = maxApproveBackoff
	}
	st.until = now.Add(backoff)
	l.byIP[ip] = st
}

type ExecRequest struct {
	Command        string   `json:"command"`
	Args           []string `json:"args,omitempty"`
	Cwd            string   `json:"cwd,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
}

type ExecResult struct {
	Command    string   `json:"command"`
	Args       []string `json:"args,omitempty"`
	Cwd        string   `json:"cwd,omitempty"`
	ExitCode   int      `json:"exit_code"`
	Stdout     string   `json:"stdout"`
	Stderr     string   `json:"stderr"`
	DurationMS int64    `json:"duration_ms"`
	Error      string   `json:"error,omitempty"`
}

type Whoami struct {
	ID                string `json:"id"`
	Hostname          string `json:"hostname"`
	OS                string `json:"os"`
	HTTPPort          int    `json:"http_port"`
	ExecEnabled       bool   `json:"exec_enabled"`
	Scope             string `json:"scope"`
	Proto             string `json:"proto"`
	ApprovalRequired  bool   `json:"approval_required"`
	Approved          bool   `json:"approved"`
	PendingApproval   bool   `json:"pending_approval"`
	RemoteExecAllowed bool   `json:"remote_exec_allowed"`
}

type ApproveRequest struct {
	PairingCode string `json:"pairing_code"`
	ApproverID  string `json:"approver_id,omitempty"`
}

func New(cfg config.Config) *Server {
	return NewWithPeers(cfg, nil)
}

func NewWithPeers(cfg config.Config, peers PeerLister) *Server {
	return NewWithApproval(cfg, peers, nil)
}

func NewWithApproval(cfg config.Config, peers PeerLister, store *approval.Store) *Server {
	s := &Server{cfg: cfg, mux: http.NewServeMux(), peers: peers, approval: store, limiter: newApproveLimiter()}
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/v1/whoami", s.handleWhoami)
	s.mux.HandleFunc("/v1/peers", s.handlePeers)
	s.mux.HandleFunc("/v1/exec", s.handleExec)
	s.mux.HandleFunc("/v1/approve", s.handleApprove)
	s.mux.HandleFunc("/v1/pairing", s.handlePairing)
	s.mux.HandleFunc("/v1/revoke", s.handleRevoke)
	return s
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := netpolicy.ParseIP(r.RemoteAddr)
		if !netpolicy.Allowed(ip, s.cfg.Scope, s.cfg.AllowCIDRs) {
			writeError(w, http.StatusForbidden, errors.New("remote access is restricted to private-network addresses by default; set HOMEFLEET_SCOPE=public only behind a firewall or reverse proxy"))
			return
		}
		if r.URL.Path == "/healthz" {
			s.mux.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/v1/") {
			writeError(w, http.StatusNotFound, errors.New("not found"))
			return
		}
		if s.cfg.Token == "" {
			writeError(w, http.StatusUnauthorized, errors.New("authorization required: set HOMEFLEET_TOKEN or DALE_TOKEN"))
			return
		}
		if !validBearer(r.Header.Get("Authorization"), s.cfg.Token) {
			writeError(w, http.StatusUnauthorized, errors.New("authorization required"))
			return
		}
		s.mux.ServeHTTP(w, r)
	})
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	// Empty host => dual-stack where the OS supports it (helps Windows LAN reachability).
	addr := net.JoinHostPort("", fmt.Sprintf("%d", s.cfg.HTTPPort))
	httpServer := &http.Server{Addr: addr, Handler: s.Handler()}
	errCh := make(chan error, 1)
	go func() {
		errCh <- httpServer.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		err := <-errCh
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	approved := s.isApproved()
	writeJSON(w, http.StatusOK, Whoami{
		ID:                s.cfg.DeviceID,
		Hostname:          s.cfg.Hostname,
		OS:                s.cfg.OS,
		HTTPPort:          s.cfg.HTTPPort,
		ExecEnabled:       s.cfg.ExecEnabled,
		Scope:             s.cfg.Scope,
		Proto:             config.DefaultProto,
		ApprovalRequired:  s.cfg.RequireApproval,
		Approved:          approved,
		PendingApproval:   s.cfg.RequireApproval && !approved,
		RemoteExecAllowed: s.cfg.ExecEnabled && (!s.cfg.RequireApproval || approved),
	})
}

func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if s.peers == nil {
		writeJSON(w, http.StatusOK, []discover.Peer{})
		return
	}
	writeJSON(w, http.StatusOK, s.peers.List())
}

func (s *Server) handleExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.cfg.ExecEnabled {
		writeError(w, http.StatusForbidden, errors.New("remote exec disabled; set HOMEFLEET_EXEC=1 or DALE_REMOTE_EXEC=1 on this device"))
		return
	}
	if s.cfg.RequireApproval && !s.isApproved() && !isLoopback(r.RemoteAddr) {
		writeError(w, http.StatusForbidden, errors.New("device pending approval; from a trusted machine run: homefleet approve --host <ip> --code <pairing-code> (code is printed by `homefleet serve` on this device)"))
		return
	}
	var req ExecRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := runCommand(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if s.approval == nil {
		writeError(w, http.StatusInternalServerError, errors.New("approval store unavailable"))
		return
	}
	var req ApproveRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	by := strings.TrimSpace(req.ApproverID)
	if by == "" {
		by = "remote"
	}

	// Loopback may approve without a code (operator on the machine).
	if isLoopback(r.RemoteAddr) && strings.TrimSpace(req.PairingCode) == "" {
		if err := s.approval.ApproveLocal(by); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	} else {
		if strings.TrimSpace(req.PairingCode) == "" {
			writeError(w, http.StatusBadRequest, errors.New("pairing_code required (shown on the pending device when serve starts)"))
			return
		}
		ip := netpolicy.ParseIP(r.RemoteAddr).String()
		if ok, wait := s.limiter.allow(ip); !ok {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())+1))
			writeError(w, http.StatusTooManyRequests, fmt.Errorf("too many failed pairing attempts; retry in %s", wait.Round(time.Second)))
			return
		}
		err := s.approval.ApproveWithCode(req.PairingCode, by)
		s.limiter.record(ip, err == nil)
		if err != nil {
			if errors.Is(err, approval.ErrCodeReset) {
				fmt.Fprintf(os.Stderr, "homefleet: %d failed pairing attempts (last from %s); new pairing code %s\n",
					approval.MaxCodeAttempts, ip, s.approval.PairingCode())
			}
			writeError(w, http.StatusForbidden, err)
			return
		}
	}
	st := s.approval.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"approved":    st.Approved,
		"approved_by": st.ApprovedBy,
		"approved_at": st.ApprovedAt,
		"device_id":   s.cfg.DeviceID,
	})
}

func (s *Server) handlePairing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !isLoopback(r.RemoteAddr) {
		writeError(w, http.StatusForbidden, errors.New("pairing code is only available on loopback"))
		return
	}
	if s.approval == nil {
		writeError(w, http.StatusInternalServerError, errors.New("approval store unavailable"))
		return
	}
	st := s.approval.Snapshot()
	out := map[string]any{
		"device_id":         s.cfg.DeviceID,
		"hostname":          s.cfg.Hostname,
		"approved":          st.Approved,
		"approval_required": s.cfg.RequireApproval,
		"pending_approval":  s.cfg.RequireApproval && !st.Approved,
		"pairing_code":      nil,
	}
	if !st.Approved {
		code := s.approval.PairingCode()
		if code == "" {
			var err error
			code, err = s.approval.EnsurePairing()
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		}
		out["pairing_code"] = code
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !isLoopback(r.RemoteAddr) {
		writeError(w, http.StatusForbidden, errors.New("revoke is only allowed on loopback"))
		return
	}
	if s.approval == nil {
		writeError(w, http.StatusInternalServerError, errors.New("approval store unavailable"))
		return
	}
	if err := s.approval.Revoke(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	code := s.approval.PairingCode()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"approved":     false,
		"pairing_code": code,
		"device_id":    s.cfg.DeviceID,
	})
}

func (s *Server) isApproved() bool {
	if !s.cfg.RequireApproval {
		return true
	}
	if s.approval == nil {
		return false
	}
	return s.approval.Snapshot().Approved
}

func runCommand(ctx context.Context, req ExecRequest) (ExecResult, error) {
	req.Command = strings.TrimSpace(req.Command)
	if req.Command == "" {
		return ExecResult{}, errors.New("command is required")
	}
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if timeout > 120*time.Second {
		timeout = 120 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	cmd := exec.CommandContext(cctx, req.Command, req.Args...)
	if strings.TrimSpace(req.Cwd) != "" {
		cmd.Dir = req.Cwd
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result := ExecResult{
		Command:    req.Command,
		Args:       req.Args,
		Cwd:        cmd.Dir,
		Stdout:     shorten(stdout.String(), 64*1024),
		Stderr:     shorten(stderr.String(), 64*1024),
		DurationMS: time.Since(start).Milliseconds(),
	}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if cctx.Err() != nil {
		result.Error = cctx.Err().Error()
		return result, nil
	}
	if err != nil {
		result.Error = err.Error()
	}
	return result, nil
}

func validBearer(header, token string) bool {
	if token == "" || !strings.HasPrefix(header, "Bearer ") {
		return false
	}
	got := strings.TrimPrefix(header, "Bearer ")
	if len(got) != len(token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

func isLoopback(remoteAddr string) bool {
	ip := netpolicy.ParseIP(remoteAddr)
	return ip != nil && ip.IsLoopback()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func shorten(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max < 3 {
		return s[:max]
	}
	cut := max - 3
	for cut > 0 && !utf8.ValidString(s[:cut]) {
		cut--
	}
	return s[:cut] + "..."
}
