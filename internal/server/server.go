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
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mmdmcy/homefleet/internal/config"
	"github.com/mmdmcy/homefleet/internal/discover"
	"github.com/mmdmcy/homefleet/internal/netpolicy"
)

type PeerLister interface {
	List() []discover.Peer
}

type Server struct {
	cfg   config.Config
	mux   *http.ServeMux
	peers PeerLister
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
	ID         string `json:"id"`
	Hostname   string `json:"hostname"`
	OS         string `json:"os"`
	HTTPPort   int    `json:"http_port"`
	ExecEnabled bool  `json:"exec_enabled"`
	Scope      string `json:"scope"`
	Proto      string `json:"proto"`
}

func New(cfg config.Config) *Server {
	return NewWithPeers(cfg, nil)
}

func NewWithPeers(cfg config.Config, peers PeerLister) *Server {
	s := &Server{cfg: cfg, mux: http.NewServeMux(), peers: peers}
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/v1/whoami", s.handleWhoami)
	s.mux.HandleFunc("/v1/peers", s.handlePeers)
	s.mux.HandleFunc("/v1/exec", s.handleExec)
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
	addr := net.JoinHostPort("0.0.0.0", fmt.Sprintf("%d", s.cfg.HTTPPort))
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
	writeJSON(w, http.StatusOK, Whoami{
		ID:          s.cfg.DeviceID,
		Hostname:    s.cfg.Hostname,
		OS:          s.cfg.OS,
		HTTPPort:    s.cfg.HTTPPort,
		ExecEnabled: s.cfg.ExecEnabled,
		Scope:       s.cfg.Scope,
		Proto:       config.DefaultProto,
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
