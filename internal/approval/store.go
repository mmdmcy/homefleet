package approval

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// State tracks whether this agent may accept remote exec when approval is required.
type State struct {
	Approved   bool      `json:"approved"`
	ApprovedAt time.Time `json:"approved_at,omitempty"`
	ApprovedBy string    `json:"approved_by,omitempty"`
	// PairingHash is sha256 hex of the current pairing code (only while pending).
	PairingHash string `json:"pairing_hash,omitempty"`
}

// MaxCodeAttempts is how many wrong pairing codes are tolerated before the
// code is thrown away and a new one minted. An 8-digit code would otherwise
// fall to a token holder brute-forcing /v1/approve.
const MaxCodeAttempts = 5

// ErrCodeReset is returned by ApproveWithCode when the failed attempt was the
// last one allowed: the old code is gone and a new one is active.
var ErrCodeReset = errors.New("invalid pairing code; too many failed attempts, a new pairing code was generated (read it with `homefleet pairing` on the device)")

type Store struct {
	mu   sync.Mutex
	path string
	st   State
	// plaintext code kept in memory for local display / loopback API only
	code string
	// failures counts wrong codes against the current code
	failures int
}

func Dir() (string, error) {
	if runtime.GOOS == "windows" {
		base := os.Getenv("AppData")
		if base == "" {
			return "", errors.New("AppData not set")
		}
		return filepath.Join(base, "homefleet"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		xdg = filepath.Join(home, ".config")
	}
	return filepath.Join(xdg, "homefleet"), nil
}

func DefaultPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "approval.json"), nil
}

func Open(path string) (*Store, error) {
	if path == "" {
		var err error
		path, err = DefaultPath()
		if err != nil {
			return nil, err
		}
	}
	s := &Store{path: path}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

func (s *Store) Path() string { return s.path }

func (s *Store) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

func (s *Store) PairingCode() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.code
}

// EnsurePairing creates a pairing code when the device is not yet approved.
func (s *Store) EnsurePairing() (code string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Approved {
		s.code = ""
		s.st.PairingHash = ""
		return "", s.saveLocked()
	}
	if s.code != "" {
		return s.code, nil
	}
	// Restart or fresh pending: mint a new code (invalidates any previous printout).
	if err := s.mintLocked(); err != nil {
		return "", err
	}
	return s.code, nil
}

// mintLocked replaces the pairing code, resets the failure counter and saves.
func (s *Store) mintLocked() error {
	code, err := generateCode()
	if err != nil {
		return err
	}
	s.code = code
	s.st.PairingHash = hashCode(code)
	s.failures = 0
	return s.saveLocked()
}

// ApproveLocal marks this device approved without a pairing code (operator at the machine).
func (s *Store) ApproveLocal(by string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if by == "" {
		by = "local"
	}
	s.st.Approved = true
	s.st.ApprovedAt = time.Now().UTC()
	s.st.ApprovedBy = by
	s.st.PairingHash = ""
	s.code = ""
	return s.saveLocked()
}

// ApproveWithCode validates the pairing code and marks approved.
func (s *Store) ApproveWithCode(code, by string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Approved {
		return nil
	}
	if s.st.PairingHash == "" {
		return errors.New("no pairing code active; restart homefleet serve on this device")
	}
	if subtle.ConstantTimeCompare([]byte(hashCode(normalizeCode(code))), []byte(s.st.PairingHash)) != 1 {
		s.failures++
		if s.failures < MaxCodeAttempts {
			return errors.New("invalid pairing code")
		}
		if err := s.mintLocked(); err != nil {
			return err
		}
		return ErrCodeReset
	}
	if by == "" {
		by = "remote"
	}
	s.st.Approved = true
	s.st.ApprovedAt = time.Now().UTC()
	s.st.ApprovedBy = by
	s.st.PairingHash = ""
	s.code = ""
	return s.saveLocked()
}

func (s *Store) Revoke() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st = State{}
	return s.mintLocked()
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	s.st = st
	return nil
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func generateCode() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	n := binaryToUint32(b[:])
	// 8 digits, grouped XXXX-XXXX for reading aloud
	left := n % 10000
	right := (n / 10000) % 10000
	return fmt.Sprintf("%04d-%04d", left, right), nil
}

func binaryToUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func normalizeCode(code string) string {
	code = strings.TrimSpace(strings.ToUpper(code))
	code = strings.ReplaceAll(code, " ", "")
	code = strings.ReplaceAll(code, "-", "")
	if len(code) == 8 {
		return code[:4] + "-" + code[4:]
	}
	return code
}

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(normalizeCode(code)))
	return hex.EncodeToString(sum[:])
}
