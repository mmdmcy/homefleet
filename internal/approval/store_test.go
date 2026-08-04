package approval

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApproveWithCodeAndLocal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "approval.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	code, err := store.EnsurePairing()
	if err != nil {
		t.Fatal(err)
	}
	if code == "" {
		t.Fatal("expected pairing code")
	}
	if store.Snapshot().Approved {
		t.Fatal("should be pending")
	}
	if err := store.ApproveWithCode("0000-0000", "x"); err == nil {
		t.Fatal("expected bad code error")
	}
	if err := store.ApproveWithCode(code, "lawnmower"); err != nil {
		t.Fatal(err)
	}
	if !store.Snapshot().Approved {
		t.Fatal("expected approved")
	}
	if store.PairingCode() != "" {
		t.Fatal("code should clear after approve")
	}

	store2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !store2.Snapshot().Approved {
		t.Fatal("approval should persist")
	}

	if err := store2.Revoke(); err != nil {
		t.Fatal(err)
	}
	if store2.Snapshot().Approved {
		t.Fatal("expected revoked")
	}
	if store2.PairingCode() == "" {
		t.Fatal("expected new pairing code after revoke")
	}
	if err := store2.ApproveLocal("self"); err != nil {
		t.Fatal(err)
	}
	if !store2.Snapshot().Approved {
		t.Fatal("local approve failed")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
