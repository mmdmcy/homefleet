package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPrefersHomefleetOverDale(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	content := "HOMEFLEET_TOKEN=hf-token\nDALE_TOKEN=dale-token\nHOMEFLEET_EXEC=1\nHOMEFLEET_SCOPE=loopback\nHOMEFLEET_DEVICE_ID=laptop\n"
	if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOMEFLEET_TOKEN", "")
	t.Setenv("DALE_TOKEN", "")
	t.Setenv("HOMEFLEET_EXEC", "")
	t.Setenv("DALE_REMOTE_EXEC", "")
	t.Setenv("HOMEFLEET_SCOPE", "")
	t.Setenv("DALE_REMOTE_SCOPE", "")
	t.Setenv("HOMEFLEET_DEVICE_ID", "")
	// Clear so file values apply; LookupEnv sees empty string as set — unset properly.
	_ = os.Unsetenv("HOMEFLEET_TOKEN")
	_ = os.Unsetenv("DALE_TOKEN")
	_ = os.Unsetenv("HOMEFLEET_EXEC")
	_ = os.Unsetenv("DALE_REMOTE_EXEC")
	_ = os.Unsetenv("HOMEFLEET_SCOPE")
	_ = os.Unsetenv("DALE_REMOTE_SCOPE")
	_ = os.Unsetenv("HOMEFLEET_DEVICE_ID")

	cfg, err := Load(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Token != "hf-token" {
		t.Fatalf("token=%q", cfg.Token)
	}
	if !cfg.ExecEnabled {
		t.Fatal("expected exec enabled")
	}
	if cfg.Scope != "loopback" {
		t.Fatalf("scope=%q", cfg.Scope)
	}
	if cfg.DeviceID != "laptop" {
		t.Fatalf("device=%q", cfg.DeviceID)
	}
}

func TestLoadDaleCompat(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "master.env")
	content := "DALE_TOKEN=shared\nDALE_REMOTE_EXEC=true\nDALE_REMOTE_SCOPE=private\n"
	if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"HOMEFLEET_TOKEN", "DALE_TOKEN", "HOMEFLEET_EXEC", "DALE_REMOTE_EXEC", "HOMEFLEET_SCOPE", "DALE_REMOTE_SCOPE"} {
		_ = os.Unsetenv(key)
	}
	cfg, err := Load(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Token != "shared" {
		t.Fatalf("token=%q", cfg.Token)
	}
	if !cfg.ExecEnabled {
		t.Fatal("expected dale remote exec")
	}
	if cfg.Scope != "private" {
		t.Fatalf("scope=%q", cfg.Scope)
	}
}
