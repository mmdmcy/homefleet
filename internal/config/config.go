package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/mmdmcy/homefleet/internal/envfile"
)

const (
	DefaultHTTPPort   = 7350
	DefaultBeaconPort = 9999
	DefaultProto      = "homefleet.v1"
)

type Config struct {
	Token      string
	ExecEnabled bool
	Scope      string
	DeviceID   string
	Hostname   string
	OS         string
	HTTPPort   int
	BeaconPort int
	AllowCIDRs []string
	EnvPath    string
}

func Load(explicitEnv string) (Config, error) {
	path, err := loadEnvFiles(explicitEnv)
	if err != nil {
		return Config{}, err
	}
	host, _ := os.Hostname()
	cfg := Config{
		Token:       firstNonEmpty(os.Getenv("HOMEFLEET_TOKEN"), os.Getenv("DALE_TOKEN")),
		ExecEnabled: truthy(firstNonEmpty(os.Getenv("HOMEFLEET_EXEC"), os.Getenv("DALE_REMOTE_EXEC"))),
		Scope:       normalizeScope(firstNonEmpty(os.Getenv("HOMEFLEET_SCOPE"), os.Getenv("DALE_REMOTE_SCOPE"))),
		DeviceID:    firstNonEmpty(os.Getenv("HOMEFLEET_DEVICE_ID"), host),
		Hostname:    host,
		OS:          runtime.GOOS,
		HTTPPort:    DefaultHTTPPort,
		BeaconPort:  DefaultBeaconPort,
		AllowCIDRs:  splitCSV(os.Getenv("HOMEFLEET_ALLOW_CIDRS")),
		EnvPath:     path,
	}
	if cfg.DeviceID == "" {
		cfg.DeviceID = "unknown"
	}
	return cfg, nil
}

func (c Config) WithPorts(httpPort, beaconPort int) Config {
	if httpPort > 0 {
		c.HTTPPort = httpPort
	}
	if beaconPort > 0 {
		c.BeaconPort = beaconPort
	}
	return c
}

func loadEnvFiles(explicit string) (string, error) {
	candidates := []string{}
	if explicit != "" {
		candidates = append(candidates, explicit)
	}
	if v := strings.TrimSpace(os.Getenv("HOMEFLEET_ENV")); v != "" {
		candidates = append(candidates, v)
	}
	if path, ok := envfile.FindUp(".env"); ok {
		candidates = append(candidates, path)
	}
	if path := configEnvPath(); path != "" {
		candidates = append(candidates, path)
	}
	var loaded string
	seen := map[string]bool{}
	for _, path := range candidates {
		path = filepath.Clean(path)
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		if _, err := os.Stat(path); err != nil {
			if explicit != "" && path == filepath.Clean(explicit) {
				return "", fmt.Errorf("env file not found: %s", explicit)
			}
			continue
		}
		if err := envfile.Load(path); err != nil {
			return "", fmt.Errorf("load %s: %w", path, err)
		}
		if loaded == "" {
			loaded = path
		}
	}
	return loaded, nil
}

func configEnvPath() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("AppData")
		if base == "" {
			return ""
		}
		return filepath.Join(base, "homefleet", "config.env")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		xdg = filepath.Join(home, ".config")
	}
	return filepath.Join(xdg, "homefleet", "config.env")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func normalizeScope(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "private":
		return "private"
	case "loopback", "local":
		return "loopback"
	case "tailnet", "tailscale":
		return "tailnet"
	case "public", "all", "any":
		return "public"
	default:
		return "private"
	}
}

func splitCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func ParsePort(raw string, fallback int) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q", raw)
	}
	return n, nil
}
