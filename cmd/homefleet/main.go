package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mmdmcy/homefleet/internal/client"
	"github.com/mmdmcy/homefleet/internal/config"
	"github.com/mmdmcy/homefleet/internal/discover"
	"github.com/mmdmcy/homefleet/internal/server"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "homefleet: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}
	envPath := flagValue(args, "--env")
	cfg, err := config.Load(envPath)
	if err != nil {
		return err
	}

	switch args[0] {
	case "serve":
		return cmdServe(cfg, args[1:])
	case "peers":
		return cmdPeers(cfg, args[1:])
	case "run":
		return cmdRun(cfg, args[1:])
	case "doctor":
		return cmdDoctor(cfg, args[1:])
	case "version", "--version", "-v":
		fmt.Println(version)
		return nil
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func cmdServe(cfg config.Config, args []string) error {
	httpPort, err := intFlag(args, "--port", cfg.HTTPPort)
	if err != nil {
		return err
	}
	beaconPort, err := intFlag(args, "--beacon-port", cfg.BeaconPort)
	if err != nil {
		return err
	}
	cfg = cfg.WithPorts(httpPort, beaconPort)
	if cfg.Token == "" {
		return fmt.Errorf("missing token: set HOMEFLEET_TOKEN or DALE_TOKEN (or put it in .env)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	table := discover.NewTable(cfg)
	errCh := make(chan error, 2)
	go func() {
		errCh <- discover.RunBeacon(ctx, cfg, table)
	}()
	go func() {
		fmt.Fprintf(os.Stderr, "homefleet listening on :%d (beacon :%d) id=%s exec=%v scope=%s\n",
			cfg.HTTPPort, cfg.BeaconPort, cfg.DeviceID, cfg.ExecEnabled, cfg.Scope)
		errCh <- server.NewWithPeers(cfg, table).ListenAndServe(ctx)
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func cmdPeers(cfg config.Config, args []string) error {
	beaconPort, err := intFlag(args, "--beacon-port", cfg.BeaconPort)
	if err != nil {
		return err
	}
	httpPort, err := intFlag(args, "--port", cfg.HTTPPort)
	if err != nil {
		return err
	}
	wait, err := durationFlag(args, "--wait", 3*time.Second)
	if err != nil {
		return err
	}

	var peers []discover.Peer
	// Prefer the local agent table when serve is already running.
	if cfg.Token != "" {
		localURL := fmt.Sprintf("http://127.0.0.1:%d", httpPort)
		if list, err := client.New(cfg.Token).Peers(context.Background(), localURL); err == nil {
			peers = list
		}
	}
	if len(peers) == 0 {
		peers, err = discover.ListenOnce(context.Background(), beaconPort, wait)
		if err != nil {
			return err
		}
	}
	if flagBool(args, "--json") {
		return printJSON(peers)
	}
	fmt.Printf("%-20s %-16s %-10s %-18s %s\n", "ID", "HOSTNAME", "OS", "IP", "URL")
	for _, peer := range peers {
		fmt.Printf("%-20s %-16s %-10s %-18s %s\n", peer.ID, peer.Hostname, peer.OS, peer.IP, peer.BaseURL())
	}
	if len(peers) == 0 {
		fmt.Fprintln(os.Stderr, "no peers heard; start `homefleet serve` on LAN devices")
	}
	return nil
}

func cmdRun(cfg config.Config, args []string) error {
	sep := indexOf(args, "--")
	if sep < 0 || sep == len(args)-1 {
		return fmt.Errorf("run requires -- followed by command and args")
	}
	flags := args[:sep]
	cmdArgs := args[sep+1:]
	httpPort, err := intFlag(flags, "--port", cfg.HTTPPort)
	if err != nil {
		return err
	}
	beaconPort, err := intFlag(flags, "--beacon-port", cfg.BeaconPort)
	if err != nil {
		return err
	}
	timeout, err := intFlag(flags, "--timeout", 30)
	if err != nil {
		return err
	}
	device := flagValue(flags, "--device")
	host := flagValue(flags, "--host")
	cwd := flagValue(flags, "--cwd")

	baseURL, err := client.ResolveBaseURL(context.Background(), cfg, device, host, httpPort, beaconPort)
	if err != nil {
		return err
	}
	if cfg.Token == "" {
		return fmt.Errorf("missing token: set HOMEFLEET_TOKEN or DALE_TOKEN")
	}
	cli := client.New(cfg.Token)
	result, err := cli.Exec(context.Background(), baseURL, server.ExecRequest{
		Command:        cmdArgs[0],
		Args:           cmdArgs[1:],
		Cwd:            cwd,
		TimeoutSeconds: timeout,
	})
	if err != nil {
		return err
	}
	return printJSON(result)
}

func cmdDoctor(cfg config.Config, args []string) error {
	httpPort, err := intFlag(args, "--port", cfg.HTTPPort)
	if err != nil {
		return err
	}
	beaconPort, err := intFlag(args, "--beacon-port", cfg.BeaconPort)
	if err != nil {
		return err
	}
	device := flagValue(args, "--device")
	host := flagValue(args, "--host")
	if device == "" && host == "" {
		host = "127.0.0.1"
	}
	baseURL, err := client.ResolveBaseURL(context.Background(), cfg, device, host, httpPort, beaconPort)
	if err != nil {
		return err
	}
	if cfg.Token == "" {
		return fmt.Errorf("missing token: set HOMEFLEET_TOKEN or DALE_TOKEN")
	}
	report := client.Doctor(context.Background(), client.New(cfg.Token), baseURL)
	return printJSON(report)
}

func printUsage() {
	fmt.Print(`homefleet — frictionless LAN fleet control

Commands:
  serve [--port 7350] [--beacon-port 9999] [--env path]
  peers [--beacon-port 9999] [--wait 3s] [--json]
  run [--device id] [--host ip] [--port 7350] [--cwd path] [--timeout seconds] -- command [args...]
  doctor [--device id] [--host ip] [--port 7350]
  version

Config (env or .env):
  HOMEFLEET_TOKEN / DALE_TOKEN
  HOMEFLEET_EXEC / DALE_REMOTE_EXEC
  HOMEFLEET_SCOPE / DALE_REMOTE_SCOPE
  HOMEFLEET_DEVICE_ID
  HOMEFLEET_ALLOW_CIDRS
  HOMEFLEET_ENV

Devices download a release binary — no language runtime install required.
`)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func flagValue(args []string, name string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == name && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(arg, name+"=") {
			return strings.TrimPrefix(arg, name+"=")
		}
	}
	return ""
}

func flagBool(args []string, name string) bool {
	for _, arg := range args {
		if arg == name {
			return true
		}
	}
	return false
}

func intFlag(args []string, name string, fallback int) (int, error) {
	raw := flagValue(args, name)
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid %s %q", name, raw)
	}
	return n, nil
}

func durationFlag(args []string, name string, fallback time.Duration) (time.Duration, error) {
	raw := flagValue(args, name)
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		if sec, err2 := strconv.Atoi(raw); err2 == nil {
			return time.Duration(sec) * time.Second, nil
		}
		return 0, fmt.Errorf("invalid %s %q", name, raw)
	}
	return d, nil
}

func indexOf(args []string, want string) int {
	for i, arg := range args {
		if arg == want {
			return i
		}
	}
	return -1
}
