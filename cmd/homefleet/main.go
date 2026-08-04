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

	"github.com/mmdmcy/homefleet/internal/approval"
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
	case "devices":
		return cmdDevices(cfg, args[1:])
	case "run":
		return cmdRun(cfg, args[1:])
	case "doctor":
		return cmdDoctor(cfg, args[1:])
	case "approve":
		return cmdApprove(cfg, args[1:])
	case "revoke":
		return cmdRevoke(cfg, args[1:])
	case "pairing":
		return cmdPairing(cfg, args[1:])
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

	store, err := approval.Open(cfg.ApprovalStatePath)
	if err != nil {
		return fmt.Errorf("approval store: %w", err)
	}
	if cfg.RequireApproval {
		if st := store.Snapshot(); !st.Approved {
			code, err := store.EnsurePairing()
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "homefleet: pending approval — pairing code %s\n", code)
			fmt.Fprintf(os.Stderr, "homefleet: from a trusted machine: homefleet approve --host <this-ip> --code %s\n", code)
			fmt.Fprintf(os.Stderr, "homefleet: or on this machine: homefleet approve --local\n")
		} else {
			fmt.Fprintf(os.Stderr, "homefleet: device approved (by %s)\n", store.Snapshot().ApprovedBy)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	table := discover.NewTable(cfg)
	errCh := make(chan error, 2)
	go func() {
		if err := discover.RunBeacon(ctx, cfg, table); err != nil {
			fmt.Fprintf(os.Stderr, "homefleet: beacon warning: %v (HTTP agent still running; discovery limited)\n", err)
			<-ctx.Done()
		}
		errCh <- nil
	}()
	go func() {
		fmt.Fprintf(os.Stderr, "homefleet listening on :%d (beacon :%d) id=%s exec=%v scope=%s approval_required=%v\n",
			cfg.HTTPPort, cfg.BeaconPort, cfg.DeviceID, cfg.ExecEnabled, cfg.Scope, cfg.RequireApproval)
		errCh <- server.NewWithApproval(cfg, table, store).ListenAndServe(ctx)
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		if err != nil {
			stop()
		}
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

func cmdDevices(cfg config.Config, args []string) error {
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
	peers, err := discover.ListenOnce(context.Background(), beaconPort, wait)
	if err != nil {
		return err
	}
	cli := client.New(cfg.Token)
	type row struct {
		Peer     discover.Peer  `json:"peer"`
		Whoami   *server.Whoami `json:"whoami,omitempty"`
		Error    string         `json:"error,omitempty"`
	}
	rows := make([]row, 0, len(peers))
	for _, peer := range peers {
		r := row{Peer: peer}
		if cfg.Token == "" {
			r.Error = "no token"
			rows = append(rows, r)
			continue
		}
		who, err := cli.Whoami(context.Background(), peer.BaseURL())
		if err != nil {
			r.Error = err.Error()
		} else {
			r.Whoami = &who
		}
		rows = append(rows, r)
	}
	if flagBool(args, "--json") {
		return printJSON(rows)
	}
	fmt.Printf("%-20s %-16s %-18s %-8s %-8s %s\n", "ID", "HOSTNAME", "IP", "APPROVED", "EXEC_OK", "NOTE")
	for _, r := range rows {
		approved, execOK, note := "?", "?", r.Error
		if r.Whoami != nil {
			if r.Whoami.Approved {
				approved = "yes"
			} else if r.Whoami.PendingApproval {
				approved = "pending"
			} else {
				approved = "n/a"
			}
			if r.Whoami.RemoteExecAllowed {
				execOK = "yes"
			} else {
				execOK = "no"
			}
			note = ""
		}
		fmt.Printf("%-20s %-16s %-18s %-8s %-8s %s\n", r.Peer.ID, r.Peer.Hostname, r.Peer.IP, approved, execOK, note)
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "no peers heard")
	}
	_ = httpPort
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

func cmdApprove(cfg config.Config, args []string) error {
	if flagBool(args, "--local") {
		store, err := approval.Open(cfg.ApprovalStatePath)
		if err != nil {
			return err
		}
		by := flagValue(args, "--by")
		if by == "" {
			by = cfg.DeviceID
		}
		if err := store.ApproveLocal(by); err != nil {
			return err
		}
		fmt.Printf("approved locally id=%s by=%s file=%s\n", cfg.DeviceID, by, store.Path())
		return nil
	}

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
	code := flagValue(args, "--code")
	if device == "" && host == "" {
		return fmt.Errorf("approve requires --local, or --host/--device plus --code <pairing-code>")
	}
	if code == "" {
		return fmt.Errorf("missing --code (printed by `homefleet serve` on the pending device)")
	}
	if cfg.Token == "" {
		return fmt.Errorf("missing token: set HOMEFLEET_TOKEN or DALE_TOKEN")
	}
	baseURL, err := client.ResolveBaseURL(context.Background(), cfg, device, host, httpPort, beaconPort)
	if err != nil {
		return err
	}
	out, err := client.New(cfg.Token).Approve(context.Background(), baseURL, code, cfg.DeviceID)
	if err != nil {
		return err
	}
	return printJSON(out)
}

func cmdRevoke(cfg config.Config, args []string) error {
	// Local revoke via store or via loopback API if serve is up.
	if flagBool(args, "--local") || (flagValue(args, "--host") == "" && flagValue(args, "--device") == "") {
		store, err := approval.Open(cfg.ApprovalStatePath)
		if err != nil {
			return err
		}
		if err := store.Revoke(); err != nil {
			return err
		}
		fmt.Printf("revoked approval for this device; new pairing code %s\n", store.PairingCode())
		fmt.Printf("state file: %s\n", store.Path())
		return nil
	}
	httpPort, err := intFlag(args, "--port", cfg.HTTPPort)
	if err != nil {
		return err
	}
	host := flagValue(args, "--host")
	if host == "" {
		host = "127.0.0.1"
	}
	if cfg.Token == "" {
		return fmt.Errorf("missing token")
	}
	baseURL, err := client.ResolveBaseURL(context.Background(), cfg, "", host, httpPort, cfg.BeaconPort)
	if err != nil {
		return err
	}
	out, err := client.New(cfg.Token).Revoke(context.Background(), baseURL)
	if err != nil {
		return err
	}
	return printJSON(out)
}

func cmdPairing(cfg config.Config, args []string) error {
	httpPort, err := intFlag(args, "--port", cfg.HTTPPort)
	if err != nil {
		return err
	}
	// Prefer live agent on loopback so code matches the running process.
	if cfg.Token != "" {
		localURL := fmt.Sprintf("http://127.0.0.1:%d", httpPort)
		if out, err := client.New(cfg.Token).Pairing(context.Background(), localURL); err == nil {
			if flagBool(args, "--json") {
				return printJSON(out)
			}
			if code, ok := out["pairing_code"].(string); ok && code != "" {
				fmt.Printf("pairing code: %s\n", code)
				fmt.Printf("device id:    %v\n", out["device_id"])
				return nil
			}
			fmt.Printf("device already approved (id=%v)\n", out["device_id"])
			return nil
		}
	}
	store, err := approval.Open(cfg.ApprovalStatePath)
	if err != nil {
		return err
	}
	st := store.Snapshot()
	if st.Approved {
		fmt.Printf("device already approved (by %s)\n", st.ApprovedBy)
		return nil
	}
	code, err := store.EnsurePairing()
	if err != nil {
		return err
	}
	if flagBool(args, "--json") {
		return printJSON(map[string]any{
			"device_id":     cfg.DeviceID,
			"pairing_code":  code,
			"approved":      false,
			"state_file":    store.Path(),
		})
	}
	fmt.Printf("pairing code: %s\n", code)
	fmt.Printf("device id:    %s\n", cfg.DeviceID)
	fmt.Printf("state file:   %s\n", store.Path())
	fmt.Fprintln(os.Stderr, "note: if `homefleet serve` is already running, prefer its printed code (restart serve after pairing file changes)")
	return nil
}

func printUsage() {
	fmt.Print(`homefleet — frictionless LAN fleet control

Commands:
  serve [--port 7350] [--beacon-port 9999] [--env path]
  peers [--beacon-port 9999] [--wait 3s] [--json]
  devices [--wait 3s] [--json]
  run [--device id] [--host ip] [--port 7350] [--cwd path] [--timeout seconds] -- command [args...]
  doctor [--device id] [--host ip] [--port 7350]
  approve --local
  approve --host <ip> --code <pairing-code>
  revoke [--local]
  pairing [--json]
  version

Config (env or .env):
  HOMEFLEET_TOKEN / DALE_TOKEN
  HOMEFLEET_EXEC / DALE_REMOTE_EXEC
  HOMEFLEET_SCOPE / DALE_REMOTE_SCOPE
  HOMEFLEET_DEVICE_ID
  HOMEFLEET_ALLOW_CIDRS
  HOMEFLEET_REQUIRE_APPROVAL   (default 1) — pending devices block remote exec until approved
  HOMEFLEET_APPROVAL_FILE      optional path to approval.json
  HOMEFLEET_ENV

Device approval:
  New devices print a pairing code on serve. A trusted operator approves them with
  that code. Token alone is not enough to unlock remote exec on a pending device.
  First controller box: homefleet approve --local

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
