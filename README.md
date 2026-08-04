# Homefleet

Frictionless LAN fleet control. One static binary per machine. No language runtime to install. No Tailscale required.

Homefleet lets trusted devices on a private network discover each other and run commands remotely. Exec between peers that share a token is intentional. Keeping outsiders out is the security goal.

## Why a binary (not a script)

Devices never install Go, Python, or anything else. You download a release asset (or copy the binary) and run it. The project is written in Go so one codebase covers Linux, macOS (Big Sur+), and Windows.

## Quick start

1. Download the release binary for your OS/arch from GitHub Releases.
2. Put the same shared token on every device (see Config).
3. Enable exec only on devices you want to control remotely.
4. Start the agent:

```bash
./homefleet serve
```

5. From another machine on the same LAN:

```bash
./homefleet peers
./homefleet doctor --device laptop
./homefleet run --device laptop -- hostname
```

Or target an IP directly (works even if discovery is blocked):

```bash
./homefleet run --host 192.168.1.50 -- hostname
```

### Build from source (developers)

```bash
git clone https://github.com/mmdmcy/homefleet.git
cd homefleet
make build
./bin/homefleet version
```

End users do not need this step.

## Config

Homefleet reads environment variables and `.env` files. It accepts Masterdale-compatible names so you can reuse an existing shared token without retyping it.

| Variable | Also accepted | Meaning |
| --- | --- | --- |
| `HOMEFLEET_TOKEN` | `DALE_TOKEN` | Shared bearer token |
| `HOMEFLEET_EXEC` | `DALE_REMOTE_EXEC` | `1` enables remote exec on this device |
| `HOMEFLEET_SCOPE` | `DALE_REMOTE_SCOPE` | `private` (default), `loopback`, `tailnet`, `public` |
| `HOMEFLEET_DEVICE_ID` | | Stable peer id (default: hostname) |
| `HOMEFLEET_ALLOW_CIDRS` | | Optional extra CIDR allowlist |
| `HOMEFLEET_ENV` | | Path to an env file |

Load order: process env → `--env` / `HOMEFLEET_ENV` → cwd/`FindUp` `.env` → `~/.config/homefleet/config.env` (Windows: `%AppData%\homefleet\config.env`). Existing env values are not overwritten by files.

Example `.env`:

```env
HOMEFLEET_TOKEN=replace-with-a-long-random-secret
HOMEFLEET_EXEC=1
HOMEFLEET_SCOPE=private
```

If you already use Masterdale, the same `DALE_TOKEN` / `DALE_REMOTE_EXEC` / `DALE_REMOTE_SCOPE` values work.

## How it works

- **UDP beacon** (default port `9999`): peers announce id, hostname, OS, and HTTP port. Beacons never include the token.
- **HTTP agent** (default port `7350`): `/healthz`, `/v1/whoami`, `/v1/exec`.
- **Auth**: `Authorization: Bearer <token>` on `/v1/*`.
- **Network policy**: by default only loopback, private LAN, and Tailscale ranges may connect. Tailscale is optional; LAN-only fleets work fine.

```text
laptop  --UDP beacon-->  LAN
laptop  --HTTP /v1/exec Bearer token-->  nas
```

## Security

Read [SECURITY.md](SECURITY.md).

Short version:

- Shared token ≈ fleet root password.
- Do not port-forward Homefleet to the internet.
- Leave `HOMEFLEET_EXEC=0` on machines that should not accept remote commands.
- Prefer `HOMEFLEET_SCOPE=private` (default).

## Commands

```text
homefleet serve [--port 7350] [--beacon-port 9999]
homefleet peers [--wait 3s] [--json]
homefleet run --device <id> -- command [args...]
homefleet run --host <ip> -- command [args...]
homefleet doctor [--device <id>|--host <ip>]
homefleet version
```

## Ports

| Port | Protocol | Purpose |
| --- | --- | --- |
| 7350 | TCP/HTTP | Agent API |
| 9999 | UDP | Discovery beacons |

Chosen to stay clear of Masterdale's default `7345` if both run on one host.

## License

Apache License 2.0. See [LICENSE](LICENSE).
