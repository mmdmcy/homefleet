# Homefleet

Frictionless LAN fleet control. One static binary per machine. No language runtime to install. No Tailscale required.

Homefleet lets trusted devices on a private network discover each other and run commands remotely. Exec between peers that share a token is intentional. Keeping outsiders out is the security goal. New devices stay **pending** until you approve them with a one-time pairing code.

## Why a binary (not a script)

Devices never install Go, Python, or anything else. You download a release asset (or copy the binary) and run it. The project is written in Go so one codebase covers Linux, macOS (Big Sur+), and Windows.

## Quick start

1. Download the release binary for your OS/arch from GitHub Releases.
2. Put the same shared token on every device (see Config).
3. Enable exec only on devices you want to control remotely.
4. On your first / controller machine, approve it locally once:

```bash
homefleet approve --local
```

5. Start the agent on each device you want online:

```bash
./homefleet serve
```

Pending devices print a pairing code. Approve them from a trusted machine:

```bash
homefleet approve --host 192.168.1.50 --code 1234-5678
```

If the token lives in an env file (including an existing Masterdale `.env`):

```bash
export HOMEFLEET_ENV=/path/to/.env
homefleet serve
```

6. From another machine on the same LAN:

```bash
export HOMEFLEET_ENV=/path/to/.env   # same shared token
homefleet peers
homefleet devices
homefleet doctor --host 192.168.1.50
homefleet run --host 192.168.1.50 -- hostname
```

Discovery (`--device`) works when UDP beacons are allowed; `--host` always works if the agent is reachable.

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
| `HOMEFLEET_REQUIRE_APPROVAL` | | `1` (default) requires pairing approval before remote exec |
| `HOMEFLEET_APPROVAL_FILE` | | Optional path to `approval.json` |
| `HOMEFLEET_ENV` | | Path to an env file |

Load order: process env → `--env` / `HOMEFLEET_ENV` → cwd/`FindUp` `.env` → `~/.config/homefleet/config.env` (Windows: `%AppData%\homefleet\config.env`). Existing env values are not overwritten by files.

Approval state defaults to `~/.config/homefleet/approval.json` (Windows: `%AppData%\homefleet\approval.json`).

Example `.env`:

```env
HOMEFLEET_TOKEN=replace-with-a-long-random-secret
HOMEFLEET_EXEC=1
HOMEFLEET_SCOPE=private
HOMEFLEET_REQUIRE_APPROVAL=1
```

If you already use Masterdale, the same `DALE_TOKEN` / `DALE_REMOTE_EXEC` / `DALE_REMOTE_SCOPE` values work.

## How it works

- **UDP beacon** (default port `9999`): peers announce id, hostname, OS, and HTTP port. Beacons never include the token.
- **HTTP agent** (default port `7350`): `/healthz`, `/v1/whoami`, `/v1/exec`, `/v1/approve`.
- **Auth**: `Authorization: Bearer <token>` on `/v1/*`.
- **Approval**: pending agents reject remote exec until `POST /v1/approve` with the pairing code (or local approve).
- **Network policy**: by default only loopback, private LAN, and Tailscale ranges may connect. Tailscale is optional; LAN-only fleets work fine.

```text
laptop  --UDP beacon-->  LAN
laptop  --HTTP /v1/approve + code-->  new-nas   (one-time)
laptop  --HTTP /v1/exec Bearer token-->  nas
```

## Security

Read [SECURITY.md](SECURITY.md).

Short version:

- Shared token ≈ fleet root password.
- Pairing code ≈ unlock for a new device (token alone is not enough while pending).
- Do not port-forward Homefleet to the internet.
- Leave `HOMEFLEET_EXEC=0` on machines that should not accept remote commands.
- Prefer `HOMEFLEET_SCOPE=private` (default).

## Commands

```text
homefleet serve [--port 7350] [--beacon-port 9999]
homefleet peers [--wait 3s] [--json]
homefleet devices [--wait 3s] [--json]
homefleet run --device <id> -- command [args...]
homefleet run --host <ip> -- command [args...]
homefleet doctor [--device <id>|--host <ip>]
homefleet approve --local
homefleet approve --host <ip> --code <pairing-code>
homefleet revoke [--local]
homefleet pairing
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
