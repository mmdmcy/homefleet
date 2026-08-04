# Security

Homefleet is intentional remote command execution between machines that share a bearer token on a private network.

## Trust model

Anyone who has the shared token **and** is talking to an **approved** device (when approval is required) can run commands where exec is enabled. Treat the token like a root password for your LAN fleet. Pairing codes stop a stolen token alone from unlocking a brand-new agent.

## Defaults that keep outsiders out

- Source IPs outside private ranges are rejected unless `HOMEFLEET_SCOPE=public` (or `DALE_REMOTE_SCOPE=public`) is set.
- `/healthz` is unauthenticated and returns only `{ "ok": true }`.
- `/v1/*` requires `Authorization: Bearer <token>`.
- Remote exec stays off until `HOMEFLEET_EXEC=1` or `DALE_REMOTE_EXEC=1`.
- **Device approval** is on by default (`HOMEFLEET_REQUIRE_APPROVAL=1`): a pending device rejects remote `/v1/exec` until approved with its pairing code (or `homefleet approve --local` on that machine). Pairing codes are never returned over non-loopback HTTP.
- Commands time out; stdout/stderr are truncated.
- UDP discovery beacons never carry the token.

## Approving a new device

1. Start `homefleet serve` on the new machine — it prints `pairing code XXXX-XXXX`.
2. From a trusted machine with the same token:  
   `homefleet approve --host <new-ip> --code XXXX-XXXX`
3. Confirm with `homefleet doctor --host <new-ip>` or `homefleet devices`.

Escape hatch for your first controller: `homefleet approve --local` on that box.  
Disable the feature entirely with `HOMEFLEET_REQUIRE_APPROVAL=0` if you accept token-only trust.

## Do not

- Port-forward Homefleet to the public internet.
- Commit `.env`, real tokens, or `approval.json`.
- Reuse the token in untrusted environments.
- Run with `HOMEFLEET_SCOPE=public` without another perimeter (firewall, VPN, reverse proxy).
- Read pairing codes aloud on untrusted networks / screen-share them carelessly.

## Reporting issues

Open a private security advisory or an issue without including tokens, hostnames that identify you, or network diagrams of a real deployment.
