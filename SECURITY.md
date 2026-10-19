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
- Pairing codes cannot be guessed: after 5 wrong codes the pending device mints a new code (printed on its stderr and shown by `homefleet pairing`), and each wrong code from an IP doubles that IP's wait (1 s, 2 s, ... 60 s) before `/v1/approve` checks another.
- Commands time out; stdout/stderr are truncated.
- UDP discovery beacons never carry the token, and they are authenticated with it: `mac` = HMAC-SHA256(token, proto|id|hostname|os|http_port|ts|nonce). A beacon with a missing or wrong MAC, a `ts` more than 60 s from the receiver's clock, or a reused nonce is dropped without a reply. A rogue host that broadcasts beacons is never listed as a peer and never sent the token.

## What is not protected

- Transport is plain HTTP on the LAN/tailnet. Authenticated discovery stops rogue responders from harvesting the token; it does not stop a passive sniffer on an untrusted LAN from reading the `Authorization` header in flight. Use trusted networks or Tailscale.
- `--host <ip>` bypasses discovery; the token is sent to whatever listens there.

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
