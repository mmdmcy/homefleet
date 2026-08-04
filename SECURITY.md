# Security

Homefleet is intentional remote command execution between machines that share a bearer token on a private network.

## Trust model

Anyone who has the shared token can run commands on any peer where exec is enabled. That is the product. Treat the token like a root password for your LAN fleet.

## Defaults that keep outsiders out

- Source IPs outside private ranges are rejected unless `HOMEFLEET_SCOPE=public` (or `DALE_REMOTE_SCOPE=public`) is set.
- `/healthz` is unauthenticated and returns only `{ "ok": true }`.
- `/v1/*` requires `Authorization: Bearer <token>`.
- Remote exec stays off until `HOMEFLEET_EXEC=1` or `DALE_REMOTE_EXEC=1`.
- Commands time out; stdout/stderr are truncated.
- UDP discovery beacons never carry the token.

## Do not

- Port-forward Homefleet to the public internet.
- Commit `.env` or real tokens.
- Reuse the token in untrusted environments.
- Run with `HOMEFLEET_SCOPE=public` without another perimeter (firewall, VPN, reverse proxy).

## Reporting issues

Open a private security advisory or an issue without including tokens, hostnames that identify you, or network diagrams of a real deployment.
