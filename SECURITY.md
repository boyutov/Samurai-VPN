# Security status

Samurai VPN 0.2 is a development preview, not an audited production VPN.
Do not publish this server on the open internet or use it to protect sensitive
production traffic. Security requirements are tracked in docs/ROADMAP.md.

## Implemented boundaries

- HTTPS is required outside explicit loopback development mode. JVM certificate
  and hostname validation are enabled. Redirects are not followed.
- Administration, network ownership, invitations and device credentials have
  separate authority. A server-admin token creates networks but is not a peer token.
- Tokens contain 256 random bits. Server storage retains only SHA-256 hashes.
  Invites expire after ten minutes and can be consumed once, including under concurrency.
- WireGuard private keys remain on the originating device. X25519 key derivation
  uses the JDK provider; packet cryptography belongs to installed WireGuard.
- Profiles contain only per-peer /32 routes in the network's assigned /24.
  No default-route, DNS, shell hooks or arbitrary config text is accepted.
- Secret outputs are create-only, with restrictive permissions at creation.
- Desktop commands reuse CLI validation without executing a shell. Opening a
  profile verifies that owner and member credentials belong to the same origin
  and network. Public peer labels are rendered as plain text, not HTML.
- Local desktop demo runs only on loopback and closes with the window.
- Request/response sizes, JSON structure, network/member/invite counts and request
  rate are bounded. Browser Origin requests are rejected; there is no CORS policy
  granting access. Request bodies and Authorization headers are never logged.

## Trust and limitations

The coordinator is trusted to bind peer identity to a public key. A compromised
coordinator can substitute public keys and influence endpoints. End-to-end identity
verification, signed network membership and key-change confirmation are pending.
An endpoint is deliberately a literal IPv4 address; IPv6/DNS endpoints are not yet supported.

Bearer credentials are capabilities. Anyone who obtains one has its authority.
There is no account recovery, MFA, token rotation or encrypted OS keychain storage yet.
File permissions do not protect against another process running as the same user.
Protect parent directories from other users. Windows ACL behavior needs native CI
and interactive deployment testing; FAT/exFAT without secure permissions is rejected.

The server is bounded (32 networks, 64 active peers and 32 outstanding
invites per network), but not a public multi-tenant service. One client can exhaust
the global rate budget. No distributed rate limiting or audit log is implemented.
With `--state-file` the state survives restarts: one private (0600) JSON file holding
only token hashes, replaced atomically with fsync and guarded by a lock file. A failed
save rolls the change back and returns 503. Anyone who can write that file can add
members, so protect its directory like the admin token. Without `--state-file`, restart
invalidates memberships, not previously exported keys.
The 10.203.0.0/16 allocation pool may conflict with existing routes; there is no native
route-conflict detection yet.

Revocation removes API membership at once and stops relaying the member's traffic.
Members whose tunnel runs through the tunnel service remove the key from their running
interface within about 30 seconds (background agent, also with the window closed).
Members who imported an exported profile into WireGuard, or use Linux without
samurai-vpnd, keep the key until they apply an updated profile. Likewise, this is a split tunnel, not an anonymity
or full-device internet VPN; no kill switch is advertised.

The privileged tunnel components are described in docs/LINUX.md, docs/WINDOWS.md and
docs/MACOS.md; on Windows and macOS they are installed and exercised in CI, not yet on
user devices. There is no automatic firewall management.

The background agent (docs/AGENT.md) runs as the signed-in user with no privileges. It
reads the profile tokens the user already owns and talks to the tunnel service over the
same socket as the window. Its files hold no keys or tokens; a process of the same user
can change them, which it could do to the profiles anyway. It registers a per-user login
item while a tunnel is connected and removes it on the last disconnect.

The optional UDP relay (docs/RELAY.md) forwards WireGuard ciphertext only; it never
holds private keys. It binds a source address to a port only after a handshake with
a valid mac1 for the expected recipient. mac1 uses a public key, so another network
member (or anyone who learns that key) can still take over a relay port: the result
is denial of service and visible ciphertext, not decryption or impersonation.
Relay metadata (who talks to whom, when, how much) is visible to the server operator.

Hole punching publishes each relayed member's observed public IP:port to the other
members of the network (not to the owner view or outsiders). The samurai-vpnd service
holds CAP_NET_ADMIN only, authenticates callers with SO_PEERCRED and limits each UID
to interfaces derived from that UID. Its "endpoint" operation cannot add peers or routes.
The SO_PEERCRED UID is read through a JDK-internal accessor (--add-opens); if it is
unavailable, the service fails closed. Any local user may open the socket; a local
user can therefore make the service do bounded work, but not touch other users' tunnels.

## Reporting

Bundled application images include a Java runtime. Keep runtime security updates
in the release process; changing system Java does not update the bundled runtime.
The image contains no WireGuard driver and makes no claim of automatic tunnel
activation. Native images, installers and signing still need platform validation.
Desktop profiles remain on disk after closing (POSIX directory 0700, files 0600;
explicit private ACL on Windows files). OS keychain storage is not implemented.

No public vulnerability-reporting endpoint has been configured yet. Before opening
this project to other users, its owner must establish a private reporting channel,
select a release license and complete independent review. Do not include keys,
invites, tokens or user traffic in reports or public issues.
