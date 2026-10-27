# Release gates

Dates will be estimated after native integration and test-device availability are established.
The earlier conversational time estimates are not a delivery commitment.

## 0.1 — current foundation

- [x] Java 21 multi-module Maven project and executable JARs.
- [x] Scoped credentials, one-use invitations and bounded API.
- [x] Local WireGuard identities and injection-resistant split-tunnel profiles.
- [x] HTTP workflow and HTTPS certificate/hostname validation tests.
- [x] CI definition for Windows, Linux and macOS (execution still required).

## 0.2 — desktop preview

- [x] Swing create/join, profile reopen, peer list, invitation, export and revocation.
- [x] Local two-device demo and background IO.
- [x] jpackage build script with bundled Java runtime.
- [ ] Interactive Windows/macOS validation and signed installers.

## Next — real cross-platform tunnels

- [x] Native helper contract, least-privilege IPC and allowlisted operations (Linux).
- [x] Linux adapter lifecycle and route-conflict detection (namespace-tested).
- [ ] Linux MTU detection; polkit flow on a real desktop.
- [x] Windows tunnel service (WireGuard for Windows, SYSTEM scheduled task, AF_UNIX socket); unit-tested only.
- [x] macOS tunnel service (wireguard-go + wg, launchd, LOCAL_PEERCRED); unit-tested only.
- [ ] Windows and macOS validation on real devices.
- [x] Automated peer refresh (sync every 30 s with the desktop open and samurai-vpnd).
- [ ] Peer refresh without the desktop window (service-side polling).
- [ ] Real WireGuard handshake, ping and Minecraft test on all OS pairs.
- [ ] OS keychains and private ACL verification on Windows/macOS.

## 0.3 — internet connectivity and durability

- [x] Persistent storage: atomic snapshot file, rollback on failed save, lock, versioned format.
- [ ] Format migrations (when version 2 appears), automated backups, audit log.
- [ ] Account/device binding, credential rotation, expired-session cleanup.
- [ ] Signed membership or independently verified peer identity.
- [x] Relay with end-to-end ciphertext, mac1-gated address learning and byte quotas.
- [x] NAT hole punching with relay fallback (unit-tested; internet test pending).
- [x] Resident Linux service with CAP_NET_ADMIN only and SO_PEERCRED callers.
- [ ] LAN candidates for peers behind the same router; relay authentication beyond mac1.
- [ ] IPv6, network switching, sleep/resume and reconnect tests.
- [ ] Backpressure, memory/connection limits and adversarial load tests.

## User release

- [x] Initial Java desktop GUI.
- [ ] Accessibility review and recovery flow for interrupted enrollment.
- [ ] Signed installers/runtime bundles for all platforms, signed update metadata.
- [ ] Dependency vulnerability scan, SBOM, release license and reporting channel.
- [ ] External security audit, fixes, and regression tests.
- [ ] Clear privacy policy, minimal logs and server-operation procedures.

Broadcast/multicast game discovery is a separately scoped feature. Mobile support
is outside the current Windows/Linux/macOS objective.
