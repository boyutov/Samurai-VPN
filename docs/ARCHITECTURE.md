# Architecture decision: Java application, WireGuard data plane

Java 21 and Maven provide a shared server/client codebase for Windows, Linux and
macOS. All project source is Java; the installed WireGuard engine is a separate
native prerequisite. The desktop uses Swing from the JDK. DesktopService calls
ClientMain.run in-process to share command validation and file handling; no shell
is launched. IO executes in SwingWorker with one operation admitted per window.
The GUI displays public peer metadata and never claims handshake/online status.

Desktop enrollment uses a new profile folder with identity.json, session.json and
owner.json when applicable. Failed enrollment retains recovery files. LocalDemo
owns its in-process loopback coordinator and stops it when the window closes.
A connected tunnel is kept current by the background agent (DesktopMain --agent), an
unprivileged per-user process: membership sync and PathManager run there, not in the
privileged service, which never holds server tokens or parses server responses.
The window registers profiles in agent/profiles.json and shows agent/status.json.
PackageApplication uses jpackage to create a platform-specific application image
including a Java runtime. It packages only the executable JAR, never profile files.

The coordinator stores network ownership, invite hashes, peer public keys,
credential hashes, addresses and optional reachable endpoints. NetworkRegistry is
synchronized so invite redemption and address allocation happen atomically. With
`--state-file`, StateStore saves a complete snapshot after every change (temporary
file, fsync, atomic rename, directory fsync) before the response is sent, and
NetworkRegistry restores the previous state if the save fails. Relay port pairs are
saved too, so members keep their relay endpoints across restarts. Without it the
state lives only in memory.

Client identities are generated locally. Enrollment sends a public key and metadata
over HTTPS. Export fetches authorized peer metadata and produces a WireGuard profile
locally, adding the private key only at that point. Neither the coordinator nor the
packet relay receives that private key.

Direct data path: device A → WireGuard → reachable UDP endpoint B.
Relayed data path (both members lack an endpoint, server started with --relay-host):
A → relay:portA → relay:portB → B. The relay is a selector loop over pre-bound
pairwise ports; it forwards only structurally valid WireGuard messages, learns a
source from a handshake with valid mac1 and applies per-direction byte quotas.
WireGuard still terminates only at the peers. See docs/RELAY.md.

Platform integration references:

- Windows: WireGuard embeddable service; privilege isolation and signed distribution.
- Linux: WireGuard kernel implementation, integration through a narrowly scoped
  helper or NetworkManager. Avoid running the whole Java application as root.
- macOS: WireGuardKit / Network Extension path with native helper, entitlements,
  signing and notarization evaluated on a real Mac.

Source: https://www.wireguard.com/embedding/

WireGuard is a layer-3 tunnel. Automatic discovery of LAN games using broadcast or
multicast is a separate feature and cannot be assumed to work by simply adding routes.
The first gameplay target is explicit virtual-IP and game-port connectivity.

0.1 uses 10.203.N.1–254 for each network, never reusing addresses during that process
lifetime. Members are limited to 64. Literal IPv4 endpoints prevent config injection
and avoid coordinator-side DNS resolution. No arbitrary process execution is exposed.
