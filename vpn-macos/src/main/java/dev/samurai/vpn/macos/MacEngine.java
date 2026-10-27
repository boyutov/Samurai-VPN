package dev.samurai.vpn.macos;

import dev.samurai.vpn.core.*;
import dev.samurai.vpn.linux.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * The privileged surface on macOS, run as root by the launchd service. It does what wg-quick
 * does, without bash: wireguard-go creates a utun interface, wg configures it, ifconfig and
 * route add the /32 address and member routes. wireguard-go and wg are root-owned copies made
 * by the installer, never the user-writable Homebrew files. No DNS or default route change.
 */
public final class MacEngine {
    static final String TOOLS = "/Library/Application Support/SamuraiVPN/bin";
    static final String WG = TOOLS + "/wg", WIREGUARD_GO = TOOLS + "/wireguard-go";
    static final String IFCONFIG = "/sbin/ifconfig", ROUTE = "/sbin/route", NETSTAT = "/usr/sbin/netstat", SH = "/bin/sh";
    // Fixed script, inputs only as positional arguments: wireguard-go reports the utun it picked through
    // WG_TUN_NAME_FILE and must not keep our output pipes open after it daemonizes.
    static final String START = "WG_TUN_NAME_FILE=\"$1\" exec \"$2\" utun </dev/null >/dev/null 2>&1";
    private final CommandRunner runner;
    private final long uid;
    private final Path state, sockets;

    /** state: root-only directory with one file per tunnel naming its utun; sockets: wireguard-go's /var/run/wireguard. */
    public MacEngine(CommandRunner runner, long uid, Path state, Path sockets) {
        if (uid < 0 || uid > 0xFFFF_FFFFL) throw new IllegalArgumentException("Invalid caller UID");
        this.runner = runner; this.uid = uid; this.state = state; this.sockets = sockets;
    }
    /** Samurai's name for the tunnel of this user and network; the kernel picks the utun number. */
    public String tunnelName(String networkId) {
        Validation.id(networkId);
        try {
            return "sm" + HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest((uid + ":" + networkId).getBytes(StandardCharsets.US_ASCII))).substring(0, 12);
        } catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
    public TunnelProtocol.Status execute(TunnelProtocol.Request request) throws Exception {
        TunnelProtocol.validate(request);
        return switch (request.operation()) {
            case "up" -> up(request.networkId(), request.configuration());
            case "down" -> down(request.networkId());
            case "status" -> status(request.networkId());
            case "endpoint" -> endpoint(request.networkId(), request.peerPublicKey(), request.endpoint());
            case "sync" -> sync(request.networkId(), request.configuration());
            default -> throw new IllegalArgumentException("Unsupported operation");
        };
    }
    private TunnelProtocol.Status up(String id, TunnelProtocol.Configuration config) throws Exception {
        String name = tunnelName(id);
        if (utun(name) != null) throw new IOException("Interface already exists; disconnect it first");
        RouteGuard.check(routes(), addresses(), config);
        Path record = state.resolve(name);
        Files.deleteIfExists(record); // stale: utun(name) found no live interface behind it
        runner.run(List.of(SH, "-c", START, "sh", record.toString(), WIREGUARD_GO), "");
        String device = null;
        try {
            device = readUtun(record);
            runner.run(List.of(WG, "setconf", device, "/dev/stdin"), TunnelProtocol.nativeConfig(config));
            runner.run(List.of(IFCONFIG, device, "inet", config.address() + "/32", config.address(), "alias"), "");
            // Conservative fixed MTU until path-MTU detection is implemented.
            runner.run(List.of(IFCONFIG, device, "mtu", "1280"), "");
            runner.run(List.of(IFCONFIG, device, "up"), "");
            for (var peer : config.peers()) route("add", peer.address(), device);
            return status(id);
        } catch (Exception failure) {
            try {
                // Removing the control socket makes wireguard-go close the utun and exit, as wg-quick down does.
                if (device != null) Files.deleteIfExists(sockets.resolve(device + ".sock"));
                Files.deleteIfExists(record);
            } catch (Exception cleanup) {
                var failureWithCleanup = new IOException("Tunnel setup failed; cleanup could not be confirmed for " + name, failure);
                failureWithCleanup.addSuppressed(cleanup); throw failureWithCleanup;
            }
            throw failure;
        }
    }
    private TunnelProtocol.Status down(String id) throws Exception {
        String name = tunnelName(id), device = utun(name);
        if (device != null) Files.deleteIfExists(sockets.resolve(device + ".sock"));
        Files.deleteIfExists(state.resolve(name));
        return new TunnelProtocol.Status("down", name, 0, 0, 0);
    }
    private TunnelProtocol.Status endpoint(String id, String publicKey, String endpoint) throws Exception {
        String device = running(id);
        // "wg set peer" would silently add an unknown key, so only already configured peers are accepted.
        boolean known = runner.run(List.of(WG, "show", device, "peers"), "").lines().map(String::strip).anyMatch(publicKey::equals);
        if (!known) throw new IOException("Refusing to add a peer through an endpoint change");
        runner.run(List.of(WG, "set", device, "peer", publicKey, "endpoint", endpoint), "");
        return status(id);
    }
    /** Same contract as the Linux sync; routes go through route(8) on the utun. */
    private TunnelProtocol.Status sync(String id, TunnelProtocol.Configuration config) throws Exception {
        String device = running(id);
        if (!runner.run(List.of(WG, "show", device, "public-key"), "").strip().equals(config.identity().publicKey()))
            throw new IOException("Refusing to change a tunnel of another identity");
        var current = new HashMap<String, String>();
        for (String line : runner.run(List.of(WG, "show", device, "allowed-ips"), "").lines().filter(s -> !s.isBlank()).toList()) {
            String[] fields = line.strip().split("\\s+");
            WireGuardKeys.validatePublic(fields[0]);
            current.put(fields[0], fields.length == 2 && fields[1].endsWith("/32") ? fields[1].substring(0, fields[1].length() - 3) : "");
        }
        var endpoints = new HashMap<String, String>();
        for (var peerState : status(id).peers()) endpoints.put(peerState.publicKey(), peerState.endpoint());
        var desired = new LinkedHashMap<String, Api.Peer>();
        for (var peer : config.peers()) desired.put(peer.publicKey(), peer);
        for (var entry : current.entrySet()) {
            var wanted = desired.get(entry.getKey());
            if (wanted != null && wanted.address().equals(entry.getValue())) continue;
            // Route first: a key without a route carries no traffic even if its removal fails.
            if (!entry.getValue().isEmpty()) {
                try { route("delete", entry.getValue(), device); } catch (IOException ignored) { /* already absent */ }
            }
            runner.run(List.of(WG, "set", device, "peer", entry.getKey(), "remove"), "");
        }
        var added = config.peers().stream().filter(p -> !p.address().equals(current.get(p.publicKey()))).toList();
        if (!added.isEmpty()) RouteGuard.check(routes(), addresses(), added.stream().map(Api.Peer::address).toList(), device);
        for (var peer : added) {
            var command = new ArrayList<>(List.of(WG, "set", device, "peer", peer.publicKey(), "allowed-ips", peer.address() + "/32"));
            String endpoint = Validation.endpoint(peer.endpoint());
            if (!endpoint.isEmpty()) command.addAll(List.of("endpoint", endpoint, "persistent-keepalive", "25"));
            runner.run(command, "");
            try { route("add", peer.address(), device); }
            catch (Exception failure) { runner.run(List.of(WG, "set", device, "peer", peer.publicKey(), "remove"), ""); throw failure; }
        }
        for (var peer : config.peers()) {
            String endpoint = Validation.endpoint(peer.endpoint());
            if (current.containsKey(peer.publicKey()) && !endpoint.isEmpty() && endpoints.getOrDefault(peer.publicKey(), "").isEmpty())
                runner.run(List.of(WG, "set", device, "peer", peer.publicKey(), "endpoint", endpoint, "persistent-keepalive", "25"), "");
        }
        return status(id);
    }
    public TunnelProtocol.Status status(String id) throws Exception {
        String name = tunnelName(id), device = utun(name);
        if (device == null) return new TunnelProtocol.Status("down", name, 0, 0, 0);
        return WireGuardStatus.parse("up", device, runner.run(List.of(WG, "show", device, "latest-handshakes"), ""),
                runner.run(List.of(WG, "show", device, "transfer"), ""), runner.run(List.of(WG, "show", device, "endpoints"), ""));
    }
    /**
     * The live utun of this tunnel, or null. Ownership is the record in the root-only state
     * directory: utun numbers are assigned by the kernel, so another tool cannot pre-create ours.
     */
    private String utun(String name) throws Exception {
        Path record = state.resolve(name);
        if (Files.isSymbolicLink(record)) throw new IOException("Refusing to change an interface not owned by this profile");
        if (!Files.isRegularFile(record, LinkOption.NOFOLLOW_LINKS)) return null;
        String device = readUtun(record);
        if (!Files.exists(sockets.resolve(device + ".sock"))) return null;
        try { runner.run(List.of(IFCONFIG, device), ""); } catch (IOException gone) { return null; }
        return device;
    }
    private String running(String id) throws Exception {
        String device = utun(tunnelName(id));
        if (device == null) throw new IOException("Refusing to change an interface that is not connected");
        return device;
    }
    private static String readUtun(Path record) throws IOException {
        String device = Files.readString(record).strip();
        if (!device.matches("utun[0-9]{1,3}")) throw new IOException("Unexpected tunnel interface name");
        return device;
    }
    private void route(String action, String address, String device) throws Exception {
        runner.run(List.of(ROUTE, "-q", "-n", action, "-inet", address + "/32", "-interface", device), "");
    }
    private String routes() throws Exception { return MacNetwork.routes(runner.run(List.of(NETSTAT, "-rn", "-f", "inet"), "")); }
    private String addresses() throws Exception { return MacNetwork.addresses(runner.run(List.of(IFCONFIG, "-a"), "")); }
}
