package dev.samurai.vpn.windows;

import com.fasterxml.jackson.databind.JsonNode;
import dev.samurai.vpn.core.*;
import dev.samurai.vpn.linux.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * The privileged surface on Windows, run by the Samurai service as SYSTEM. Each network is a
 * WireGuard for Windows tunnel service whose configuration lives in a directory that only
 * SYSTEM and Administrators can read. A tunnel belongs to Samurai only if its configuration
 * file is in that directory. Only /32 routes to members; no DNS, default route or firewall change.
 */
public final class WindowsEngine {
    static final String WIREGUARD_DIR = "C:\\Program Files\\WireGuard\\", SYSTEM32 = "C:\\Windows\\System32\\";
    static final String WIREGUARD = WIREGUARD_DIR + "wireguard.exe", WG = WIREGUARD_DIR + "wg.exe";
    static final String SC = SYSTEM32 + "sc.exe", NETSH = SYSTEM32 + "netsh.exe",
            POWERSHELL = SYSTEM32 + "WindowsPowerShell\\v1.0\\powershell.exe";
    // Fixed scripts in the same JSON shape as "ip -j", so RouteGuard checks both systems alike. Module
    // autoloading is off: without a module analysis cache (the service's clean environment) it scans every
    // installed module first, 35-50 s on a CI runner instead of under one second.
    static final String MODULES = "$PSModuleAutoLoadingPreference = 'None'; Import-Module Microsoft.PowerShell.Utility, NetTCPIP -ErrorAction Stop; ";
    static final String ROUTES = MODULES + "[Console]::OutputEncoding = [Text.Encoding]::UTF8; ConvertTo-Json -Compress -Depth 4 -InputObject "
            + "@(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ dst = $_.DestinationPrefix; dev = $_.InterfaceAlias } })";
    static final String ADDRESSES = MODULES + "[Console]::OutputEncoding = [Text.Encoding]::UTF8; ConvertTo-Json -Compress -Depth 4 -InputObject "
            + "@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ ifname = $_.InterfaceAlias; "
            + "addr_info = @([pscustomobject]@{ family = 'inet'; local = $_.IPAddress; prefixlen = [int]$_.PrefixLength }) } })";
    private final CommandRunner runner;
    private final Path tunnels;

    public WindowsEngine(CommandRunner runner, Path tunnels) { this.runner = runner; this.tunnels = tunnels; }

    /** Tunnel and interface name; WireGuard for Windows allows at most 32 characters. */
    public static String tunnelName(String networkId) {
        Validation.id(networkId);
        try {
            return "samurai" + HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(networkId.getBytes(StandardCharsets.US_ASCII))).substring(0, 12);
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
    private Path configuration(String name) { return tunnels.resolve(name + ".conf"); }
    static String nativeConfig(TunnelProtocol.Configuration config) {
        // Unlike wg setconf, the tunnel service applies Address itself and adds routes for AllowedIPs.
        String rendered = WireGuardConfig.render(config.identity(), config.address(), config.listenPort(), config.peers());
        String listen = "ListenPort = " + config.listenPort() + "\n";
        return rendered.replace(listen, listen + "MTU = 1280\n");
    }
    private TunnelProtocol.Status up(String id, TunnelProtocol.Configuration config) throws Exception {
        String name = tunnelName(id); Path file = configuration(name);
        if (serviceExists(name) || Files.exists(file, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Interface already exists; disconnect it first");
        RouteGuard.check(powershell(ROUTES), powershell(ADDRESSES), config);
        // CREATE_NEW: never follows or replaces a file planted in the directory.
        Files.writeString(file, nativeConfig(config), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        try {
            runner.run(List.of(WIREGUARD, "/installtunnelservice", file.toString()), "");
            // The tunnel service creates the interface after the command returns.
            await(() -> { runner.run(List.of(WG, "show", name, "public-key"), ""); return true; }, "Tunnel service did not start");
            var state = status(id);
            if (!state.state().equals("up")) throw new IOException("Tunnel service did not start");
            return state;
        } catch (Exception failure) {
            try {
                if (serviceExists(name)) uninstall(name);
                Files.deleteIfExists(file);
            } catch (Exception cleanup) {
                var failureWithCleanup = new IOException("Tunnel setup failed; cleanup could not be confirmed for " + name, failure);
                failureWithCleanup.addSuppressed(cleanup); throw failureWithCleanup;
            }
            throw failure;
        }
    }
    private TunnelProtocol.Status down(String id) throws Exception {
        String name = tunnelName(id);
        if (owned(name) && serviceExists(name)) uninstall(name);
        Files.deleteIfExists(configuration(name));
        return new TunnelProtocol.Status("down", name, 0, 0, 0);
    }
    private TunnelProtocol.Status endpoint(String id, String publicKey, String endpoint) throws Exception {
        String name = running(id);
        // "wg set peer" would silently add an unknown key, so only already configured peers are accepted.
        boolean known = runner.run(List.of(WG, "show", name, "peers"), "").lines().map(String::strip).anyMatch(publicKey::equals);
        if (!known) throw new IOException("Refusing to add a peer through an endpoint change");
        runner.run(List.of(WG, "set", name, "peer", publicKey, "endpoint", endpoint), "");
        return status(id);
    }
    /**
     * Same contract as the Linux sync: removes revoked keys with their routes, adds new members,
     * and gives a published endpoint to kept peers that have none. The configuration file is
     * rewritten too, so a restarted tunnel service keeps the current membership.
     */
    private TunnelProtocol.Status sync(String id, TunnelProtocol.Configuration config) throws Exception {
        String name = running(id);
        if (!runner.run(List.of(WG, "show", name, "public-key"), "").strip().equals(config.identity().publicKey()))
            throw new IOException("Refusing to change a tunnel of another identity");
        var current = new HashMap<String, String>();
        for (String line : runner.run(List.of(WG, "show", name, "allowed-ips"), "").lines().filter(s -> !s.isBlank()).toList()) {
            String[] fields = line.strip().split("\\s+");
            WireGuardKeys.validatePublic(fields[0]);
            current.put(fields[0], fields.length == 2 && fields[1].endsWith("/32") ? fields[1].substring(0, fields[1].length() - 3) : "");
        }
        var endpoints = new HashMap<String, String>();
        for (var state : status(id).peers()) endpoints.put(state.publicKey(), state.endpoint());
        var desired = new LinkedHashMap<String, Api.Peer>();
        for (var peer : config.peers()) desired.put(peer.publicKey(), peer);
        for (var entry : current.entrySet()) {
            var wanted = desired.get(entry.getKey());
            if (wanted != null && wanted.address().equals(entry.getValue())) continue;
            // Route first: a key without a route carries no traffic even if its removal fails.
            if (!entry.getValue().isEmpty()) {
                try { route("delete", entry.getValue(), name); } catch (IOException ignored) { /* already absent */ }
            }
            runner.run(List.of(WG, "set", name, "peer", entry.getKey(), "remove"), "");
        }
        var added = config.peers().stream().filter(p -> !p.address().equals(current.get(p.publicKey()))).toList();
        if (!added.isEmpty()) RouteGuard.check(powershell(ROUTES), powershell(ADDRESSES), added.stream().map(Api.Peer::address).toList(), name);
        for (var peer : added) {
            var command = new ArrayList<>(List.of(WG, "set", name, "peer", peer.publicKey(), "allowed-ips", peer.address() + "/32"));
            String endpoint = Validation.endpoint(peer.endpoint());
            if (!endpoint.isEmpty()) command.addAll(List.of("endpoint", endpoint, "persistent-keepalive", "25"));
            runner.run(command, "");
            try {
                // The tunnel service may already have added the route itself; what matters is that it exists.
                try { route("add", peer.address(), name); } catch (IOException ignored) {}
                if (!hasRoute(powershell(ROUTES), peer.address(), name)) throw new IOException("Route to new member was not applied");
            } catch (Exception failure) { runner.run(List.of(WG, "set", name, "peer", peer.publicKey(), "remove"), ""); throw failure; }
        }
        for (var peer : config.peers()) {
            String endpoint = Validation.endpoint(peer.endpoint());
            if (current.containsKey(peer.publicKey()) && !endpoint.isEmpty() && endpoints.getOrDefault(peer.publicKey(), "").isEmpty())
                runner.run(List.of(WG, "set", name, "peer", peer.publicKey(), "endpoint", endpoint, "persistent-keepalive", "25"), "");
        }
        Path file = configuration(name), temporary = tunnels.resolve(name + ".conf.tmp");
        Files.deleteIfExists(temporary);
        Files.writeString(temporary, nativeConfig(config), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        return status(id);
    }
    public TunnelProtocol.Status status(String id) throws Exception {
        String name = tunnelName(id);
        if (!owned(name) || !serviceExists(name)) return new TunnelProtocol.Status("down", name, 0, 0, 0);
        return WireGuardStatus.parse("up", name, runner.run(List.of(WG, "show", name, "latest-handshakes"), ""),
                runner.run(List.of(WG, "show", name, "transfer"), ""), runner.run(List.of(WG, "show", name, "endpoints"), ""));
    }
    /** True if Samurai created this tunnel; a foreign tunnel service with the same name is never touched. */
    private boolean owned(String name) throws IOException {
        Path file = configuration(name);
        if (Files.isSymbolicLink(file)) throw new IOException("Refusing to change an interface not owned by this profile");
        if (Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) return true;
        if (serviceExists(name)) throw new IOException("Refusing to change an interface not owned by this profile");
        return false;
    }
    private String running(String id) throws IOException {
        String name = tunnelName(id);
        if (!owned(name) || !serviceExists(name)) throw new IOException("Refusing to change an interface that is not connected");
        return name;
    }
    /** Removal is asynchronous too; the configuration (our ownership marker) is deleted only once the service is gone. */
    private void uninstall(String name) throws Exception {
        runner.run(List.of(WIREGUARD, "/uninstalltunnelservice", name), "");
        await(() -> !serviceExists(name), "Tunnel service was not removed");
    }
    private interface Check { boolean done() throws Exception; }
    private static void await(Check check, String failure) throws Exception {
        for (int attempt = 0; attempt < 40; attempt++) {
            try { if (check.done()) return; } catch (Exception notYet) { /* retried */ }
            Thread.sleep(250);
        }
        throw new IOException(failure);
    }
    private boolean serviceExists(String name) {
        // sc query fails for a missing service; any other failure also counts as "not there" for status,
        // while up/down then fail on the WireGuard command itself.
        try { runner.run(List.of(SC, "query", "WireGuardTunnel$" + name), ""); return true; }
        catch (Exception e) { return false; }
    }
    private void route(String action, String address, String name) throws Exception {
        runner.run(List.of(NETSH, "interface", "ipv4", action, "route", "prefix=" + address + "/32", "interface=" + name, "store=active"), "");
    }
    static boolean hasRoute(String routesJson, String address, String name) throws IOException {
        JsonNode routes = Json.MAPPER.readTree(routesJson);
        if (!routes.isArray()) throw new IOException("Cannot inspect IPv4 routing");
        for (JsonNode route : routes) if (route.path("dst").asText().equals(address + "/32") && route.path("dev").asText().equals(name)) return true;
        return false;
    }
    private String powershell(String script) throws Exception {
        return runner.run(List.of(POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script), "");
    }
}
