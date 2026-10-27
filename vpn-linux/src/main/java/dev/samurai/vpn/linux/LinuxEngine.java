package dev.samurai.vpn.linux;

import com.fasterxml.jackson.databind.JsonNode;
import dev.samurai.vpn.core.*;
import java.io.IOException;
import java.util.*;

/** The privileged surface: one owned WireGuard interface, /32 routes, no shell or DNS changes. */
public final class LinuxEngine {
    private static final String IP = "/usr/sbin/ip", WG = "/usr/bin/wg";
    private final CommandRunner runner;
    private final long uid;
    public LinuxEngine(CommandRunner runner, long uid) {
        if (uid < 0 || uid > 0xFFFF_FFFFL) throw new IllegalArgumentException("Invalid caller UID");
        this.runner = runner; this.uid = uid;
    }
    public String interfaceName(String networkId) {
        Validation.id(networkId);
        try {
            return "sm" + java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest((uid + ":" + networkId).getBytes(java.nio.charset.StandardCharsets.US_ASCII))).substring(0, 12);
        } catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
    private String marker(String id) { return "samurai-vpn:" + uid + ":" + id; }
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
        String name = interfaceName(id);
        if (link(name) != null) throw new IOException("Interface already exists; disconnect it first");
        RouteGuard.check(ip("-j", "-4", "route", "show", "table", "all"), ip("-j", "-4", "address", "show"), config);
        boolean attempted = false;
        int createdIndex = -1;
        try {
            attempted = true;
            ip("link", "add", "dev", name, "type", "wireguard");
            JsonNode created = link(name);
            if (created == null || !"wireguard".equals(created.path("linkinfo").path("info_kind").asText()))
                throw new IOException("Created interface cannot be verified");
            createdIndex = created.path("ifindex").asInt(-1);
            if (createdIndex <= 0) throw new IOException("Created interface index missing");
            // ip link add does not reliably apply IFLA_IFALIAS for WireGuard.
            ip("link", "set", "dev", name, "alias", marker(id));
            runner.run(List.of(WG, "setconf", name, "/dev/stdin"), TunnelProtocol.nativeConfig(config));
            ip("address", "add", config.address() + "/32", "dev", name);
            // Conservative fixed MTU until path-MTU detection is implemented.
            ip("link", "set", "dev", name, "mtu", "1280", "up");
            for (var peer : config.peers()) ip("-4", "route", "add", peer.address() + "/32", "dev", name, "proto", "static");
            return status(id);
        } catch (Exception failure) {
            if (attempted) {
                try {
                    JsonNode existing = link(name);
                    if (existing != null) {
                        boolean justCreated = createdIndex > 0 && existing.path("ifindex").asInt(-1) == createdIndex
                                && existing.path("ifalias").asText("").isEmpty()
                                && "wireguard".equals(existing.path("linkinfo").path("info_kind").asText());
                        if (!justCreated) owned(existing, id);
                        ip("link", "delete", "dev", name);
                    }
                } catch (Exception cleanup) {
                    var failureWithCleanup = new IOException("Tunnel setup failed; cleanup could not be confirmed for " + name, failure);
                    failureWithCleanup.addSuppressed(cleanup); throw failureWithCleanup;
                }
            }
            throw failure;
        }
    }
    private TunnelProtocol.Status down(String id) throws Exception {
        String name = interfaceName(id); JsonNode existing = link(name);
        if (existing != null) { owned(existing, id); ip("link", "delete", "dev", name); }
        return new TunnelProtocol.Status("down", name, 0, 0, 0);
    }
    private TunnelProtocol.Status endpoint(String id, String publicKey, String endpoint) throws Exception {
        String name = interfaceName(id); JsonNode existing = link(name);
        if (existing == null) throw new IOException("Refusing to change an interface that is not connected");
        owned(existing, id);
        // "wg set peer" would silently add an unknown key, so only already configured peers are accepted.
        boolean known = runner.run(List.of(WG, "show", name, "peers"), "").lines().map(String::strip).anyMatch(publicKey::equals);
        if (!known) throw new IOException("Refusing to add a peer through an endpoint change");
        runner.run(List.of(WG, "set", name, "peer", publicKey, "endpoint", endpoint), "");
        return status(id);
    }
    /**
     * Brings a running tunnel to the current membership without reconnecting: removes revoked
     * keys with their routes and adds new members. Endpoints of kept peers are left to roaming
     * and PathManager, except that a peer which had none receives the published one.
     */
    private TunnelProtocol.Status sync(String id, TunnelProtocol.Configuration config) throws Exception {
        String name = interfaceName(id); JsonNode existing = link(name);
        if (existing == null) throw new IOException("Refusing to change an interface that is not connected");
        owned(existing, id);
        if (!runner.run(List.of(WG, "show", name, "public-key"), "").strip().equals(config.identity().publicKey()))
            throw new IOException("Refusing to change a tunnel of another identity");
        var current = new HashMap<String, String>();
        for (String line : runner.run(List.of(WG, "show", name, "allowed-ips"), "").lines().filter(s -> !s.isBlank()).toList()) {
            String[] fields = line.split("\\s+");
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
                try { ip("-4", "route", "del", entry.getValue() + "/32", "dev", name); } catch (IOException ignored) { /* already absent */ }
            }
            runner.run(List.of(WG, "set", name, "peer", entry.getKey(), "remove"), "");
        }
        var added = config.peers().stream().filter(p -> !p.address().equals(current.get(p.publicKey()))).toList();
        if (!added.isEmpty()) RouteGuard.check(ip("-j", "-4", "route", "show", "table", "all"), ip("-j", "-4", "address", "show"),
                added.stream().map(Api.Peer::address).toList(), name);
        for (var peer : added) {
            var command = new ArrayList<>(List.of(WG, "set", name, "peer", peer.publicKey(), "allowed-ips", peer.address() + "/32"));
            String endpoint = Validation.endpoint(peer.endpoint());
            if (!endpoint.isEmpty()) command.addAll(List.of("endpoint", endpoint, "persistent-keepalive", "25"));
            runner.run(command, "");
            try { ip("-4", "route", "add", peer.address() + "/32", "dev", name, "proto", "static"); }
            catch (Exception failure) { runner.run(List.of(WG, "set", name, "peer", peer.publicKey(), "remove"), ""); throw failure; }
        }
        for (var peer : config.peers()) {
            String endpoint = Validation.endpoint(peer.endpoint());
            if (current.containsKey(peer.publicKey()) && !endpoint.isEmpty() && endpoints.getOrDefault(peer.publicKey(), "").isEmpty())
                runner.run(List.of(WG, "set", name, "peer", peer.publicKey(), "endpoint", endpoint, "persistent-keepalive", "25"), "");
        }
        return status(id);
    }
    public TunnelProtocol.Status status(String id) throws Exception {
        String name = interfaceName(id); JsonNode existing = link(name);
        if (existing == null) return new TunnelProtocol.Status("down", name, 0, 0, 0);
        owned(existing, id);
        boolean up = false; for (JsonNode flag : existing.path("flags")) if (flag.asText().equals("UP")) up = true;
        return WireGuardStatus.parse(up ? "up" : "down", name, runner.run(List.of(WG, "show", name, "latest-handshakes"), ""),
                runner.run(List.of(WG, "show", name, "transfer"), ""), runner.run(List.of(WG, "show", name, "endpoints"), ""));
    }
    private JsonNode link(String name) throws Exception {
        JsonNode links = Json.MAPPER.readTree(ip("-j", "-d", "link", "show"));
        if (!links.isArray()) throw new IOException("Cannot inspect interfaces");
        for (JsonNode link : links) if (name.equals(link.path("ifname").asText())) return link;
        return null;
    }
    private void owned(JsonNode link, String id) throws IOException {
        if (!marker(id).equals(link.path("ifalias").asText()) || !"wireguard".equals(link.path("linkinfo").path("info_kind").asText()))
            throw new IOException("Refusing to change an interface not owned by this profile");
    }
    private String ip(String... args) throws Exception {
        var command = new ArrayList<String>(); command.add(IP); command.addAll(List.of(args)); return runner.run(command, "");
    }
}
