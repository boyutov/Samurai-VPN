package dev.samurai.vpn.linux;

import dev.samurai.vpn.core.*;
import java.util.List;

public final class TunnelProtocol {
    private TunnelProtocol() {}
    public record Configuration(String address, int listenPort, WireGuardKeys.Identity identity, List<Api.Peer> peers) {
        public Configuration { if (peers != null) peers = List.copyOf(peers); }
        @Override public String toString() { return "Configuration[private key redacted]"; }
    }
    /** peerPublicKey and endpoint are used only by the "endpoint" operation. */
    public record Request(String operation, String networkId, Configuration configuration, String peerPublicKey, String endpoint) {
        public Request(String operation, String networkId, Configuration configuration) { this(operation, networkId, configuration, null, null); }
        @Override public String toString() { return "Request[" + operation + ", credentials redacted]"; }
    }
    /** Per-peer WireGuard state; endpoint is empty until the peer has one. */
    public record PeerState(String publicKey, String endpoint, long latestHandshake, long receivedBytes) {}
    public record Status(String state, String interfaceName, long latestHandshake, long receivedBytes, long sentBytes, List<PeerState> peers) {
        public Status { peers = peers == null ? List.of() : List.copyOf(peers); }
        public Status(String state, String interfaceName, long latestHandshake, long receivedBytes, long sentBytes) {
            this(state, interfaceName, latestHandshake, receivedBytes, sentBytes, List.of());
        }
    }
    public record Response(boolean success, Status status, String message) {}

    public static void validate(Request request) {
        if (request == null) throw new IllegalArgumentException("Request required");
        Validation.id(request.networkId());
        if (!List.of("up", "down", "status", "endpoint", "sync").contains(request.operation())) throw new IllegalArgumentException("Unsupported operation");
        if (request.operation().equals("endpoint")) {
            // Only moves an already configured peer between its relay and direct address.
            if (request.configuration() != null) throw new IllegalArgumentException("Configuration not accepted for this operation");
            WireGuardKeys.validatePublic(request.peerPublicKey());
            if (Validation.endpoint(request.endpoint()).isEmpty() || request.endpoint().startsWith("10.203."))
                throw new IllegalArgumentException("Endpoint must be a reachable unicast IPv4:port");
            return;
        }
        if (request.peerPublicKey() != null || request.endpoint() != null) throw new IllegalArgumentException("Field not accepted for this operation");
        if (!request.operation().equals("up") && !request.operation().equals("sync")) {
            if (request.configuration() != null) throw new IllegalArgumentException("Configuration not accepted for this operation");
            return;
        }
        Configuration config = request.configuration();
        if (config == null || config.peers() == null) throw new IllegalArgumentException("Peer list required");
        // A running network may lose all other members; a new tunnel needs at least one.
        if (request.operation().equals("up") && config.peers().isEmpty()) throw new IllegalArgumentException("At least one peer required");
        WireGuardConfig.render(config.identity(), config.address(), config.listenPort(), config.peers());
        for (var peer : config.peers()) {
            Validation.id(peer.peerId()); Validation.name(peer.name());
            if (peer.endpoint() != null && peer.endpoint().startsWith("10.203."))
                throw new IllegalArgumentException("Endpoint cannot use the overlay address pool");
        }
    }
    public static String nativeConfig(Configuration config) {
        // wg setconf accepts WireGuard settings only; addresses/routes are applied separately.
        return WireGuardConfig.render(config.identity(), config.address(), config.listenPort(), config.peers())
                .replace("Address = " + config.address() + "/32\n", "");
    }
}
