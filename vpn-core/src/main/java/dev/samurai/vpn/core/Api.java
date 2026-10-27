package dev.samurai.vpn.core;

import java.util.List;

/** Versioned wire DTOs. No private WireGuard keys are accepted by the server. */
public final class Api {
    private Api() {}
    public record CreateNetwork(String name) {}
    public record NetworkCreated(String networkId, String name, String ownerToken) {
        @Override public String toString() { return "NetworkCreated[credentials redacted]"; }
    }
    public record InviteCreated(String networkId, String inviteToken, String expiresAt) {
        @Override public String toString() { return "InviteCreated[credentials redacted]"; }
    }
    public record Join(String name, String publicKey, String endpoint) {}
    public record Joined(String networkId, String peerId, String address, String peerToken) {
        @Override public String toString() { return "Joined[credentials redacted]"; }
    }
    /** endpoint: what WireGuard should use now; candidate: the peer's observed public address for a direct attempt. */
    public record Peer(String peerId, String name, String publicKey, String address, String endpoint, String candidate) {
        public Peer { if (candidate == null) candidate = ""; }
        public Peer(String peerId, String name, String publicKey, String address, String endpoint) { this(peerId, name, publicKey, address, endpoint, ""); }
    }
    public record Peers(String networkId, List<Peer> peers) {}
    public record Error(String code, String message) {}
}
