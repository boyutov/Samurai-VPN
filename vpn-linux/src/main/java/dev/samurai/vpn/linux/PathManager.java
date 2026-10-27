package dev.samurai.vpn.linux;

import dev.samurai.vpn.core.Api;
import java.util.*;

/**
 * Hole punching for relayed peers. The relay reports each peer's public NAT mapping
 * (candidate); both sides point WireGuard at the other's candidate during the same
 * wall-clock slot and send small packets through the tunnel, so each NAT opens a mapping
 * towards the other. WireGuard roaming follows the last authenticated packet, so incoming
 * bytes while the endpoint is still the candidate prove the direct path. Otherwise the
 * peer returns to its relay endpoint and retries in a later aligned slot.
 * Symmetric NATs, which change the mapping per destination, stay on the relay.
 */
public final class PathManager {
    public interface Tunnel {
        TunnelProtocol.Status status() throws Exception;
        void endpoint(String publicKey, String endpoint) throws Exception;
        /** Sends a tiny datagram to the peer's overlay address so WireGuard transmits towards its endpoint. */
        void poke(String overlayAddress) throws Exception;
    }
    public enum Path { RELAY, TRYING, DIRECT, OTHER }
    // Attempts start in shared 30 s slots (clocks via NTP), so both sides punch together.
    // Both sides send PersistentKeepalive every 25 s, so a live direct path receives bytes at least that often.
    static final long SLOT_SECONDS = 30, ATTEMPT_SECONDS = 25, SILENT_SECONDS = 60;
    static final int MAX_BACKOFF_EXPONENT = 6;
    private final Tunnel tunnel;
    private final Map<String, Track> tracks = new HashMap<>();

    public PathManager(Tunnel tunnel) { this.tunnel = tunnel; }

    /** One control step (every few seconds); {@code now} is Unix time in seconds. Returns path per public key. */
    public Map<String, Path> tick(List<Api.Peer> peers, long now) throws Exception {
        var states = new HashMap<String, TunnelProtocol.PeerState>();
        for (var state : tunnel.status().peers()) states.put(state.publicKey(), state);
        var result = new LinkedHashMap<String, Path>();
        var present = new HashSet<String>();
        for (Api.Peer peer : peers) {
            var state = states.get(peer.publicKey());
            if (state == null) continue; // Not in the running tunnel yet; membership sync adds it.
            present.add(peer.publicKey());
            // The server offers a candidate only while it relays this pair.
            if (peer.candidate().isEmpty() || peer.endpoint().isEmpty()) { result.put(peer.publicKey(), Path.OTHER); continue; }
            Track track = tracks.computeIfAbsent(peer.publicKey(), key -> new Track());
            if (!peer.candidate().equals(track.candidate)) track.reset(peer.candidate());
            result.put(peer.publicKey(), step(track, peer, state, now));
        }
        tracks.keySet().retainAll(present);
        return result;
    }
    /** Returns managed peers to their relay endpoints; the relay keeps working without this manager. */
    public void restoreRelay(List<Api.Peer> peers) throws Exception {
        for (Api.Peer peer : peers) {
            Track track = tracks.get(peer.publicKey());
            if (track != null && track.path != Path.RELAY && !peer.endpoint().isEmpty()) tunnel.endpoint(peer.publicKey(), peer.endpoint());
        }
        tracks.clear();
    }
    private Path step(Track track, Api.Peer peer, TunnelProtocol.PeerState state, long now) throws Exception {
        boolean onDirect = state.endpoint().equals(track.candidate);
        switch (track.path) {
            case RELAY -> {
                long slot = now / SLOT_SECONDS;
                long period = 1L << Math.min(track.failures, MAX_BACKOFF_EXPONENT);
                if (slot != track.lastSlot && slot % period == 0) {
                    track.lastSlot = slot; track.path = Path.TRYING; track.since = now;
                    aim(track, peer, state);
                }
            }
            case TRYING -> {
                // Bytes counted between two observations that both saw the candidate came over the direct path:
                // any relayed packet in between would have made WireGuard roam back to the relay endpoint.
                if (onDirect && track.received >= 0 && state.receivedBytes() > track.received) track.direct(state, now);
                else if (now - track.since >= ATTEMPT_SECONDS) fallBack(track, peer, state);
                // Roaming moved us back to the relay because the other side was not punching yet.
                else if (!onDirect) aim(track, peer, state);
                else { if (track.received < 0) track.received = state.receivedBytes(); tunnel.poke(peer.address()); }
            }
            case DIRECT -> {
                if (state.receivedBytes() != track.received) { track.received = state.receivedBytes(); track.heard = now; }
                if (!onDirect || now - track.heard >= SILENT_SECONDS) fallBack(track, peer, state);
            }
            case OTHER -> track.path = Path.RELAY;
        }
        return track.path;
    }
    private void aim(Track track, Api.Peer peer, TunnelProtocol.PeerState state) throws Exception {
        if (!state.endpoint().equals(track.candidate)) tunnel.endpoint(peer.publicKey(), track.candidate);
        track.received = -1; // baseline is taken on the next observation, after the switch took effect
        tunnel.poke(peer.address());
    }
    private void fallBack(Track track, Api.Peer peer, TunnelProtocol.PeerState state) throws Exception {
        if (!state.endpoint().equals(peer.endpoint())) tunnel.endpoint(peer.publicKey(), peer.endpoint());
        track.failures++;
        track.path = Path.RELAY;
    }
    private static final class Track {
        Path path = Path.RELAY;
        String candidate;
        long since, received, heard, lastSlot = -1;
        int failures;
        void reset(String candidate) { this.candidate = candidate; path = Path.RELAY; lastSlot = -1; failures = 0; }
        void direct(TunnelProtocol.PeerState state, long now) { path = Path.DIRECT; failures = 0; received = state.receivedBytes(); heard = now; }
    }
}
