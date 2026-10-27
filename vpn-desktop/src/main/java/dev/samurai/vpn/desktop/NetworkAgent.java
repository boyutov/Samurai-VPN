package dev.samurai.vpn.desktop;

import dev.samurai.vpn.core.Api;
import dev.samurai.vpn.linux.*;
import java.util.*;
import java.util.concurrent.Callable;

/**
 * Keeps one connected network current: applies membership changes to the running tunnel and
 * moves relayed peers to direct paths when NATs allow it. Runs in the background agent, never
 * in the privileged service: it holds the user's server token and parses server responses.
 */
final class NetworkAgent {
    /** What the window shows; contains no keys or tokens. */
    record Snapshot(boolean up, List<Api.Peer> peers, Map<String, PathManager.Path> paths, long membershipChanged) {}
    static final long MEMBERSHIP_SECONDS = 30;
    private final String networkId, self, address;
    private final dev.samurai.vpn.core.WireGuardKeys.Identity identity;
    private final TunnelBackend tunnel;
    private final Callable<List<Api.Peer>> members;
    private final PathManager manager;
    private List<Api.Peer> everyone = List.of(), others = List.of();
    private long fetched = Long.MIN_VALUE / 2, changed;

    NetworkAgent(DesktopService.Profile profile, TunnelBackend tunnel, Callable<List<Api.Peer>> members, PathManager.Tunnel paths) {
        var membership = profile.session().membership();
        this.networkId = membership.networkId(); this.self = membership.peerId(); this.address = membership.address();
        this.identity = profile.session().identity(); this.tunnel = tunnel; this.members = members;
        this.manager = new PathManager(paths);
    }
    /** The production wiring: the OS tunnel service and the coordination server of the profile. */
    static NetworkAgent of(DesktopService service, DesktopService.Profile profile, boolean dev) {
        var tunnel = NativeTunnel.client();
        String id = profile.session().membership().networkId();
        return new NetworkAgent(profile, tunnel, () -> service.refresh(profile, dev).peers(), new PathManager.Tunnel() {
            public TunnelProtocol.Status status() throws Exception { return tunnel.execute(new TunnelProtocol.Request("status", id, null)); }
            public void endpoint(String key, String endpoint) throws Exception { tunnel.execute(new TunnelProtocol.Request("endpoint", id, null, key, endpoint)); }
            public void poke(String overlay) throws Exception {
                // Discard port: the content is irrelevant, the encrypted WireGuard packet opens the NAT.
                try (var socket = new java.net.DatagramSocket()) {
                    socket.send(new java.net.DatagramPacket(new byte[1], 1, java.net.InetAddress.getByName(overlay), 9));
                }
            }
        });
    }
    String networkId() { return networkId; }

    /** One step, every few seconds; {@code now} is Unix time in seconds. */
    Snapshot tick(long now) throws Exception {
        if (!tunnel.execute(new TunnelProtocol.Request("status", networkId, null)).state().equals("up")) {
            fetched = Long.MIN_VALUE / 2; // fetch again as soon as the tunnel is back
            return new Snapshot(false, everyone, Map.of(), changed);
        }
        // Membership and candidates change rarely; the tunnel itself is polled every tick.
        if (now - fetched >= MEMBERSHIP_SECONDS) {
            everyone = List.copyOf(members.call()); fetched = now;
            others = everyone.stream().filter(p -> !p.peerId().equals(self)).toList();
            if (sync()) changed = now;
        }
        return new Snapshot(true, everyone, Map.copyOf(manager.tick(others, now)), changed);
    }
    /** Applies added and revoked members to the running tunnel; returns whether anything changed. */
    private boolean sync() throws Exception {
        var running = new HashSet<String>();
        for (var state : tunnel.execute(new TunnelProtocol.Request("status", networkId, null)).peers()) running.add(state.publicKey());
        var wanted = new HashSet<String>();
        for (var peer : others) wanted.add(peer.publicKey());
        if (running.equals(wanted)) return false;
        // The listen port is not changed by sync; any valid value satisfies validation.
        tunnel.execute(new TunnelProtocol.Request("sync", networkId, new TunnelProtocol.Configuration(address, 51820, identity, others)));
        return true;
    }
    /** Returns direct peers to the relay, so the tunnel keeps working without this agent. */
    void restoreRelay() {
        try { manager.restoreRelay(others); } catch (Exception ignored) { /* tunnel already down */ }
    }
}
