package dev.samurai.vpn.linux;

import dev.samurai.vpn.core.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static dev.samurai.vpn.linux.PathManager.Path.*;
import static org.junit.jupiter.api.Assertions.*;

class PathManagerTest {
    private static final String RELAY_EP = "203.0.113.10:40001", DIRECT_EP = "198.51.100.20:61000";
    private static final long T = 3000; // start of 30 s slot 100
    private final String key = WireGuardKeys.generate().publicKey();
    private final FakeTunnel tunnel = new FakeTunnel();
    private final PathManager manager = new PathManager(tunnel);
    private List<Api.Peer> peers(String candidate) {
        return List.of(new Api.Peer(UUID.randomUUID().toString(), "Friend", key, "10.203.1.2", RELAY_EP, candidate));
    }
    private PathManager.Path tick(long now) throws Exception { return manager.tick(peers(DIRECT_EP), now).get(key); }

    @Test void successfulPunchNeedsBytesAfterTheSwitchAndStaysDirect() throws Exception {
        tunnel.endpoint = RELAY_EP; tunnel.received = 500;
        assertEquals(TRYING, tick(T));
        assertEquals(DIRECT_EP, tunnel.endpoint);
        assertEquals(List.of("10.203.1.2"), tunnel.pokes);
        tunnel.received = 532; // may have arrived before the switch: only sets the baseline
        assertEquals(TRYING, tick(T + 5));
        tunnel.received = 564; // arrived while the endpoint stayed direct
        assertEquals(DIRECT, tick(T + 10));
        for (long t = T + 35; t < T + 400; t += 25) { tunnel.received += 32; assertEquals(DIRECT, tick(t)); }
    }
    @Test void relayedPacketDuringAttemptIsNotMistakenForSuccess() throws Exception {
        tunnel.endpoint = RELAY_EP;
        tick(T);
        tunnel.endpoint = RELAY_EP; tunnel.received += 32; // other side not punching yet; WireGuard roamed back
        assertEquals(TRYING, tick(T + 5));
        assertEquals(DIRECT_EP, tunnel.endpoint, "re-aimed at the candidate");
        assertEquals(TRYING, tick(T + 10));
        tunnel.received += 32;
        assertEquals(DIRECT, tick(T + 15));
    }
    @Test void failedPunchRetriesInAlignedSlotsWithBackoff() throws Exception {
        tunnel.endpoint = RELAY_EP;
        tick(T);
        for (long t = T + 5; t < T + 25; t += 5) assertEquals(TRYING, tick(t));
        assertEquals(RELAY, tick(T + 25));
        assertEquals(RELAY_EP, tunnel.endpoint);
        assertEquals(RELAY, tick(T + 29), "no second attempt in the same slot");
        assertEquals(RELAY, tick(T + 30), "slot 101 skipped: period 2");
        assertEquals(TRYING, tick(T + 60));
        assertEquals(RELAY, tick(T + 85));
        assertEquals(RELAY, tick(T + 90), "slot 103 skipped: period 4");
        assertEquals(TRYING, tick(T + 120));
    }
    @Test void directPathFallsBackWhenSilentOrRoamedAway() throws Exception {
        tunnel.endpoint = RELAY_EP;
        tick(T); tick(T + 5); tunnel.received += 32;
        assertEquals(DIRECT, tick(T + 10));
        assertEquals(DIRECT, tick(T + 60));
        assertEquals(RELAY, tick(T + 70), "no bytes for 60 s");
        assertEquals(RELAY_EP, tunnel.endpoint);

        assertEquals(TRYING, tick(T + 120)); tick(T + 125); tunnel.received += 32;
        assertEquals(DIRECT, tick(T + 130));
        tunnel.endpoint = RELAY_EP; // the other side gave up and sends through the relay
        assertEquals(RELAY, tick(T + 135));
    }
    @Test void peersWithoutCandidateOrOutsideTunnelAreLeftAlone() throws Exception {
        tunnel.endpoint = RELAY_EP;
        assertEquals(OTHER, manager.tick(peers(""), T).get(key));
        assertTrue(manager.tick(List.of(new Api.Peer(UUID.randomUUID().toString(), "New", WireGuardKeys.generate().publicKey(), "10.203.1.3", RELAY_EP, DIRECT_EP)), T).isEmpty());
        assertEquals(0, tunnel.changes);
        assertTrue(tunnel.pokes.isEmpty());
    }
    @Test void restoreReturnsDirectPeersToRelay() throws Exception {
        tunnel.endpoint = RELAY_EP;
        tick(T); tick(T + 5); tunnel.received += 32; tick(T + 10);
        assertEquals(DIRECT_EP, tunnel.endpoint);
        manager.restoreRelay(peers(DIRECT_EP));
        assertEquals(RELAY_EP, tunnel.endpoint);
    }
    @Test void newCandidateRestartsWithoutBackoff() throws Exception {
        tunnel.endpoint = RELAY_EP;
        tick(T); tick(T + 25);
        assertEquals(TRYING, manager.tick(peers("198.51.100.20:62000"), T + 30).get(key));
        assertEquals("198.51.100.20:62000", tunnel.endpoint);
    }
    private final class FakeTunnel implements PathManager.Tunnel {
        String endpoint = ""; long received; int changes;
        final List<String> pokes = new ArrayList<>();
        public TunnelProtocol.Status status() {
            return new TunnelProtocol.Status("up", "smtest", 0, received, 0, List.of(new TunnelProtocol.PeerState(key, endpoint, 0, received)));
        }
        public void endpoint(String publicKey, String value) { assertEquals(key, publicKey); endpoint = value; changes++; }
        public void poke(String address) { pokes.add(address); }
    }
}
