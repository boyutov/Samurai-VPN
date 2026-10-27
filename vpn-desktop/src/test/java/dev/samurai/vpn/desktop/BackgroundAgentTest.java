package dev.samurai.vpn.desktop;

import dev.samurai.vpn.client.Credentials;
import dev.samurai.vpn.core.*;
import dev.samurai.vpn.linux.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** The agent's logic with a fake tunnel service and a fake membership list; no network, no root. */
class BackgroundAgentTest {
    @TempDir Path data;
    private final WireGuardKeys.Identity own = WireGuardKeys.generate();
    private final String network = UUID.randomUUID().toString(), self = UUID.randomUUID().toString();
    private final Api.Peer me = peer(self, own.publicKey(), "10.203.1.1"),
            friend = peer(UUID.randomUUID().toString(), WireGuardKeys.generate().publicKey(), "10.203.1.2"),
            newcomer = peer(UUID.randomUUID().toString(), WireGuardKeys.generate().publicKey(), "10.203.1.3");
    private final Fake tunnel = new Fake();
    private List<Api.Peer> server = List.of(me, friend);
    private final AtomicInteger fetches = new AtomicInteger();

    private static Api.Peer peer(String id, String key, String address) { return new Api.Peer(id, "Device", key, address, "", ""); }
    private DesktopService.Profile profile(String folder) {
        var session = new Credentials.Session("https://vpn.example", own, new Api.Joined(network, self, "10.203.1.1", Tokens.generate()));
        return new DesktopService.Profile(data.resolve(folder), session, false);
    }
    private NetworkAgent agent(DesktopService.Profile profile) {
        return new NetworkAgent(profile, tunnel, () -> { fetches.incrementAndGet(); return server; }, new PathManager.Tunnel() {
            public TunnelProtocol.Status status() { return tunnel.status(); }
            public void endpoint(String key, String endpoint) {}
            public void poke(String address) {}
        });
    }

    @Test void membershipChangesReachTheRunningTunnel() throws Exception {
        var agent = agent(profile("p"));
        tunnel.up = true; tunnel.peers.add(friend.publicKey());
        var first = agent.tick(1000);
        assertTrue(first.up());
        assertEquals(2, first.peers().size());
        assertEquals(0, tunnel.syncs, "nothing to change");

        server = List.of(me, newcomer); // friend revoked, newcomer joined
        agent.tick(1010);
        assertEquals(1, fetches.get(), "membership is fetched every 30 s, not every tick");
        var changed = agent.tick(1030);
        assertEquals(1, tunnel.syncs);
        assertEquals(Set.of(newcomer.publicKey()), tunnel.peers, "sync applied without reconnecting");
        assertEquals(1030, changed.membershipChanged());
        assertFalse(tunnel.lastSync.contains(own.publicKey()), "own key is not a peer");

        tunnel.up = false;
        assertFalse(agent.tick(1040).up());
        tunnel.up = true;
        agent.tick(1045);
        assertEquals(3, fetches.get(), "fetched again right after the tunnel came back");
    }
    @Test void registryStatusAndIdleExit() throws Exception {
        var files = new AgentFiles(data);
        var one = profile("one"); Files.createDirectory(one.directory());
        assertEquals(1, files.update(one, true, true));
        assertEquals(1, files.update(one, true, true), "registering twice keeps one entry");
        assertEquals(List.of(new AgentFiles.Entry(one.directory().toString(), true)), files.profiles());

        var created = new AtomicInteger();
        var background = new BackgroundAgent(files, entry -> { created.incrementAndGet(); return agent(one); }, 1000);
        tunnel.up = true; tunnel.peers.add(friend.publicKey());
        assertTrue(background.tick(1000));
        var shown = files.network(one).orElseThrow();
        assertTrue(shown.up());
        assertEquals(2, shown.peers().size());
        assertTrue(shown.error().isEmpty());
        assertFalse(Files.readString(files.folder().resolve("status.json")).contains(own.privateKey()), "no keys in shared files");
        background.tick(1005);
        assertEquals(1, created.get(), "one agent per profile");

        tunnel.up = false;
        assertTrue(background.tick(1080), "a tunnel may still be starting");
        assertFalse(background.tick(1095), "nothing up for 90 s: exit");

        assertEquals(0, files.update(one, true, false));
        assertFalse(new BackgroundAgent(files, entry -> agent(one), 2000).tick(2000), "nothing registered: exit");
        assertTrue(files.network(one).isEmpty(), "disconnected profile leaves the status");
    }
    @Test void unreachableServerIsReportedAndRetried() throws Exception {
        var files = new AgentFiles(data);
        var one = profile("one");
        files.update(one, false, true);
        var attempts = new AtomicInteger();
        var background = new BackgroundAgent(files, entry -> {
            if (attempts.incrementAndGet() == 1) throw new java.io.IOException("server unreachable");
            return agent(one);
        }, 1000);
        tunnel.up = true;
        assertTrue(background.tick(1000));
        assertEquals("server unreachable", files.network(one).orElseThrow().error());
        background.tick(1005);
        assertTrue(files.network(one).orElseThrow().up());
    }
    @Test void secondAgentForTheSameDataExitsAtOnce() throws Exception {
        var files = new AgentFiles(data);
        try (var held = files.agentLock()) {
            assertNotNull(held);
            assertEquals(0, BackgroundAgent.run(data), "another agent serves this data directory");
        }
    }

    /** Models the service: up/down and the peer keys of the running tunnel. */
    private final class Fake implements TunnelBackend {
        boolean up;
        int syncs;
        String lastSync = "";
        final Set<String> peers = new HashSet<>();
        TunnelProtocol.Status status() {
            if (!up) return new TunnelProtocol.Status("down", "smtest", 0, 0, 0);
            var states = peers.stream().map(key -> new TunnelProtocol.PeerState(key, "", 0, 0)).toList();
            return new TunnelProtocol.Status("up", "smtest", 0, 0, 0, states);
        }
        public TunnelProtocol.Status execute(TunnelProtocol.Request request) throws Exception {
            assertEquals(network, request.networkId());
            if (request.operation().equals("sync")) {
                syncs++; peers.clear();
                for (var peer : request.configuration().peers()) peers.add(peer.publicKey());
                lastSync = Json.MAPPER.writeValueAsString(request.configuration().peers());
            }
            return status();
        }
    }
}
