package dev.samurai.vpn.server;

import dev.samurai.vpn.core.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.net.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class StateStoreTest {
    private final String admin = Tokens.generate();
    @TempDir Path temp;
    private Path file() { return temp.resolve("state").resolve("server.json"); }
    private NetworkRegistry open(StateStore store) throws IOException { return new NetworkRegistry(admin, Clock.systemUTC(), null, store); }
    private static Api.Join request(String endpoint) { return new Api.Join("Device", WireGuardKeys.generate().publicKey(), endpoint); }

    @Test void membershipsInvitesAndRevocationsSurviveRestart() throws Exception {
        Api.NetworkCreated network; Api.Joined kept, revoked; Api.InviteCreated pending;
        try (var store = new StateStore(file())) {
            var registry = open(store);
            network = registry.create(admin, "Friends");
            kept = registry.join(network.networkId(), registry.invite(network.networkId(), network.ownerToken()).inviteToken(), request("192.0.2.1:51820"));
            revoked = registry.join(network.networkId(), registry.invite(network.networkId(), network.ownerToken()).inviteToken(), request(""));
            registry.revoke(network.networkId(), network.ownerToken(), revoked.peerId());
            pending = registry.invite(network.networkId(), network.ownerToken());
        }
        try (var store = new StateStore(file())) {
            var registry = open(store);
            assertTrue(registry.persistent());
            var peers = registry.peers(network.networkId(), kept.peerToken()).peers();
            assertEquals(List.of(kept.peerId()), peers.stream().map(Api.Peer::peerId).toList());
            assertEquals("192.0.2.1:51820", peers.getFirst().endpoint());
            assertThrows(ApiException.class, () -> registry.peers(network.networkId(), revoked.peerToken()), "revocation is durable");
            var joined = registry.join(network.networkId(), pending.inviteToken(), request(""));
            assertNotEquals(revoked.address(), joined.address(), "addresses are not reused after restart");
            assertThrows(ApiException.class, () -> registry.join(network.networkId(), pending.inviteToken(), request("")), "invite stays single-use");
            assertNotEquals(registry.create(admin, "Second").networkId(), network.networkId());
        }
    }
    @Test void fileIsPrivateAndContainsNoCredentials() throws Exception {
        Api.NetworkCreated network; Api.InviteCreated invite; Api.Joined member;
        try (var store = new StateStore(file())) {
            var registry = open(store);
            network = registry.create(admin, "Friends");
            member = registry.join(network.networkId(), registry.invite(network.networkId(), network.ownerToken()).inviteToken(), request(""));
            invite = registry.invite(network.networkId(), network.ownerToken());
        }
        String text = Files.readString(file());
        for (String secret : List.of(admin, network.ownerToken(), invite.inviteToken(), member.peerToken())) assertFalse(text.contains(secret));
        if (Files.getFileStore(file()).supportsFileAttributeView("posix"))
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file())));
        assertFalse(Files.exists(file().resolveSibling("server.json.tmp")));
    }
    @Test void failedSaveLeavesMemoryAndDiskUnchanged() throws Exception {
        Api.NetworkCreated network;
        try (var store = new FailingStore(file())) {
            var registry = open(store);
            network = registry.create(admin, "Friends");
            store.fail = true;
            var error = assertThrows(ApiException.class, () -> registry.invite(network.networkId(), network.ownerToken()));
            assertEquals(503, error.status());
            assertThrows(ApiException.class, () -> registry.create(admin, "Lost"));
            store.fail = false;
            var second = registry.create(admin, "Second");
            var invite = registry.invite(second.networkId(), second.ownerToken());
            assertEquals("10.203.2.1", registry.join(second.networkId(), invite.inviteToken(), request("")).address(), "rolled-back network freed its subnet");
        }
        try (var store = new StateStore(file())) {
            var registry = open(store);
            assertTrue(registry.peers(network.networkId(), network.ownerToken()).peers().isEmpty());
        }
    }
    @Test void secondServerAndInvalidFilesAreRefused() throws Exception {
        try (var store = new StateStore(file())) {
            open(store).create(admin, "Friends");
            assertThrows(IOException.class, () -> new StateStore(file()), "state is locked");
        }
        String valid = Files.readString(file());
        for (String broken : List.of(valid.replace("\"version\":1", "\"version\":2"), valid.replace("\"subnet\":1", "\"subnet\":7"),
                valid.substring(0, valid.length() / 2), valid.replace("\"name\":\"Friends\"", "\"name\":\"Friends\",\"extra\":1"))) {
            Files.writeString(file(), broken);
            try (var store = new StateStore(file())) { assertThrows(IOException.class, () -> open(store), broken); }
        }
        if (Files.getFileStore(file()).supportsFileAttributeView("posix")) {
            Files.writeString(file(), valid);
            Files.setPosixFilePermissions(file(), PosixFilePermissions.fromString("rw-r--r--"));
            try (var store = new StateStore(file())) { assertThrows(IOException.class, () -> open(store), "world-readable state"); }
        }
    }
    @Test void relayPortsSurviveRestart() throws Exception {
        int first = RelayTest.freeRange(6);
        Api.NetworkCreated network; Api.Joined a, b; String aToB, bToA;
        try (var store = new StateStore(file()); var relay = new Relay(InetAddress.getLoopbackAddress(), "127.0.0.1", first, 6)) {
            var registry = new NetworkRegistry(admin, Clock.systemUTC(), relay, store);
            network = registry.create(admin, "Friends");
            // C's sync takes the four lowest ports, so the pair A–B does not start at the first port by accident.
            var c = join(registry, network); a = join(registry, network); b = join(registry, network);
            endpoint(registry, network, c, a);
            aToB = endpoint(registry, network, a, b); bToA = endpoint(registry, network, b, a);
            registry.revoke(network.networkId(), network.ownerToken(), c.peerId());
        }
        try (var store = new StateStore(file()); var relay = new Relay(InetAddress.getLoopbackAddress(), "127.0.0.1", first, 6)) {
            var registry = new NetworkRegistry(admin, Clock.systemUTC(), relay, store);
            assertEquals(2, relay.allocatedPorts(), "the revoked member's pair is not restored");
            assertEquals(aToB, endpoint(registry, network, a, b));
            assertEquals(bToA, endpoint(registry, network, b, a));
        }
        try (var store = new StateStore(file()); var relay = new Relay(InetAddress.getLoopbackAddress(), "127.0.0.1", first, 2)) {
            var registry = new NetworkRegistry(admin, Clock.systemUTC(), relay, store);
            assertEquals(0, relay.allocatedPorts());
            String moved = endpoint(registry, network, a, b);
            assertTrue(moved.startsWith("127.0.0.1:") && !moved.equals(aToB), "pairs outside a changed range are allocated anew");
        }
    }
    private static Api.Joined join(NetworkRegistry registry, Api.NetworkCreated network) {
        return registry.join(network.networkId(), registry.invite(network.networkId(), network.ownerToken()).inviteToken(), request(""));
    }
    private static String endpoint(NetworkRegistry registry, Api.NetworkCreated network, Api.Joined from, Api.Joined to) {
        return registry.peers(network.networkId(), from.peerToken()).peers().stream().filter(p -> p.peerId().equals(to.peerId())).findFirst().orElseThrow().endpoint();
    }
    private static final class FailingStore extends StateStore {
        boolean fail;
        FailingStore(Path file) throws IOException { super(file); }
        @Override void save(State state) throws IOException { if (fail) throw new IOException("disk full"); super.save(state); }
    }
}
