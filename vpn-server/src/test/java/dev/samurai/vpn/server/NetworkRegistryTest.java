package dev.samurai.vpn.server;

import dev.samurai.vpn.core.*;
import org.junit.jupiter.api.Test;
import java.time.*;
import java.util.ArrayList;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

class NetworkRegistryTest {
    private final String admin = Tokens.generate();
    private final NetworkRegistry registry = new NetworkRegistry(admin);
    private Api.Join request() { return new Api.Join("Device", WireGuardKeys.generate().publicKey(), "192.168.1.2:51820"); }

    @Test void credentialsAreScopedAndEnrollmentIsSingleUse() {
        var network = registry.create(admin, "Friends");
        var other = registry.create(admin, "Other");
        var invite = registry.invite(network.networkId(), network.ownerToken());
        assertThrows(ApiException.class, () -> registry.join(other.networkId(), invite.inviteToken(), request()));
        var member = registry.join(network.networkId(), invite.inviteToken(), request());
        assertEquals(1, registry.peers(network.networkId(), member.peerToken()).peers().size());
        assertThrows(ApiException.class, () -> registry.join(network.networkId(), invite.inviteToken(), request()));
        assertThrows(ApiException.class, () -> registry.invite(network.networkId(), member.peerToken()));
        assertThrows(ApiException.class, () -> registry.peers(other.networkId(), member.peerToken()));
        assertThrows(ApiException.class, () -> registry.revoke(network.networkId(), member.peerToken(), member.peerId()));
        assertThrows(ApiException.class, () -> registry.create(network.ownerToken(), "Forbidden"));
        assertThrows(ApiException.class, () -> registry.peers(network.networkId(), admin));
    }
    @Test void revocationRemovesApiAccessAndAddressIsNotReused() {
        var network = registry.create(admin, "Friends");
        var first = registry.join(network.networkId(), registry.invite(network.networkId(), network.ownerToken()).inviteToken(), request());
        registry.revoke(network.networkId(), network.ownerToken(), first.peerId());
        assertThrows(ApiException.class, () -> registry.peers(network.networkId(), first.peerToken()));
        assertTrue(registry.peers(network.networkId(), network.ownerToken()).peers().isEmpty());
        var second = registry.join(network.networkId(), registry.invite(network.networkId(), network.ownerToken()).inviteToken(), request());
        assertNotEquals(first.address(), second.address());
    }
    @Test void invalidJoinDoesNotBurnInvitationAndDuplicateKeysAreRejected() {
        var network = registry.create(admin, "Friends");
        var invite = registry.invite(network.networkId(), network.ownerToken());
        assertThrows(IllegalArgumentException.class, () -> registry.join(network.networkId(), invite.inviteToken(), new Api.Join("Device", "bad-key", "")));
        var request = request();
        registry.join(network.networkId(), invite.inviteToken(), request);
        var next = registry.invite(network.networkId(), network.ownerToken());
        assertThrows(ApiException.class, () -> registry.join(network.networkId(), next.inviteToken(), request));
    }
    @Test void expiredInvitationIsRejectedAtExactDeadline() {
        var clock = new MutableClock(); var store = new NetworkRegistry(admin, clock);
        var network = store.create(admin, "Friends"); var invite = store.invite(network.networkId(), network.ownerToken());
        clock.now = clock.now.plus(Duration.ofMinutes(10));
        assertThrows(ApiException.class, () -> store.join(network.networkId(), invite.inviteToken(), request()));
    }
    @Test void concurrentRedemptionAllowsExactlyOneWinner() throws Exception {
        var network = registry.create(admin, "Friends"); var invite = registry.invite(network.networkId(), network.ownerToken());
        try (var pool = Executors.newFixedThreadPool(8)) {
            var jobs = new ArrayList<Callable<Boolean>>();
            for (int i = 0; i < 20; i++) jobs.add(() -> {
                try { registry.join(network.networkId(), invite.inviteToken(), request()); return true; }
                catch (ApiException e) { return false; }
            });
            int successes = 0;
            for (var future : pool.invokeAll(jobs)) if (future.get()) successes++;
            assertEquals(1, successes);
        }
    }
    @Test void capsNetworksAndOutstandingInvites() {
        var network = registry.create(admin, "Friends");
        for (int i = 0; i < 32; i++) registry.invite(network.networkId(), network.ownerToken());
        assertThrows(ApiException.class, () -> registry.invite(network.networkId(), network.ownerToken()));
        for (int i = 1; i < 32; i++) registry.create(admin, "Network " + i);
        assertThrows(ApiException.class, () -> registry.create(admin, "Overflow"));
    }
    private static class MutableClock extends Clock {
        Instant now = Instant.parse("2026-10-26T00:00:00Z");
        public ZoneId getZone() { return ZoneOffset.UTC; }
        public Clock withZone(ZoneId zone) { return this; }
        public Instant instant() { return now; }
    }
}
