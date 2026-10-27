package dev.samurai.vpn.server;

import dev.samurai.vpn.core.*;
import org.junit.jupiter.api.Test;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class RelayTest {
    private static final HexFormat HEX = HexFormat.of();

    @Test void blake2sMatchesReferenceVectors() {
        // RFC 7693 Appendix B, and keyed vectors produced by Python hashlib.blake2s.
        assertEquals("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
                HEX.formatHex(Blake2s.hash("abc".getBytes(StandardCharsets.US_ASCII))));
        byte[] key = new byte[32]; for (int i = 0; i < 32; i++) key[i] = (byte) i;
        assertEquals("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49", HEX.formatHex(Blake2s.hash(key, new byte[0], 0, 0, 32)));
        byte[] data = new byte[255]; for (int i = 0; i < data.length; i++) data[i] = (byte) i;
        assertEquals("3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd", HEX.formatHex(Blake2s.hash(key, data, 0, data.length, 32)));
        byte[] publicKey = new byte[32]; for (int i = 0; i < 32; i++) publicKey[i] = (byte) (100 + i);
        byte[] message = new byte[148]; for (int i = 0; i < 116; i++) message[i] = (byte) (i * 7);
        System.arraycopy(HEX.parseHex("850b3656772e51ca537f84d9c047b4e0"), 0, message, 116, 16);
        assertTrue(Blake2s.validMac1(publicKey, message, 148));
        message[5] ^= 1;
        assertFalse(Blake2s.validMac1(publicKey, message, 148));
    }

    @Test void membersWithoutEndpointsReceiveSymmetricRelayPortsUntilRevoked() throws Exception {
        String admin = Tokens.generate();
        try (var relay = new Relay(InetAddress.getLoopbackAddress(), "127.0.0.1", freeRange(), 4)) {
            var registry = new NetworkRegistry(admin, Clock.systemUTC(), relay);
            var network = registry.create(admin, "Friends");
            var a = join(registry, network, "A", ""); var b = join(registry, network, "B", ""); var c = join(registry, network, "C", "198.51.100.7:51820");
            String aToB = peer(registry, network, a, b).endpoint(), bToA = peer(registry, network, b, a).endpoint();
            assertTrue(aToB.startsWith("127.0.0.1:") && bToA.startsWith("127.0.0.1:"));
            assertNotEquals(aToB, bToA);
            assertEquals(aToB, peer(registry, network, a, b).endpoint(), "allocation is stable");
            assertEquals("198.51.100.7:51820", peer(registry, network, a, c).endpoint(), "reachable peers stay direct");
            assertEquals("", peer(registry, network, c, a).endpoint(), "direct peer learns the roaming endpoint");
            assertTrue(registry.peers(network.networkId(), network.ownerToken()).peers().stream().allMatch(p -> !p.endpoint().startsWith("127.")));
            assertEquals(2, relay.allocatedPorts());
            var d = join(registry, network, "D", "");
            peer(registry, network, a, d);
            assertEquals("", peer(registry, network, b, d).endpoint(), "exhausted pool falls back to no endpoint");
            registry.revoke(network.networkId(), network.ownerToken(), a.peerId());
            assertEquals(0, relay.allocatedPorts());
            assertTrue(peer(registry, network, b, d).endpoint().startsWith("127.0.0.1:"), "released ports are reused");
        }
    }

    @Test void forwardsOnlyAuthenticatedHandshakesAndLearnedAddresses() throws Exception {
        String admin = Tokens.generate();
        try (var relay = new Relay(InetAddress.getLoopbackAddress(), "127.0.0.1", freeRange(), 2);
             var sa = socket(); var sb = socket(); var stranger = socket()) {
            relay.start();
            var registry = new NetworkRegistry(admin, Clock.systemUTC(), relay);
            var network = registry.create(admin, "Friends");
            var keyA = WireGuardKeys.generate(); var keyB = WireGuardKeys.generate();
            var a = join(registry, network, "A", "", keyA.publicKey()); var b = join(registry, network, "B", "", keyB.publicKey());
            var portA = address(peer(registry, network, a, b).endpoint()); var portB = address(peer(registry, network, b, a).endpoint());

            send(sb, portB, handshake(keyA.publicKey()));            // B → A initiation; A not learned yet, dropped
            send(sa, portA, handshake(keyB.publicKey()));            // A → B initiation, forwarded to B
            assertArrayEquals(handshake(keyB.publicKey()), receive(sb, portB));
            assertEquals("127.0.0.1:" + sa.getLocalPort(), peer(registry, network, b, a).candidate(), "B learns A's observed address");
            assertEquals("127.0.0.1:" + sb.getLocalPort(), peer(registry, network, a, b).candidate());
            assertEquals("", registry.peers(network.networkId(), network.ownerToken()).peers().getFirst().candidate(), "owner view has no candidates");
            byte[] data = dataPacket(64);
            send(sb, portB, data);                                    // B learned earlier, now reaches A
            assertArrayEquals(data, receive(sa, portA));

            send(stranger, portA, dataPacket(32));                    // unlearned source, data refused
            send(stranger, portA, handshake(keyA.publicKey()));       // mac1 for the wrong recipient
            byte[] corrupt = handshake(keyB.publicKey()); corrupt[20] ^= 1;
            send(stranger, portA, corrupt);
            send(stranger, portA, new byte[]{9, 0, 0, 0, 1, 2});      // not a WireGuard message
            sb.setSoTimeout(400);
            assertThrows(SocketTimeoutException.class, () -> sb.receive(new DatagramPacket(new byte[4096], 4096)));

            byte[] after = dataPacket(48);
            send(sa, portA, after);                                   // legitimate member still owns the port
            sb.setSoTimeout(3000);
            assertArrayEquals(after, receive(sb, portB));

            registry.revoke(network.networkId(), network.ownerToken(), a.peerId());
            send(sa, portA, dataPacket(32));
            sb.setSoTimeout(400);
            assertThrows(SocketTimeoutException.class, () -> sb.receive(new DatagramPacket(new byte[4096], 4096)));
        }
    }

    @Test void recognisesOnlyWellFormedWireGuardMessages() {
        assertEquals(1, Relay.wireGuardType(typed(1, 148), 148));
        assertEquals(2, Relay.wireGuardType(typed(2, 92), 92));
        assertEquals(4, Relay.wireGuardType(typed(4, 32), 32));
        assertEquals(0, Relay.wireGuardType(typed(4, 40), 40));
        assertEquals(0, Relay.wireGuardType(typed(1, 147), 147));
        assertEquals(0, Relay.wireGuardType(typed(5, 32), 32));
        byte[] reserved = typed(4, 32); reserved[2] = 1;
        assertEquals(0, Relay.wireGuardType(reserved, 32));
    }
    private static byte[] typed(int type, int length) { byte[] packet = new byte[length]; packet[0] = (byte) type; return packet; }

    static int freeRange() throws Exception { return freeRange(4); }
    static int freeRange(int count) throws Exception {
        // Probe a random high range; a collision only makes this test retry with another range.
        for (int attempt = 0; attempt < 50; attempt++) {
            int first = 20000 + new Random().nextInt(30000);
            boolean free = true;
            for (int port = first; port < first + count && free; port++)
                try (var probe = new DatagramSocket(port, InetAddress.getLoopbackAddress())) { /* free */ } catch (SocketException e) { free = false; }
            if (free) return first;
        }
        throw new IllegalStateException("No free UDP range");
    }
    private static Api.Joined join(NetworkRegistry registry, Api.NetworkCreated network, String name, String endpoint) {
        return join(registry, network, name, endpoint, WireGuardKeys.generate().publicKey());
    }
    private static Api.Joined join(NetworkRegistry registry, Api.NetworkCreated network, String name, String endpoint, String publicKey) {
        var invite = registry.invite(network.networkId(), network.ownerToken());
        return registry.join(network.networkId(), invite.inviteToken(), new Api.Join(name, publicKey, endpoint));
    }
    private static Api.Peer peer(NetworkRegistry registry, Api.NetworkCreated network, Api.Joined caller, Api.Joined target) {
        return registry.peers(network.networkId(), caller.peerToken()).peers().stream().filter(p -> p.peerId().equals(target.peerId())).findFirst().orElseThrow();
    }
    private static byte[] handshake(String recipientPublicKey) {
        byte[] message = new byte[148]; message[0] = 1;
        for (int i = 4; i < 116; i++) message[i] = (byte) (i * 31);
        byte[] label = new byte[40];
        System.arraycopy("mac1----".getBytes(StandardCharsets.US_ASCII), 0, label, 0, 8);
        System.arraycopy(Base64.getDecoder().decode(recipientPublicKey), 0, label, 8, 32);
        System.arraycopy(Blake2s.hash(Blake2s.hash(label), message, 0, 116, 16), 0, message, 116, 16);
        return message;
    }
    private static byte[] dataPacket(int length) {
        byte[] packet = new byte[length]; packet[0] = 4;
        for (int i = 4; i < length; i++) packet[i] = (byte) (i * 13);
        return packet;
    }
    private static DatagramSocket socket() throws SocketException {
        var socket = new DatagramSocket(0, InetAddress.getLoopbackAddress()); socket.setSoTimeout(3000); return socket;
    }
    private static InetSocketAddress address(String endpoint) {
        String[] parts = endpoint.split(":"); return new InetSocketAddress(parts[0], Integer.parseInt(parts[1]));
    }
    private static void send(DatagramSocket socket, InetSocketAddress target, byte[] packet) throws Exception {
        socket.send(new DatagramPacket(packet, packet.length, target)); Thread.sleep(50);
    }
    private static byte[] receive(DatagramSocket socket, InetSocketAddress expectedSource) throws Exception {
        var packet = new DatagramPacket(new byte[4096], 4096); socket.receive(packet);
        assertEquals(expectedSource, packet.getSocketAddress(), "relay answers from the endpoint configured for this peer");
        return Arrays.copyOf(packet.getData(), packet.getLength());
    }
}
