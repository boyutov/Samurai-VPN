package dev.samurai.vpn.server;

import dev.samurai.vpn.core.*;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReferenceArray;

/**
 * UDP relay for WireGuard ciphertext between two members that have no reachable endpoint.
 * Each member pair gets two ports; a member's kernel WireGuard simply uses relay-host:port as
 * the peer endpoint. The relay never receives private keys and cannot decrypt traffic.
 * A sender address is learned only from a handshake whose mac1 matches the expected
 * recipient's public key; afterwards only that address may use the port until the next
 * valid handshake (WireGuard roaming).
 * The learned address is the member's public NAT mapping of its WireGuard socket; it is offered
 * to the other member as a hole-punching candidate.
 */
public final class Relay implements AutoCloseable {
    static final int MAX_PORTS = 2048, MAX_PACKET = 2048;
    static final long RATE_BYTES = 2_000_000, BURST_BYTES = 4_000_000, HANDSHAKE_RATE = 20;
    private final String publicHost;
    private final int firstPort;
    private final DatagramChannel[] channels;
    private final AtomicReferenceArray<Slot> slots;
    private final Map<String, int[]> pairs = new HashMap<>();
    private final Map<String, InetSocketAddress> observed = new java.util.concurrent.ConcurrentHashMap<>();
    private final Selector selector;
    private final Thread thread;
    private volatile boolean closed;

    public Relay(InetAddress bind, String publicHost, int firstPort, int count) throws IOException {
        Validation.ipv4(publicHost);
        if (count < 2 || count > MAX_PORTS || firstPort < 1024 || firstPort + count - 1 > 65535)
            throw new IllegalArgumentException("Relay port range must contain 2–" + MAX_PORTS + " ports within 1024–65535");
        Validation.endpoint(publicHost + ":" + firstPort);
        this.publicHost = publicHost; this.firstPort = firstPort;
        channels = new DatagramChannel[count]; slots = new AtomicReferenceArray<>(count);
        selector = Selector.open();
        try {
            for (int i = 0; i < count; i++) {
                channels[i] = DatagramChannel.open(StandardProtocolFamily.INET);
                channels[i].bind(new InetSocketAddress(bind, firstPort + i));
                channels[i].configureBlocking(false);
                channels[i].register(selector, SelectionKey.OP_READ, i);
            }
        } catch (IOException | RuntimeException e) { close(); throw e; }
        thread = Thread.ofPlatform().name("samurai-relay").daemon().unstarted(this::loop);
    }
    public void start() { thread.start(); }
    public int firstPort() { return firstPort; }

    /** Endpoint that {@code from} must use for {@code to}; empty when the port pool is exhausted. */
    public synchronized String endpoint(String networkId, Api.Peer from, Api.Peer to) {
        boolean fromLow = from.peerId().compareTo(to.peerId()) < 0;
        String key = networkId + "/" + (fromLow ? from.peerId() + "/" + to.peerId() : to.peerId() + "/" + from.peerId());
        int[] pair = pairs.get(key);
        if (pair == null) {
            int a = free(-1), b = a < 0 ? -1 : free(a);
            if (a < 0 || b < 0) return "";
            pair = allocate(networkId, fromLow ? from : to, fromLow ? to : from, a, b);
        }
        return publicHost + ":" + (firstPort + pair[fromLow ? 0 : 1]);
    }
    /** A persisted allocation: lowPort carries packets from the member with the smaller peer ID. */
    public record Pair(String networkId, String lowPeerId, String highPeerId, int lowPort, int highPort) {}
    public synchronized List<Pair> pairs() {
        var result = new ArrayList<Pair>();
        pairs.forEach((key, pair) -> {
            String[] parts = key.split("/");
            result.add(new Pair(parts[0], parts[1], parts[2], firstPort + pair[0], firstPort + pair[1]));
        });
        result.sort(Comparator.comparingInt(Pair::lowPort));
        return result;
    }
    /** Re-creates a persisted allocation so members keep their endpoints; false if its ports are unavailable. */
    public synchronized boolean restore(Pair pair, Api.Peer low, Api.Peer high) {
        int a = pair.lowPort() - firstPort, b = pair.highPort() - firstPort;
        if (low.peerId().compareTo(high.peerId()) >= 0 || !low.peerId().equals(pair.lowPeerId()) || !high.peerId().equals(pair.highPeerId())
                || a < 0 || b < 0 || a >= channels.length || b >= channels.length || a == b || slots.get(a) != null || slots.get(b) != null
                || pairs.containsKey(pair.networkId() + "/" + low.peerId() + "/" + high.peerId())) return false;
        allocate(pair.networkId(), low, high, a, b);
        return true;
    }
    private int[] allocate(String networkId, Api.Peer low, Api.Peer high, int a, int b) {
        String key = networkId + "/" + low.peerId() + "/" + high.peerId();
        // Packets entering port a come from low and are addressed to high, and vice versa.
        slots.set(a, new Slot(key, networkId + "/" + low.peerId(), b, Base64.getDecoder().decode(high.publicKey())));
        slots.set(b, new Slot(key, networkId + "/" + high.peerId(), a, Base64.getDecoder().decode(low.publicKey())));
        int[] pair = {a, b}; pairs.put(key, pair);
        return pair;
    }
    /** Public address:port last authenticated for this member through the relay, or empty. */
    public String observed(String networkId, String peerId) {
        InetSocketAddress address = observed.get(networkId + "/" + peerId);
        if (address == null) return "";
        try { return Validation.endpoint(address.getAddress().getHostAddress() + ":" + address.getPort()); }
        catch (IllegalArgumentException e) { return ""; }
    }
    /** Drops every allocation of a revoked member; its ports stop forwarding immediately. */
    public synchronized void release(String networkId, String peerId) {
        observed.remove(networkId + "/" + peerId);
        for (var iterator = pairs.entrySet().iterator(); iterator.hasNext(); ) {
            var entry = iterator.next();
            String[] parts = entry.getKey().split("/");
            if (parts[0].equals(networkId) && (parts[1].equals(peerId) || parts[2].equals(peerId))) {
                for (int index : entry.getValue()) slots.set(index, null);
                iterator.remove();
            }
        }
    }
    synchronized int allocatedPorts() { return pairs.size() * 2; }
    private int free(int except) {
        for (int i = 0; i < channels.length; i++) if (i != except && slots.get(i) == null) return i;
        return -1;
    }

    private void loop() {
        ByteBuffer buffer = ByteBuffer.allocate(MAX_PACKET + 1);
        while (!closed) {
            try {
                selector.select(1000);
                for (var iterator = selector.selectedKeys().iterator(); iterator.hasNext(); ) {
                    SelectionKey key = iterator.next(); iterator.remove();
                    int index = (Integer) key.attachment();
                    for (int burst = 0; burst < 64; burst++) {
                        buffer.clear();
                        SocketAddress source = channels[index].receive(buffer);
                        if (source == null) break;
                        forward(index, (InetSocketAddress) source, buffer);
                    }
                }
            } catch (ClosedSelectorException e) { return; }
            catch (IOException ignored) { /* A single failed send must not stop other pairs. */ }
        }
    }
    private void forward(int index, InetSocketAddress source, ByteBuffer buffer) throws IOException {
        Slot slot = slots.get(index);
        int length = buffer.position();
        if (slot == null || length > MAX_PACKET) return;
        byte[] packet = buffer.array();
        int type = wireGuardType(packet, length);
        if (type == 0) return;
        long now = System.nanoTime();
        if (!source.equals(slot.learned)) {
            if ((type != 1 && type != 2) || !slot.allowHandshakeCheck(now) || !Blake2s.validMac1(slot.recipientKey, packet, length)) return;
            slot.learned = source;
            observed.put(slot.member, source);
        }
        if (!slot.take(length, now)) return;
        Slot partner = slots.get(slot.partner);
        if (partner == null || partner.learned == null || !partner.pair.equals(slot.pair)) return;
        buffer.flip();
        channels[slot.partner].send(buffer, partner.learned);
    }
    /** Returns the WireGuard message type for a structurally valid message, otherwise 0. */
    static int wireGuardType(byte[] packet, int length) {
        if (length < 4 || packet[1] != 0 || packet[2] != 0 || packet[3] != 0) return 0;
        int type = packet[0];
        boolean valid = switch (type) {
            case 1 -> length == 148;
            case 2 -> length == 92;
            case 3 -> length == 64;
            case 4 -> length >= 32 && length % 16 == 0;
            default -> false;
        };
        return valid ? type : 0;
    }
    @Override public void close() {
        closed = true;
        try { selector.close(); } catch (IOException ignored) {}
        for (DatagramChannel channel : channels) if (channel != null) try { channel.close(); } catch (IOException ignored) {}
    }

    /** Mutable fields are touched only by the relay thread. */
    private static final class Slot {
        final String pair, member;
        final int partner;
        final byte[] recipientKey;
        InetSocketAddress learned;
        double bytes = BURST_BYTES, handshakes = HANDSHAKE_RATE;
        long refilled = System.nanoTime(), handshakeRefilled = System.nanoTime();
        Slot(String pair, String member, int partner, byte[] recipientKey) {
            this.pair = pair; this.member = member; this.partner = partner; this.recipientKey = recipientKey;
        }
        boolean take(int length, long now) {
            bytes = Math.min(BURST_BYTES, bytes + (now - refilled) * RATE_BYTES / 1e9); refilled = now;
            if (bytes < length) return false;
            bytes -= length; return true;
        }
        boolean allowHandshakeCheck(long now) {
            handshakes = Math.min(HANDSHAKE_RATE, handshakes + (now - handshakeRefilled) * HANDSHAKE_RATE / 1e9); handshakeRefilled = now;
            if (handshakes < 1) return false;
            handshakes -= 1; return true;
        }
    }
}
