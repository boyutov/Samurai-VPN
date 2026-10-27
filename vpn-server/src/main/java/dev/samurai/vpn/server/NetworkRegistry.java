package dev.samurai.vpn.server;

import dev.samurai.vpn.core.*;
import java.io.IOException;
import java.time.*;
import java.util.*;

/**
 * Control-plane state. All enrollment transitions are atomic under this monitor. With a store,
 * each change is saved before it is acknowledged; a failed save restores the previous state.
 */
public final class NetworkRegistry {
    private static final int MAX_NETWORKS = 32, MAX_PEERS = 64, MAX_INVITES = 32;
    private final Map<String, Network> networks = new LinkedHashMap<>();
    private final String adminHash;
    private final Clock clock;
    private final Relay relay;
    private final StateStore store;
    private List<Relay.Pair> savedPairs = List.of();
    public NetworkRegistry(String adminToken) { this(adminToken, Clock.systemUTC()); }
    public NetworkRegistry(String adminToken, Clock clock) { this(adminToken, clock, null); }
    public NetworkRegistry(String adminToken, Clock clock, Relay relay) {
        this.adminHash = Tokens.hash(adminToken); this.clock = Objects.requireNonNull(clock); this.relay = relay; this.store = null;
    }
    /** Loads existing state; relay allocations are restored so members keep their relay endpoints. */
    NetworkRegistry(String adminToken, Clock clock, Relay relay, StateStore store) throws IOException {
        this.adminHash = Tokens.hash(adminToken); this.clock = Objects.requireNonNull(clock); this.relay = relay; this.store = Objects.requireNonNull(store);
        var state = store.load();
        if (state.isEmpty()) return;
        try { apply(state.get()); }
        catch (RuntimeException e) { throw new IOException("State file is invalid", e); }
        if (relay != null && state.get().relayPairs() != null) {
            for (var pair : state.get().relayPairs()) {
                Network network = networks.get(pair.networkId());
                Member low = network == null ? null : network.peers.get(pair.lowPeerId()), high = network == null ? null : network.peers.get(pair.highPeerId());
                // Pairs outside the current port range are allocated anew on the next sync.
                if (low != null && high != null) relay.restore(pair, low.peer, high.peer);
            }
            savedPairs = relay.pairs();
        }
    }
    public boolean persistent() { return store != null; }
    public synchronized Api.NetworkCreated create(String credential, String name) {
        authenticate(credential, adminHash);
        Validation.name(name);
        if (networks.size() >= MAX_NETWORKS) throw new ApiException(409, "capacity", "Network limit reached");
        var before = before();
        String id = UUID.randomUUID().toString(), owner = Tokens.generate();
        networks.put(id, new Network(name, Tokens.hash(owner), networks.size() + 1));
        commit(before);
        return new Api.NetworkCreated(id, name, owner);
    }
    public synchronized Api.InviteCreated invite(String id, String credential) {
        Network network = network(id);
        authenticate(credential, network.ownerHash);
        var before = before();
        network.invites.values().removeIf(expiry -> !clock.instant().isBefore(expiry));
        if (network.invites.size() >= MAX_INVITES) throw new ApiException(409, "capacity", "Too many active invitations");
        String token = Tokens.generate();
        Instant expires = clock.instant().plus(Duration.ofMinutes(10));
        network.invites.put(Tokens.hash(token), expires);
        commit(before);
        return new Api.InviteCreated(id, token, expires.toString());
    }
    public synchronized Api.Joined join(String id, String credential, Api.Join request) {
        Network network = network(id);
        if (!Tokens.valid(credential)) throw unauthorized();
        String inviteHash = Tokens.hash(credential);
        Instant expires = network.invites.get(inviteHash);
        if (expires == null || !clock.instant().isBefore(expires)) {
            network.invites.remove(inviteHash);
            throw unauthorized();
        }
        Validation.name(request.name());
        WireGuardKeys.validatePublic(request.publicKey());
        String endpoint = Validation.endpoint(request.endpoint());
        if (network.peers.values().stream().anyMatch(p -> p.peer.publicKey().equals(request.publicKey())))
            throw new ApiException(409, "duplicate_key", "This public key is already enrolled");
        if (network.peers.size() >= MAX_PEERS || network.nextHost > 254)
            throw new ApiException(409, "capacity", "Network address or member limit reached");
        var before = before();
        String peerId = UUID.randomUUID().toString(), token = Tokens.generate();
        String address = "10.203." + network.subnet + "." + network.nextHost++;
        Api.Peer peer = new Api.Peer(peerId, request.name(), request.publicKey(), address, endpoint);
        network.peers.put(peerId, new Member(peer, Tokens.hash(token)));
        network.invites.remove(inviteHash);
        commit(before);
        return new Api.Joined(id, peerId, address, token);
    }
    public synchronized Api.Peers peers(String id, String credential) {
        Network network = network(id);
        Member caller = network.peers.values().stream().filter(p -> Tokens.matches(credential, p.tokenHash)).findFirst().orElse(null);
        if (caller == null && !Tokens.matches(credential, network.ownerHash)) throw unauthorized();
        // A member's view replaces missing endpoints with relay ports when neither side is reachable directly.
        var result = new Api.Peers(id, network.peers.values().stream().map(p -> p.peer).map(peer -> relay == null || caller == null
                || peer == caller.peer || !caller.peer.endpoint().isEmpty() || !peer.endpoint().isEmpty() ? peer
                : new Api.Peer(peer.peerId(), peer.name(), peer.publicKey(), peer.address(), relay.endpoint(id, caller.peer, peer),
                        relay.observed(id, peer.peerId()))).toList());
        // New relay ports are saved so they survive a restart; a failed save is retried with the next change.
        if (store != null && relay != null && !relay.pairs().equals(savedPairs)) {
            try { save(); } catch (IOException ignored) { /* the allocation still works until restart */ }
        }
        return result;
    }
    public synchronized void revoke(String id, String credential, String peerId) {
        Network network = network(id);
        authenticate(credential, network.ownerHash);
        var before = before();
        if (network.peers.remove(peerId) == null) throw new ApiException(404, "not_found", "Peer not found");
        commit(before);
        if (relay != null) relay.release(id, peerId);
        // Addresses are deliberately not reused: old exported profiles may still exist.
    }
    private StateStore.State before() { return store == null ? null : snapshot(); }
    private void commit(StateStore.State before) {
        if (store == null) return;
        try { save(); }
        catch (IOException e) {
            apply(before);
            throw new ApiException(503, "storage_unavailable", "State could not be saved; nothing was changed");
        }
    }
    private void save() throws IOException {
        var state = snapshot();
        store.save(state);
        savedPairs = relay == null ? List.of() : relay.pairs();
    }
    private StateStore.State snapshot() {
        var list = new ArrayList<StateStore.NetworkState>();
        networks.forEach((id, n) -> {
            var invites = new TreeMap<String, String>();
            n.invites.forEach((hash, expires) -> invites.put(hash, expires.toString()));
            list.add(new StateStore.NetworkState(id, n.name, n.ownerHash, n.subnet, n.nextHost, invites, n.peers.values().stream()
                    .map(m -> new StateStore.MemberState(m.peer.peerId(), m.peer.name(), m.peer.publicKey(), m.peer.address(), m.peer.endpoint(), m.tokenHash))
                    .toList()));
        });
        // A revoked member's ports are released after its removal is saved: never persist them.
        var pairs = relay == null ? List.<Relay.Pair>of() : relay.pairs().stream().filter(p -> {
            Network network = networks.get(p.networkId());
            return network != null && network.peers.containsKey(p.lowPeerId()) && network.peers.containsKey(p.highPeerId());
        }).toList();
        return new StateStore.State(StateStore.VERSION, list, pairs);
    }
    /** Replaces all networks with a snapshot; validates everything, since the file may have been edited. */
    private void apply(StateStore.State state) {
        var restored = new LinkedHashMap<String, Network>();
        if (state.networks() == null || state.networks().size() > MAX_NETWORKS) throw new IllegalArgumentException("Invalid networks");
        for (var n : state.networks()) {
            Validation.id(n.networkId()); Validation.name(n.name()); hash(n.ownerHash());
            // Networks are never deleted and create() assigns size + 1, so subnets are exactly 1..n in order.
            if (n.subnet() != restored.size() + 1 || n.nextHost() < 1 || n.nextHost() > 255
                    || n.invites() == null || n.invites().size() > MAX_INVITES || n.members() == null || n.members().size() > MAX_PEERS)
                throw new IllegalArgumentException("Invalid network");
            var network = new Network(n.name(), n.ownerHash(), n.subnet());
            network.nextHost = n.nextHost();
            n.invites().forEach((hash, expires) -> network.invites.put(hash(hash), Instant.parse(expires)));
            var keys = new HashSet<String>(); var addresses = new HashSet<String>();
            for (var m : n.members()) {
                Validation.id(m.peerId()); Validation.name(m.name()); WireGuardKeys.validatePublic(m.publicKey()); hash(m.tokenHash());
                String prefix = "10.203." + n.subnet() + ".";
                if (m.address() == null || !m.address().startsWith(prefix) || !keys.add(m.publicKey()) || !addresses.add(m.address()))
                    throw new IllegalArgumentException("Invalid member");
                int host = Integer.parseInt(Validation.overlayAddress(m.address()).substring(prefix.length()));
                if (host < 1 || host >= n.nextHost()) throw new IllegalArgumentException("Invalid member address");
                var peer = new Api.Peer(m.peerId(), m.name(), m.publicKey(), m.address(), Validation.endpoint(m.endpoint()));
                if (network.peers.put(m.peerId(), new Member(peer, m.tokenHash())) != null) throw new IllegalArgumentException("Duplicate member");
            }
            if (restored.put(n.networkId(), network) != null) throw new IllegalArgumentException("Duplicate network");
        }
        networks.clear(); networks.putAll(restored);
    }
    private static String hash(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("Invalid hash");
        return value;
    }
    private Network network(String id) {
        Network network = networks.get(id);
        if (network == null) throw new ApiException(404, "not_found", "Network not found");
        return network;
    }
    private static void authenticate(String token, String hash) { if (!Tokens.matches(token, hash)) throw unauthorized(); }
    private static ApiException unauthorized() { return new ApiException(401, "unauthorized", "Invalid or expired credential"); }
    private record Member(Api.Peer peer, String tokenHash) {}
    private static final class Network {
        final String name, ownerHash;
        final int subnet;
        int nextHost = 1;
        final Map<String, Instant> invites = new HashMap<>();
        final Map<String, Member> peers = new LinkedHashMap<>();
        Network(String name, String ownerHash, int subnet) { this.name = name; this.ownerHash = ownerHash; this.subnet = subnet; }
    }
}
