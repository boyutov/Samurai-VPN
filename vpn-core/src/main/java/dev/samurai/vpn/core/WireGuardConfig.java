package dev.samurai.vpn.core;

import java.util.HashSet;
import java.util.List;

public final class WireGuardConfig {
    private WireGuardConfig() {}
    public static String render(WireGuardKeys.Identity identity, String ownAddress, int listenPort, List<Api.Peer> peers) {
        WireGuardKeys.validateIdentity(identity);
        Validation.overlayAddress(ownAddress);
        Validation.port(listenPort);
        if (peers == null || peers.size() > 64) throw new IllegalArgumentException("Invalid peer list");
        StringBuilder config = new StringBuilder("[Interface]\nPrivateKey = ").append(identity.privateKey())
                .append("\nAddress = ").append(ownAddress).append("/32\nListenPort = ").append(listenPort).append('\n');
        var keys = new HashSet<String>();
        var addresses = new HashSet<String>();
        addresses.add(ownAddress);
        keys.add(identity.publicKey());
        for (Api.Peer peer : peers) {
            WireGuardKeys.validatePublic(peer.publicKey());
            Validation.overlayAddress(peer.address());
            String endpoint = Validation.endpoint(peer.endpoint());
            if (!keys.add(peer.publicKey()) || !addresses.add(peer.address())) throw new IllegalArgumentException("Duplicate peer");
            if (!peer.address().substring(0, peer.address().lastIndexOf('.')).equals(ownAddress.substring(0, ownAddress.lastIndexOf('.'))))
                throw new IllegalArgumentException("Peer belongs to another network");
            config.append("\n[Peer]\nPublicKey = ").append(peer.publicKey())
                    .append("\nAllowedIPs = ").append(peer.address()).append("/32\n");
            if (!endpoint.isEmpty()) config.append("Endpoint = ").append(endpoint).append("\nPersistentKeepalive = 25\n");
        }
        return config.toString();
    }
}
