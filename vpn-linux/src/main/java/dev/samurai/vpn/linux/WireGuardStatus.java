package dev.samurai.vpn.linux;

import dev.samurai.vpn.core.*;
import java.io.IOException;
import java.util.*;

/** Parses "wg show IFACE latest-handshakes | transfer | endpoints"; the same on Linux and Windows. */
public final class WireGuardStatus {
    private WireGuardStatus() {}
    public static TunnelProtocol.Status parse(String state, String name, String handshakes, String transfers, String endpoints) throws IOException {
        long latest = 0, received = 0, sent = 0;
        var handshakeByKey = new LinkedHashMap<String, Long>();
        for (String line : handshakes.lines().filter(s -> !s.isBlank()).toList()) {
            String[] fields = line.strip().split("\\s+");
            if (fields.length != 2) throw new IOException("Unexpected WireGuard status");
            WireGuardKeys.validatePublic(fields[0]); long value = nonnegative(fields[1]);
            handshakeByKey.put(fields[0], value); latest = Math.max(latest, value);
        }
        var receivedByKey = new HashMap<String, Long>();
        for (String line : transfers.lines().filter(s -> !s.isBlank()).toList()) {
            String[] fields = line.strip().split("\\s+");
            if (fields.length != 3) throw new IOException("Unexpected WireGuard counters");
            WireGuardKeys.validatePublic(fields[0]);
            long in = nonnegative(fields[1]); receivedByKey.put(fields[0], in);
            received = Math.addExact(received, in); sent = Math.addExact(sent, nonnegative(fields[2]));
        }
        var peers = new ArrayList<TunnelProtocol.PeerState>();
        for (String line : endpoints.lines().filter(s -> !s.isBlank()).toList()) {
            String[] fields = line.strip().split("\\s+");
            if (fields.length != 2) throw new IOException("Unexpected WireGuard endpoints");
            WireGuardKeys.validatePublic(fields[0]);
            String endpoint = fields[1].equals("(none)") ? "" : fields[1];
            try { Validation.endpoint(endpoint); } catch (IllegalArgumentException e) { endpoint = ""; } // IPv6 is not reported yet
            peers.add(new TunnelProtocol.PeerState(fields[0], endpoint, handshakeByKey.getOrDefault(fields[0], 0L), receivedByKey.getOrDefault(fields[0], 0L)));
        }
        return new TunnelProtocol.Status(state, name, latest, received, sent, peers);
    }
    private static long nonnegative(String text) { long value = Long.parseLong(text); if (value < 0) throw new IllegalArgumentException("Negative counter"); return value; }
}
