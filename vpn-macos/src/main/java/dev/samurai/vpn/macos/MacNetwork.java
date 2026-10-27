package dev.samurai.vpn.macos;

import dev.samurai.vpn.core.*;
import java.util.*;

/**
 * Converts "netstat -rn -f inet" and "ifconfig -a" into the "ip -j" JSON shape that RouteGuard
 * checks on Linux. macOS has no JSON output for routes; unparsable lines are skipped only when
 * they cannot be IPv4 routes, never silently treated as "no conflict".
 */
final class MacNetwork {
    private MacNetwork() {}
    static String routes(String netstat) throws Exception {
        var result = new ArrayList<Map<String, String>>();
        boolean table = false;
        for (String line : netstat.lines().toList()) {
            String[] fields = line.strip().split("\\s+");
            if (fields.length > 0 && fields[0].equals("Destination")) { table = true; continue; }
            if (!table || fields.length < 4 || fields[0].equals("default")) continue;
            result.add(Map.of("dst", prefix(fields[0]), "dev", fields[3]));
        }
        if (!table) throw new java.io.IOException("Cannot inspect IPv4 routing");
        return Json.MAPPER.writeValueAsString(result);
    }
    /** netstat abbreviates networks: "192.168.1" is 192.168.1.0/24, "224.0.0/4" is 224.0.0.0/4, "127" is 127.0.0.0/8. */
    static String prefix(String destination) {
        String[] parts = destination.split("/", -1);
        String[] octets = parts[0].split("\\.", -1);
        if (octets.length > 4 || parts.length > 2) throw new IllegalArgumentException("Invalid route destination");
        var address = new ArrayList<>(List.of(octets));
        while (address.size() < 4) address.add("0");
        String ip = Validation.ipv4(String.join(".", address));
        int bits = parts.length == 2 ? Integer.parseInt(parts[1]) : octets.length * 8;
        if (bits < 0 || bits > 32) throw new IllegalArgumentException("Invalid prefix length");
        return ip + "/" + bits;
    }
    static String addresses(String ifconfig) throws Exception {
        var result = new ArrayList<Map<String, Object>>();
        String device = null;
        for (String line : ifconfig.lines().toList()) {
            if (!line.isEmpty() && !Character.isWhitespace(line.charAt(0)) && line.contains(": flags=")) {
                device = line.substring(0, line.indexOf(':')); continue;
            }
            String[] fields = line.strip().split("\\s+");
            if (device == null || fields.length < 2 || !fields[0].equals("inet")) continue;
            int mask = Arrays.asList(fields).indexOf("netmask");
            if (mask < 0 || mask + 1 >= fields.length || !fields[mask + 1].matches("0x[0-9a-f]{8}")) throw new java.io.IOException("Unexpected interface address");
            int bits = Long.bitCount(Long.parseLong(fields[mask + 1].substring(2), 16));
            result.add(Map.of("ifname", device, "addr_info", List.of(Map.of("family", "inet", "local", Validation.ipv4(fields[1]), "prefixlen", bits))));
        }
        return Json.MAPPER.writeValueAsString(result);
    }
}
