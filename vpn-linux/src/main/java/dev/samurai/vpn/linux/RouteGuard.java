package dev.samurai.vpn.linux;

import com.fasterxml.jackson.databind.JsonNode;
import dev.samurai.vpn.core.*;
import java.io.IOException;
import java.util.ArrayList;

public final class RouteGuard {
    private RouteGuard() {}
    public static void check(String routesJson, String addressesJson, TunnelProtocol.Configuration config) throws IOException {
        var targets = new ArrayList<String>(); targets.add(config.address()); config.peers().forEach(p -> targets.add(p.address()));
        check(routesJson, addressesJson, targets, null);
    }
    /** Checks new targets; routes and addresses of {@code ownDevice} (the running tunnel) are expected and ignored. */
    public static void check(String routesJson, String addressesJson, java.util.List<String> targets, String ownDevice) throws IOException {
        JsonNode routes = Json.MAPPER.readTree(routesJson), devices = Json.MAPPER.readTree(addressesJson);
        if (!routes.isArray() || !devices.isArray()) throw new IOException("Cannot inspect IPv4 routing");
        for (JsonNode route : routes) {
            String prefix = route.path("dst").asText("");
            if (prefix.isEmpty() || prefix.equals("default") || prefix.equals("0.0.0.0/0")) continue;
            if (ownDevice != null && ownDevice.equals(route.path("dev").asText())) continue;
            for (String target : targets) if (contains(prefix, target)) throw new IOException("Route conflict for " + target + " with " + prefix);
        }
        for (JsonNode device : devices) {
            if (ownDevice != null && ownDevice.equals(device.path("ifname").asText())) continue;
            for (JsonNode entry : device.path("addr_info")) {
                if (!entry.path("family").asText().equals("inet")) continue;
                String prefix = entry.path("local").asText() + "/" + entry.path("prefixlen").asInt(-1);
                for (String target : targets) if (contains(prefix, target)) throw new IOException("Address conflict for " + target + " with " + prefix);
            }
        }
    }
    static boolean contains(String prefix, String address) {
        String[] parts = prefix.split("/", -1);
        if (parts.length > 2) throw new IllegalArgumentException("Invalid route prefix");
        long network = number(parts[0]), target = number(address);
        int bits = parts.length == 1 ? 32 : Integer.parseInt(parts[1]);
        if (bits < 0 || bits > 32) throw new IllegalArgumentException("Invalid prefix length");
        long mask = bits == 0 ? 0 : (0xFFFF_FFFFL << (32 - bits)) & 0xFFFF_FFFFL;
        return (network & mask) == (target & mask);
    }
    private static long number(String ip) {
        Validation.ipv4(ip); long result = 0;
        for (String part : ip.split("\\.")) result = (result << 8) | Integer.parseInt(part);
        return result;
    }
}
