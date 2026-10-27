package dev.samurai.vpn.core;

import java.util.UUID;

public final class Validation {
    private Validation() {}
    public static String name(String name) {
        if (name == null || name.isBlank() || name.length() > 64 || !name.equals(name.strip())
                || name.codePoints().anyMatch(c -> Character.isISOControl(c) || Character.getType(c) == Character.FORMAT)) {
            throw new IllegalArgumentException("Name must contain 1–64 visible characters without surrounding spaces");
        }
        return name;
    }
    public static String id(String value) {
        if (value == null || !UUID.fromString(value).toString().equals(value))
            throw new IllegalArgumentException("Invalid ID");
        return value;
    }
    public static String ipv4(String value) {
        if (value == null) throw new IllegalArgumentException("IPv4 address required");
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) throw new IllegalArgumentException("Invalid IPv4 address");
        for (String p : parts) {
            if (!p.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(p) > 255)
                throw new IllegalArgumentException("Invalid IPv4 address");
        }
        return value;
    }
    public static String overlayAddress(String value) {
        ipv4(value);
        if (!value.startsWith("10.203.") || value.endsWith(".0") || value.endsWith(".255"))
            throw new IllegalArgumentException("Address outside the reserved overlay pool");
        return value;
    }
    public static String endpoint(String endpoint) {
        if (endpoint == null || endpoint.isEmpty()) return "";
        String[] parts = endpoint.split(":", -1);
        if (parts.length != 2) throw new IllegalArgumentException("Endpoint must be a literal IPv4:port");
        ipv4(parts[0]);
        int first = Integer.parseInt(parts[0].split("\\.")[0]);
        if (first == 0 || first >= 224 || parts[0].equals("255.255.255.255"))
            throw new IllegalArgumentException("Endpoint must be a unicast address");
        if (!parts[1].matches("[1-9][0-9]{0,4}")) throw new IllegalArgumentException("Invalid endpoint port");
        port(Integer.parseInt(parts[1]));
        return endpoint;
    }
    public static int port(int port) {
        if (port < 1 || port > 65535) throw new IllegalArgumentException("Port must be between 1 and 65535");
        return port;
    }
}
