package dev.samurai.vpn.core;

import java.util.*;

public final class Arguments {
    private final Map<String, String> values = new HashMap<>();
    public Arguments(String[] args, int start, Set<String> flags, Set<String> options) {
        for (int i = start; i < args.length; i++) {
            String key = args[i];
            if (!flags.contains(key) && !options.contains(key)) throw new IllegalArgumentException("Unknown option: " + key);
            String value = "true";
            if (!flags.contains(key)) {
                if (++i >= args.length || args[i].startsWith("--")) throw new IllegalArgumentException("Missing value for " + key);
                value = args[i];
            }
            if (values.putIfAbsent(key, value) != null) throw new IllegalArgumentException("Duplicate option: " + key);
        }
    }
    public boolean has(String key) { return values.containsKey(key); }
    public String get(String key, String fallback) { return values.getOrDefault(key, fallback); }
    public String require(String key) {
        String value = values.get(key);
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Required option: " + key);
        return value;
    }
}
