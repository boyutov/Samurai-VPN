package dev.samurai.vpn.server;

/** Bounded global token bucket; no attacker-controlled map of source IPs. */
final class RateLimiter {
    private double tokens = 100;
    private long last = System.nanoTime();
    synchronized boolean allow() {
        long now = System.nanoTime();
        tokens = Math.min(100, tokens + (now - last) / 1_000_000_000.0 * 10);
        last = now;
        if (tokens < 1) return false;
        tokens--;
        return true;
    }
}
