package dev.samurai.vpn.client;

import dev.samurai.vpn.core.*;

public final class Credentials {
    private Credentials() {}
    public record Owner(String server, String networkId, String ownerToken) {
        @Override public String toString() { return "Owner[credentials redacted]"; }
    }
    public record Invite(String server, String networkId, String inviteToken, String expiresAt) {
        @Override public String toString() { return "Invite[credentials redacted]"; }
    }
    public record Session(String server, WireGuardKeys.Identity identity, Api.Joined membership) {
        @Override public String toString() { return "Session[credentials redacted]"; }
    }
}
