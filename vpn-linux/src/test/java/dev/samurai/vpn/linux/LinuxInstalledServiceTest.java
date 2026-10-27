package dev.samurai.vpn.linux;

import dev.samurai.vpn.core.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * samurai-vpnd as the Debian package installs it (temporary systemd user, CAP_NET_ADMIN only),
 * used by an ordinary user over its socket. CI only (.github/workflows/verify.yml).
 */
@EnabledOnOs(OS.LINUX)
@EnabledIfSystemProperty(named = "samurai.installed.test", matches = "true")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class LinuxInstalledServiceTest {
    @Test @Order(1) void userControlsOwnTunnelThroughInstalledService() throws Exception {
        assertNotEquals("root", System.getProperty("user.name"), "must run as an ordinary user");
        assertTrue(LinuxClient.daemonAvailable());
        var client = new LinuxClient();
        var own = WireGuardKeys.generate();
        String id = UUID.randomUUID().toString();
        var config = new TunnelProtocol.Configuration("10.203.78.1", 51878, own,
                List.of(new Api.Peer(UUID.randomUUID().toString(), "Friend", WireGuardKeys.generate().publicKey(), "10.203.78.2", "192.0.2.1:51820")));
        var up = client.execute(new TunnelProtocol.Request("up", id, config));
        try {
            assertEquals("up", up.state());
            assertTrue(run("/usr/sbin/ip", "-o", "-4", "addr", "show", "dev", up.interfaceName()).contains("10.203.78.1"));
            assertTrue(run("/usr/sbin/ip", "route", "show", "dev", up.interfaceName()).contains("10.203.78.2"));
            var next = new TunnelProtocol.Configuration("10.203.78.1", 51878, own,
                    List.of(new Api.Peer(UUID.randomUUID().toString(), "Newcomer", WireGuardKeys.generate().publicKey(), "10.203.78.3", "")));
            assertEquals(1, client.execute(new TunnelProtocol.Request("sync", id, next)).peers().size());
            assertFalse(run("/usr/sbin/ip", "route", "show", "dev", up.interfaceName()).contains("10.203.78.2"), "route of a removed member is gone");
        } finally {
            assertEquals("down", client.execute(new TunnelProtocol.Request("down", id, null)).state());
        }
    }
    /** Left running on purpose: the workflow then checks that removing the package deletes it. */
    @Test @Order(2) void tunnelLeftForUninstaller() throws Exception {
        var config = new TunnelProtocol.Configuration("10.203.79.1", 51879, WireGuardKeys.generate(),
                List.of(new Api.Peer(UUID.randomUUID().toString(), "Friend", WireGuardKeys.generate().publicKey(), "10.203.79.2", "")));
        assertEquals("up", new LinuxClient().execute(new TunnelProtocol.Request("up", UUID.randomUUID().toString(), config)).state());
    }
    private static String run(String... command) throws Exception {
        var process = new ProcessBuilder(command).redirectErrorStream(true).start();
        process.getOutputStream().close();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, process.waitFor(), String.join(" ", command) + ": " + output);
        return output;
    }
}
