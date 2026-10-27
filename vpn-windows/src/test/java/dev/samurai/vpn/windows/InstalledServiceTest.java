package dev.samurai.vpn.windows;

import dev.samurai.vpn.core.*;
import dev.samurai.vpn.linux.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * The service as native/windows/install-service.ps1 installs it (scheduled task as SYSTEM),
 * used over its socket like the window does. CI only (.github/workflows/verify.yml).
 */
@EnabledOnOs(OS.WINDOWS)
@EnabledIfSystemProperty(named = "samurai.installed.test", matches = "true")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class InstalledServiceTest {
    @Test @Order(1) void tunnelThroughInstalledService() throws Exception {
        assertTrue(WindowsClient.serviceAvailable());
        var client = new WindowsClient();
        var runner = new CommandRunner.SystemRunner(Duration.ofSeconds(20));
        var own = WireGuardKeys.generate();
        String id = UUID.randomUUID().toString(), name = WindowsEngine.tunnelName(id);
        var config = new TunnelProtocol.Configuration("10.203.78.1", 51878, own,
                List.of(new Api.Peer(UUID.randomUUID().toString(), "Friend", WireGuardKeys.generate().publicKey(), "10.203.78.2", "192.0.2.1:51820")));
        try {
            assertEquals("up", client.execute(new TunnelProtocol.Request("up", id, config)).state());
            assertEquals(own.publicKey(), runner.run(List.of(WindowsEngine.WG, "show", name, "public-key"), "").strip());
            assertTrue(Files.isRegularFile(ServiceMain.TUNNELS.resolve(name + ".conf")), "configuration kept by the service");
            var next = new TunnelProtocol.Configuration("10.203.78.1", 51878, own,
                    List.of(new Api.Peer(UUID.randomUUID().toString(), "Newcomer", WireGuardKeys.generate().publicKey(), "10.203.78.3", "")));
            assertEquals(1, client.execute(new TunnelProtocol.Request("sync", id, next)).peers().size());
        } finally {
            assertEquals("down", client.execute(new TunnelProtocol.Request("down", id, null)).state());
        }
        assertFalse(Files.exists(ServiceMain.TUNNELS.resolve(name + ".conf")));
    }
    /** Left running on purpose: the workflow then checks that the uninstaller stops it. */
    @Test @Order(2) void tunnelLeftForUninstaller() throws Exception {
        var config = new TunnelProtocol.Configuration("10.203.79.1", 51879, WireGuardKeys.generate(),
                List.of(new Api.Peer(UUID.randomUUID().toString(), "Friend", WireGuardKeys.generate().publicKey(), "10.203.79.2", "")));
        assertEquals("up", new WindowsClient().execute(new TunnelProtocol.Request("up", UUID.randomUUID().toString(), config)).state());
    }
}
