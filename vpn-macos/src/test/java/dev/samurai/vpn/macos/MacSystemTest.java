package dev.samurai.vpn.macos;

import dev.samurai.vpn.core.*;
import dev.samurai.vpn.linux.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Real wireguard-go, ifconfig and route: needs root and the tool copies the installer makes,
 * as on the CI runner (.github/workflows/verify.yml). Never run it on a machine in use.
 */
@EnabledOnOs(OS.MAC)
@EnabledIfSystemProperty(named = "samurai.system.test", matches = "true")
class MacSystemTest {
    @TempDir Path state;
    private final CommandRunner runner = new CommandRunner.SystemRunner(Duration.ofSeconds(20));
    private final WireGuardKeys.Identity own = WireGuardKeys.generate();
    private final String friend = WireGuardKeys.generate().publicKey(), newcomer = WireGuardKeys.generate().publicKey();

    @Test void wireguardGoRoutesSyncAndCleanup() throws Exception {
        Path sockets = Path.of("/var/run/wireguard");
        Files.createDirectories(sockets);
        var engine = new MacEngine(runner, 501, state, sockets);
        String id = UUID.randomUUID().toString();
        var config = new TunnelProtocol.Configuration("10.203.77.1", 51877, own,
                List.of(new Api.Peer(UUID.randomUUID().toString(), "Friend", friend, "10.203.77.2", "192.0.2.1:51820")));
        String device;
        try {
            var up = engine.execute(new TunnelProtocol.Request("up", id, config));
            assertEquals("up", up.state());
            device = up.interfaceName();
            assertTrue(device.matches("utun[0-9]+"), device);
            assertEquals(own.publicKey(), wg(device, "public-key").strip());
            assertTrue(runner.run(List.of(MacEngine.IFCONFIG, device), "").contains("inet 10.203.77.1"));
            assertTrue(hasRoute("10.203.77.2", device), () -> "member route on the tunnel:\n" + netstat());
            assertEquals("up", engine.execute(new TunnelProtocol.Request("status", id, null)).state(), "wireguard-go survives the starting shell");

            engine.execute(new TunnelProtocol.Request("endpoint", id, null, friend, "198.51.100.20:61000"));
            assertTrue(wg(device, "endpoints").contains("198.51.100.20:61000"));

            var next = new TunnelProtocol.Configuration("10.203.77.1", 51877, own,
                    List.of(new Api.Peer(UUID.randomUUID().toString(), "Newcomer", newcomer, "10.203.77.3", "")));
            engine.execute(new TunnelProtocol.Request("sync", id, next));
            String peers = wg(device, "allowed-ips");
            assertTrue(peers.contains(newcomer) && !peers.contains(friend), peers);
            assertTrue(hasRoute("10.203.77.3", device));
            assertFalse(hasRoute("10.203.77.2", device), "route of a removed member is gone");
        } finally {
            assertEquals("down", engine.execute(new TunnelProtocol.Request("down", id, null)).state());
        }
        // wireguard-go notices its removed control socket and closes the utun.
        boolean gone = false;
        for (int i = 0; i < 50 && !gone; i++) {
            try { runner.run(List.of(MacEngine.IFCONFIG, device), ""); Thread.sleep(200); } catch (Exception e) { gone = true; }
        }
        assertTrue(gone, "utun removed after down");
        assertEquals("down", engine.execute(new TunnelProtocol.Request("status", id, null)).state());
    }
    private String wg(String device, String field) throws Exception { return runner.run(List.of(MacEngine.WG, "show", device, field), ""); }
    private String netstat() {
        try { return runner.run(List.of(MacEngine.NETSTAT, "-rn", "-f", "inet"), ""); } catch (Exception e) { return e.toString(); }
    }
    private boolean hasRoute(String address, String device) {
        // Same parsing as RouteGuard input: netstat may print a host route as "a.b.c.d" or "a.b.c.d/32".
        return netstat().lines().map(line -> line.strip().split("\\s+"))
                .filter(f -> f.length >= 4 && f[0].matches("[0-9./]+") && f[3].equals(device))
                .anyMatch(f -> MacNetwork.prefix(f[0]).equals(address + "/32"));
    }
}
