package dev.samurai.vpn.windows;

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
 * Real WireGuard for Windows, real routes: needs an administrator and an installed WireGuard,
 * as on the CI runner (.github/workflows/verify.yml). Never run it on a machine in use.
 */
@EnabledOnOs(OS.WINDOWS)
@EnabledIfSystemProperty(named = "samurai.system.test", matches = "true")
class WindowsSystemTest {
    @TempDir Path tunnels;
    // The service's budget. Failures name the command and its stderr: keys only ever travel on stdin.
    private final CommandRunner runner = (command, input) -> {
        var result = new CommandRunner.SystemRunner(Duration.ofSeconds(20)).result(command, input);
        if (result.exitCode() != 0) throw new java.io.IOException(String.join(" ", command.subList(0, Math.min(3, command.size())))
                + " exit " + result.exitCode() + ": " + result.errors().strip() + " " + result.output().strip());
        return result.output();
    };
    private final WireGuardKeys.Identity own = WireGuardKeys.generate();
    private final String friend = WireGuardKeys.generate().publicKey(), newcomer = WireGuardKeys.generate().publicKey();

    @Test void routeQueryFinishesInTime() throws Exception {
        // Diagnostic for the service's 20 s budget: the same script with the cleared and with the inherited environment.
        long start = System.nanoTime();
        var cleared = new CommandRunner.SystemRunner(Duration.ofSeconds(180)).result(powershell(), "");
        long clearedMs = (System.nanoTime() - start) / 1_000_000;
        start = System.nanoTime();
        var inherited = new ProcessBuilder(powershell()).redirectErrorStream(true).start();
        inherited.getOutputStream().close();
        String output = new String(inherited.getInputStream().readAllBytes());
        long inheritedMs = (System.nanoTime() - start) / 1_000_000;
        System.out.println("ROUTES cleared env: " + clearedMs + " ms, exit " + cleared.exitCode() + ", stderr: " + cleared.errors().strip()
                + "\nROUTES inherited env: " + inheritedMs + " ms, exit " + inherited.waitFor() + ", output " + output.length() + " chars");
        assertEquals(0, cleared.exitCode(), cleared.errors());
        assertTrue(clearedMs < 10_000, "route query took " + clearedMs + " ms");
    }
    private static List<String> powershell() {
        return List.of(WindowsEngine.POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", WindowsEngine.ROUTES);
    }
    @Test void tunnelServiceRoutesSyncAndCleanup() throws Exception {
        var engine = new WindowsEngine(runner, tunnels);
        String id = UUID.randomUUID().toString(), name = WindowsEngine.tunnelName(id);
        var config = new TunnelProtocol.Configuration("10.203.77.1", 51877, own,
                List.of(new Api.Peer(UUID.randomUUID().toString(), "Friend", friend, "10.203.77.2", "192.0.2.1:51820")));
        try {
            assertEquals("up", engine.execute(new TunnelProtocol.Request("up", id, config)).state());
            assertEquals(own.publicKey(), wg(name, "public-key").strip());
            assertTrue(hasRoute("10.203.77.2", name), "member route on the tunnel");
            assertFalse(hasRoute("0.0.0.0/0", name), "no default route through the tunnel");

            engine.execute(new TunnelProtocol.Request("endpoint", id, null, friend, "198.51.100.20:61000"));
            assertTrue(wg(name, "endpoints").contains("198.51.100.20:61000"));

            var next = new TunnelProtocol.Configuration("10.203.77.1", 51877, own,
                    List.of(new Api.Peer(UUID.randomUUID().toString(), "Newcomer", newcomer, "10.203.77.3", "")));
            engine.execute(new TunnelProtocol.Request("sync", id, next));
            String peers = wg(name, "allowed-ips");
            assertTrue(peers.contains(newcomer) && !peers.contains(friend), peers);
            assertTrue(hasRoute("10.203.77.3", name));
            assertFalse(hasRoute("10.203.77.2", name), "route of a removed member is gone");
            assertTrue(Files.readString(tunnels.resolve(name + ".conf")).contains(newcomer), "config follows sync for the next service start");
        } catch (Throwable failure) {
            // Keep the first failure visible; cleanup problems are attached to it.
            try { engine.execute(new TunnelProtocol.Request("down", id, null)); } catch (Exception cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
        assertEquals("down", engine.execute(new TunnelProtocol.Request("down", id, null)).state());
        assertEquals("down", engine.execute(new TunnelProtocol.Request("status", id, null)).state());
        assertThrows(Exception.class, () -> runner.run(List.of(WindowsEngine.SC, "query", "WireGuardTunnel$" + name), ""), "service removed");
        assertFalse(Files.exists(tunnels.resolve(name + ".conf")));
    }
    private String wg(String name, String field) throws Exception { return runner.run(List.of(WindowsEngine.WG, "show", name, field), ""); }
    private boolean hasRoute(String destination, String name) throws Exception {
        var routes = Json.MAPPER.readTree(new CommandRunner.SystemRunner(Duration.ofSeconds(180)).run(powershell(), ""));
        String prefix = destination.contains("/") ? destination : destination + "/32";
        for (var route : routes) if (route.path("dst").asText().equals(prefix) && route.path("dev").asText().equals(name)) return true;
        return false;
    }
}
