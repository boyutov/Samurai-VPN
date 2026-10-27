package dev.samurai.vpn.desktop;

import dev.samurai.vpn.linux.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/**
 * No window at all: a tunnel through the installed service, kept current by the agent running as
 * a separate process. Needs the installed tunnel service; CI only (.github/workflows/verify.yml).
 */
@EnabledOnOs({OS.WINDOWS, OS.MAC})
@EnabledIfSystemProperty(named = "samurai.installed.test", matches = "true")
class AgentInstalledTest {
    @TempDir Path folder;

    @Test void agentAppliesMembershipChangesWithoutWindow() throws Exception {
        assertTrue(NativeTunnel.resident(), "installed tunnel service");
        var service = new DesktopService();
        var tunnel = NativeTunnel.client();
        Path data = folder.resolve("data");
        var files = new AgentFiles(data);
        try (var demo = LocalDemo.start(folder.resolve("demo"), service)) {
            var owner = demo.profile();
            String id = owner.session().membership().networkId();
            assertEquals("up", tunnel.execute(service.prepareTunnel(owner, true, 51880)).state());
            try {
                files.update(owner, true, true);
                AgentProcess.ensureRunning(data);
                await(() -> running(files), "agent process started");

                Path invite = folder.resolve("invite.json");
                service.invite(owner, true, invite);
                var newcomer = service.join(folder.resolve("newcomer"), invite, true, "Newcomer", "");
                String key = newcomer.session().identity().publicKey();
                await(() -> keys(tunnel, id).contains(key), "agent added the new member to the running tunnel");
                await(() -> files.network(owner).map(n -> n.up() && n.peers().size() == 3).orElse(false), "agent reports the network");

                service.revoke(owner, true, newcomer.session().membership().peerId());
                await(() -> !keys(tunnel, id).contains(key), "agent removed the revoked member");
                assertEquals("up", tunnel.execute(new TunnelProtocol.Request("status", id, null)).state());

                files.update(owner, true, false);
                await(() -> !running(files), "agent exits when nothing is registered");
            } finally {
                files.update(owner, true, false);
                tunnel.execute(new TunnelProtocol.Request("down", id, null));
            }
        }
        if (Files.exists(files.log())) System.out.println("agent.log:\n" + Files.readString(files.log()));
    }
    @Test void loginItemIsRegisteredAndRemoved() throws Exception {
        Path data = folder.resolve("data");
        AgentProcess.autostart(data, false); // removing an absent item is not an error
        try {
            AgentProcess.autostart(data, true);
            String item = loginItem();
            assertTrue(item.contains(data.toAbsolutePath().toString()), item);
        } catch (Throwable failure) {
            // Keep the first failure visible; cleanup problems are attached to it.
            try { AgentProcess.autostart(data, false); } catch (Exception cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
        AgentProcess.autostart(data, false);
        assertFalse(loginItem().contains(data.toAbsolutePath().toString()));
    }

    private static String loginItem() throws Exception {
        if (NativeTunnel.MAC) {
            Path plist = Path.of(System.getProperty("user.home"), "Library", "LaunchAgents", AgentProcess.LABEL + ".plist");
            return Files.exists(plist) ? Files.readString(plist) : "";
        }
        var process = new ProcessBuilder("reg.exe", "query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", "SamuraiVPNAgent")
                .redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes());
        return process.waitFor() == 0 ? output : "";
    }
    private static boolean running(AgentFiles files) {
        try { return files.agentRunning(); } catch (Exception e) { return false; }
    }
    private static Set<String> keys(TunnelBackend tunnel, String id) throws Exception {
        var keys = new HashSet<String>();
        for (var peer : tunnel.execute(new TunnelProtocol.Request("status", id, null)).peers()) keys.add(peer.publicKey());
        return keys;
    }
    private interface Check { boolean done() throws Exception; }
    private static void await(Check check, String what) throws Exception {
        long deadline = System.nanoTime() + 90_000_000_000L; // membership is fetched every 30 s
        while (System.nanoTime() < deadline) {
            if (check.done()) return;
            Thread.sleep(1000);
        }
        fail("Timed out: " + what);
    }
}
