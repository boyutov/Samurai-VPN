package dev.samurai.vpn.macos;

import dev.samurai.vpn.core.*;
import dev.samurai.vpn.linux.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * The service as native/macos/install-service.sh installs it, used by an ordinary user over
 * its socket; a second account (samurai.other.user, passwordless sudo) must not reach the tunnel.
 * CI only (.github/workflows/verify.yml).
 */
@EnabledOnOs(OS.MAC)
@EnabledIfSystemProperty(named = "samurai.installed.test", matches = "true")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class MacInstalledServiceTest {
    static final String JAVA = "/Library/Application Support/SamuraiVPN/runtime/bin/java",
            JAR = "/Library/Application Support/SamuraiVPN/app/samurai-desktop.jar";

    @Test @Order(1) void userControlsOwnTunnelThroughInstalledService() throws Exception {
        assertNotEquals("root", System.getProperty("user.name"), "must run as an ordinary user");
        assertTrue(MacClient.serviceAvailable());
        var client = new MacClient();
        var own = WireGuardKeys.generate();
        String id = UUID.randomUUID().toString(), friend = WireGuardKeys.generate().publicKey();
        var config = new TunnelProtocol.Configuration("10.203.78.1", 51878, own,
                List.of(new Api.Peer(UUID.randomUUID().toString(), "Friend", friend, "10.203.78.2", "192.0.2.1:51820")));
        var up = client.execute(new TunnelProtocol.Request("up", id, config));
        try {
            assertEquals("up", up.state());
            assertTrue(run(List.of("/sbin/ifconfig", up.interfaceName())).contains("inet 10.203.78.1"));

            // The other account names the same network: the service maps it to that account's own tunnel.
            String other = System.getProperty("samurai.other.user");
            assertEquals("down", run(asOther(other, "status", id)).split(" ")[0]);
            assertEquals("down", run(asOther(other, "down", id)).split(" ")[0]);
            assertEquals("up", client.execute(new TunnelProtocol.Request("status", id, null)).state(), "other account cannot stop our tunnel");

            var next = new TunnelProtocol.Configuration("10.203.78.1", 51878, own,
                    List.of(new Api.Peer(UUID.randomUUID().toString(), "Newcomer", WireGuardKeys.generate().publicKey(), "10.203.78.3", "")));
            assertEquals(1, client.execute(new TunnelProtocol.Request("sync", id, next)).peers().size());
        } finally {
            assertEquals("down", client.execute(new TunnelProtocol.Request("down", id, null)).state());
        }
    }
    private static List<String> asOther(String user, String operation, String id) {
        return List.of("/usr/bin/sudo", "-n", "-u", user, JAVA, "-cp", JAR, "dev.samurai.vpn.macos.MacClient", operation, id);
    }
    /** Left running on purpose: the workflow then checks that the uninstaller stops it. */
    @Test @Order(2) void tunnelLeftForUninstaller() throws Exception {
        var config = new TunnelProtocol.Configuration("10.203.79.1", 51879, WireGuardKeys.generate(),
                List.of(new Api.Peer(UUID.randomUUID().toString(), "Friend", WireGuardKeys.generate().publicKey(), "10.203.79.2", "")));
        assertEquals("up", new MacClient().execute(new TunnelProtocol.Request("up", UUID.randomUUID().toString(), config)).state());
    }
    private static String run(List<String> command) throws Exception {
        // /tmp: the other account may not be allowed into the runner's working directory.
        var process = new ProcessBuilder(command).directory(new java.io.File("/tmp")).redirectErrorStream(true).start();
        process.getOutputStream().close();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, process.waitFor(), String.join(" ", command) + ": " + output);
        return output.strip();
    }
}
