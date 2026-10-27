package dev.samurai.vpn.windows;

import dev.samurai.vpn.core.*;
import dev.samurai.vpn.linux.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** The client and the service as ServiceMain wires them, over a real AF_UNIX socket (Windows 10+ and Linux). */
class WindowsClientTest {
    @TempDir Path folder;
    @Test void clientTalksToServiceAndSeesOnlySanitisedErrors() throws Exception {
        Path socket = folder.resolve("service.sock");
        String id = UUID.randomUUID().toString();
        var client = new WindowsClient(socket);
        assertThrows(Exception.class, () -> client.execute(new TunnelProtocol.Request("status", id, null)), "service not running");
        try (var daemon = new Daemon(socket, (uid, request) -> {
            assertEquals(0, uid);
            if (request.operation().equals("down")) throw new IllegalStateException("secret internal detail");
            return new TunnelProtocol.Status("up", WindowsEngine.tunnelName(id), 0, 0, 0);
        }, channel -> 0, false)) {
            Thread.ofPlatform().daemon().start(daemon::serve);
            assertEquals(WindowsEngine.tunnelName(id), client.execute(new TunnelProtocol.Request("status", id, null)).interfaceName());
            var error = assertThrows(Exception.class, () -> client.execute(new TunnelProtocol.Request("down", id, null)));
            assertFalse(error.getMessage().contains("secret"));
            assertThrows(IllegalArgumentException.class, () -> client.execute(new TunnelProtocol.Request("shell", id, null)), "validated before sending");
        }
    }
}
