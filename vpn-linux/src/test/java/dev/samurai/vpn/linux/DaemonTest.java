package dev.samurai.vpn.linux;

import dev.samurai.vpn.core.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

// Also runs on macOS (CI): proves the JDK exposes the caller UID there, which the macOS service relies on.
@EnabledOnOs({OS.LINUX, OS.MAC})
class DaemonTest {
    @TempDir Path folder;
    @Test void callerUidComesFromKernelAndErrorsStaySanitised() throws Exception {
        Path socket = folder.resolve("daemon.sock");
        var seen = new AtomicLong(-1);
        String id = UUID.randomUUID().toString();
        try (var daemon = new Daemon(socket, (uid, request) -> {
            seen.set(uid);
            if (request.operation().equals("down")) throw new IllegalStateException("secret internal detail");
            return new TunnelProtocol.Status("up", "smtest", 0, 0, 0);
        })) {
            Thread.ofPlatform().daemon().start(daemon::serve);
            var client = new LinuxClient(socket);
            assertEquals("up", client.execute(new TunnelProtocol.Request("status", id, null)).state());
            long own = (Integer) Files.getAttribute(folder, "unix:uid"); // the temp folder was created by this process
            assertEquals(own, seen.get());
            var error = assertThrows(Exception.class, () -> client.execute(new TunnelProtocol.Request("down", id, null)));
            assertFalse(error.getMessage().contains("secret"));
            assertThrows(IllegalArgumentException.class, () -> client.execute(new TunnelProtocol.Request("endpoint", id, null, WireGuardKeys.generate().publicKey(), "10.203.1.9:5")));
            Files.setPosixFilePermissions(folder, java.nio.file.attribute.PosixFilePermissions.fromString("rwxrwxrwx"));
            assertThrows(Exception.class, () -> client.execute(new TunnelProtocol.Request("status", id, null)), "world-writable socket directory is refused");
        }
    }
}
