package dev.samurai.vpn.macos;

import dev.samurai.vpn.linux.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;

/**
 * Entry point of the macOS tunnel service; launchd runs it as root (native/macos/install-service.sh).
 * The caller UID comes from the kernel via LOCAL_PEERCRED, as on Linux; each user reaches only
 * tunnels named after its own UID.
 */
public final class MacServiceMain {
    public static final Path SOCKET = Path.of("/var/run/samurai-vpnd/daemon.sock");
    static final Path STATE = Path.of("/var/run/samurai-vpn"), SOCKETS = Path.of("/var/run/wireguard");
    private MacServiceMain() {}
    public static void main(String[] args) {
        try {
            if (args.length != 0 || !System.getProperty("os.name").startsWith("Mac")) throw new IllegalArgumentException("The service takes no arguments");
            // /var/run is cleared at boot; recreate root-owned directories (state stays private, the socket's is listable).
            for (var entry : new Object[][]{{STATE, "rwx------"}, {SOCKET.getParent(), "rwxr-xr-x"}, {SOCKETS, null}}) {
                Path directory = (Path) entry[0];
                Files.createDirectories(directory);
                if (Files.isSymbolicLink(directory) || (Integer) Files.getAttribute(directory, "unix:uid", LinkOption.NOFOLLOW_LINKS) != 0)
                    throw new IllegalStateException("Unsafe service directory " + directory);
                // wireguard-go's directory is shared with other WireGuard tools: only its owner is checked.
                if (entry[1] != null) Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString((String) entry[1]));
            }
            var runner = new CommandRunner.SystemRunner(Duration.ofSeconds(8));
            try (var daemon = new Daemon(SOCKET, (uid, request) -> new MacEngine(runner, uid, STATE, SOCKETS).execute(request), Daemon::peerUid, true)) {
                System.out.println("Samurai tunnel service listening on " + SOCKET);
                daemon.serve();
            }
        } catch (Exception e) {
            System.err.println("Samurai tunnel service failed: " + e.getMessage());
            System.exit(1);
        }
    }
}
