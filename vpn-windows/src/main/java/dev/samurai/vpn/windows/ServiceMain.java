package dev.samurai.vpn.windows;

import dev.samurai.vpn.linux.*;
import java.nio.file.*;
import java.time.Duration;

/**
 * Entry point of the Samurai tunnel service, started as SYSTEM by a scheduled task
 * (native/windows/install-service.ps1). Windows gives an AF_UNIX server no caller identity,
 * so the socket directory admits exactly one user: the one named at installation.
 */
public final class ServiceMain {
    public static final Path ROOT = Path.of("C:\\ProgramData\\SamuraiVPN");
    public static final Path TUNNELS = ROOT.resolve("tunnels"), SOCKET = ROOT.resolve("run").resolve("service.sock");
    private ServiceMain() {}
    public static void main(String[] args) {
        try {
            if (args.length != 0 || !System.getProperty("os.name").startsWith("Windows")) throw new IllegalArgumentException("The service takes no arguments");
            for (Path directory : new Path[]{TUNNELS, SOCKET.getParent()})
                if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) throw new IllegalStateException("Run install-service.ps1 first: " + directory + " is missing");
            // Only SYSTEM may delete in the run directory, so a leftover socket is ours from a previous run.
            Files.deleteIfExists(SOCKET);
            var runner = new CommandRunner.SystemRunner(Duration.ofSeconds(20));
            var engine = new WindowsEngine(runner, TUNNELS);
            // Every caller is the installed user; the uid argument only exists for the Linux per-user naming.
            try (var daemon = new Daemon(SOCKET, (uid, request) -> engine.execute(request), channel -> 0, false)) {
                System.out.println("Samurai tunnel service listening on " + SOCKET);
                daemon.serve();
            }
        } catch (Exception e) {
            System.err.println("Samurai tunnel service failed: " + e.getMessage());
            System.exit(1);
        }
    }
}
