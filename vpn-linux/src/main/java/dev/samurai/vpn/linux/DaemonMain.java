package dev.samurai.vpn.linux;

import java.nio.file.*;
import java.time.Duration;

/** Entry point of samurai-vpnd; systemd grants it CAP_NET_ADMIN only (native/linux/samurai-vpnd.service). */
public final class DaemonMain {
    public static final Path SOCKET = Path.of("/run/samurai-vpnd/daemon.sock");
    private DaemonMain() {}
    public static void main(String[] args) {
        try {
            if (args.length != 0 || !System.getProperty("os.name").equals("Linux")) throw new IllegalArgumentException("samurai-vpnd takes no arguments");
            var runner = new CommandRunner.SystemRunner(Duration.ofSeconds(8));
            try (var daemon = new Daemon(SOCKET, (uid, request) -> new LinuxEngine(runner, uid).execute(request))) {
                System.out.println("samurai-vpnd listening on " + SOCKET);
                daemon.serve();
            }
        } catch (Exception e) {
            System.err.println("samurai-vpnd failed: " + e.getMessage());
            System.exit(1);
        }
    }
}
