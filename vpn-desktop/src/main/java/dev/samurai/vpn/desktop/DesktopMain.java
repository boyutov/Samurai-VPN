package dev.samurai.vpn.desktop;

import dev.samurai.vpn.core.Arguments;
import java.awt.GraphicsEnvironment;
import java.nio.file.*;
import java.util.Set;
import javax.swing.*;

public final class DesktopMain {
    public static void main(String[] args) {
        try {
            var options = new Arguments(args, 0, Set.of("--help", "--dev", "--demo", "--self-test", "--agent"), Set.of("--data-dir"));
            if (options.has("--help")) {
                System.out.println("Samurai VPN desktop 0.3\n--demo: local two-device demonstration\n--dev: allow loopback HTTP\n--data-dir PATH: profile directory (default: ~/.samurai-vpn)\n--self-test: verify this runtime using temporary local demo files\n--agent: background agent for connected networks (started by the window)");
                return;
            }
            if (options.has("--self-test")) { selfTest(); return; }
            Path data = Path.of(options.get("--data-dir", Path.of(System.getProperty("user.home"), ".samurai-vpn").toString())).toAbsolutePath();
            if (options.has("--agent")) {
                // No window, no Dock icon: the agent never touches AWT.
                System.setProperty("java.awt.headless", "true");
                System.exit(BackgroundAgent.run(data));
            }
            if (GraphicsEnvironment.isHeadless()) throw new IllegalStateException("A graphical desktop is required.");
            Theme.install();
            SwingUtilities.invokeLater(() -> {
                var window = new MainWindow(data, options.has("--dev")); window.setVisible(true);
                if (options.has("--demo")) window.startDemo();
            });
        } catch (Exception e) { System.err.println("Cannot start Samurai VPN: " + e.getMessage()); System.exit(1); }
    }
    private static void selfTest() throws Exception {
        Path temporary = Files.createTempDirectory("samurai-runtime-check-");
        try {
            var service = new DesktopService();
            try (var demo = LocalDemo.start(temporary.resolve("demo"), service)) {
                if (service.refresh(demo.profile(), true).peers().size() != 2) throw new IllegalStateException("Demo membership failed");
                service.export(demo.profile(), true, 51820, temporary.resolve("test.conf"));
                // Check providers needed by HTTPS and PKCS12, even though demo uses loopback HTTP.
                javax.net.ssl.SSLContext.getDefault();
                java.security.KeyStore.getInstance("PKCS12");
                System.out.println("Runtime self-test passed: keys, two devices, HTTP, TLS provider, profile export.");
            }
        } finally {
            try (var paths = Files.walk(temporary)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }
}
