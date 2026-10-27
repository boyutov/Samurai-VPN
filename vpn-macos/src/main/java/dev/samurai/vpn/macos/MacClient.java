package dev.samurai.vpn.macos;

import dev.samurai.vpn.linux.*;
import java.nio.file.*;

/** Unprivileged GUI bridge to the macOS tunnel service; same socket protocol as samurai-vpnd. */
public final class MacClient implements TunnelBackend {
    public static boolean supported() { return System.getProperty("os.name").startsWith("Mac"); }
    public static boolean serviceAvailable() { return supported() && Files.exists(MacServiceMain.SOCKET); }
    /** Diagnostics for the signed-in user: java -cp samurai-desktop.jar dev.samurai.vpn.macos.MacClient status|down NETWORK_ID */
    public static void main(String[] args) {
        try {
            if (args.length != 2 || !(args[0].equals("status") || args[0].equals("down"))) throw new IllegalArgumentException("Usage: status|down NETWORK_ID");
            var status = new MacClient().execute(new TunnelProtocol.Request(args[0], args[1], null));
            System.out.println(status.state() + " " + status.interfaceName());
        } catch (Exception e) {
            System.err.println("Samurai tunnel: " + e.getMessage());
            System.exit(1);
        }
    }
    public TunnelProtocol.Status execute(TunnelProtocol.Request request) throws Exception {
        return LinuxClient.daemon(MacServiceMain.SOCKET, request);
    }
}
