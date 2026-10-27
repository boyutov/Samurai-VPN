package dev.samurai.vpn.macos;

import dev.samurai.vpn.linux.*;
import java.nio.file.*;

/** Unprivileged GUI bridge to the macOS tunnel service; same socket protocol as samurai-vpnd. */
public final class MacClient implements TunnelBackend {
    public static boolean supported() { return System.getProperty("os.name").startsWith("Mac"); }
    public static boolean serviceAvailable() { return supported() && Files.exists(MacServiceMain.SOCKET); }
    public TunnelProtocol.Status execute(TunnelProtocol.Request request) throws Exception {
        return LinuxClient.daemon(MacServiceMain.SOCKET, request);
    }
}
