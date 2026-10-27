package dev.samurai.vpn.desktop;

import dev.samurai.vpn.core.SecretFiles;
import dev.samurai.vpn.server.*;
import java.net.InetSocketAddress;
import java.nio.file.Path;

public final class LocalDemo implements AutoCloseable {
    private final ControlServer server;
    private final DesktopService.Profile profile;
    private LocalDemo(ControlServer server, DesktopService.Profile profile) { this.server = server; this.profile = profile; }
    public static LocalDemo start(Path directory, DesktopService service) throws Exception {
        DesktopService.newDirectory(directory);
        Path admin = directory.resolve("admin.token");
        DesktopService.command(false, "gen-admin", "--out", admin.toString());
        var server = new ControlServer(new InetSocketAddress("127.0.0.1", 0), new NetworkRegistry(SecretFiles.read(admin)), null, true);
        try {
            server.start();
            var alice = service.create(directory.resolve("alice"), "http://127.0.0.1:" + server.port(), true, admin, "Друзья", "Мой компьютер", "");
            Path invite = directory.resolve("friend-invite.json"); service.invite(alice, true, invite);
            service.join(directory.resolve("friend"), invite, true, "Компьютер друга", "");
            return new LocalDemo(server, alice);
        } catch (Exception e) { server.close(); throw e; }
    }
    public DesktopService.Profile profile() { return profile; }
    @Override public void close() { server.close(); }
}
