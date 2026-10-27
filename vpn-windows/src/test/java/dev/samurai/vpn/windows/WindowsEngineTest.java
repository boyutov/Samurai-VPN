package dev.samurai.vpn.windows;

import dev.samurai.vpn.core.*;
import dev.samurai.vpn.linux.*;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Runs everywhere: Windows commands are answered by a fake that models WireGuard for Windows. */
class WindowsEngineTest {
    private final String id = UUID.randomUUID().toString(), name = WindowsEngine.tunnelName(id);
    private final WireGuardKeys.Identity own = WireGuardKeys.generate(), friend = WireGuardKeys.generate();
    @TempDir Path tunnels;
    private final Fake fake = new Fake();
    private WindowsEngine engine() { return new WindowsEngine(fake, tunnels); }
    private Path conf() { return tunnels.resolve(name + ".conf"); }
    private TunnelProtocol.Configuration config(Api.Peer... peers) {
        return new TunnelProtocol.Configuration("10.203.1.1", 51820, own, peers.length == 0
                ? List.of(new Api.Peer(UUID.randomUUID().toString(), "Friend", friend.publicKey(), "10.203.1.2", "192.0.2.2:51820")) : List.of(peers));
    }
    private TunnelProtocol.Status run(String operation, TunnelProtocol.Configuration config) throws Exception {
        return engine().execute(new TunnelProtocol.Request(operation, id, config));
    }

    @Test void tunnelNameFitsWireGuardForWindows() {
        assertTrue(name.matches("samurai[0-9a-f]{12}") && name.length() <= 32);
        assertNotEquals(name, WindowsEngine.tunnelName(UUID.randomUUID().toString()));
    }
    @Test void upInstallsTunnelServiceFromProtectedConfigurationAndDownRemovesIt() throws Exception {
        assertEquals("up", run("up", config()).state());
        String text = Files.readString(conf());
        assertTrue(text.contains("PrivateKey = " + own.privateKey()) && text.contains("Address = 10.203.1.1/32") && text.contains("MTU = 1280"));
        assertTrue(text.contains("AllowedIPs = 10.203.1.2/32") && !text.contains("0.0.0.0/0") && !text.contains("DNS"));
        assertTrue(fake.commands.contains(List.of(WindowsEngine.WIREGUARD, "/installtunnelservice", conf().toString())));
        // The private key is only in the protected file, never in a command line.
        assertTrue(fake.commands.stream().noneMatch(c -> c.stream().anyMatch(s -> s.contains(own.privateKey()))));
        assertThrows(IOException.class, () -> run("up", config()), "second up while connected");

        assertEquals("down", run("down", null).state());
        assertTrue(fake.commands.contains(List.of(WindowsEngine.WIREGUARD, "/uninstalltunnelservice", name)));
        assertFalse(Files.exists(conf()));
        assertEquals("down", run("down", null).state(), "disconnect is idempotent");
    }
    @Test void failedStartRemovesServiceAndConfiguration() throws Exception {
        fake.startFails = true;
        assertThrows(IOException.class, () -> run("up", config()));
        assertFalse(fake.service);
        assertFalse(Files.exists(conf()));
        assertTrue(fake.commands.contains(List.of(WindowsEngine.WIREGUARD, "/uninstalltunnelservice", name)));
    }
    @Test void foreignTunnelWithTheSameNameIsNeverTouched() throws Exception {
        fake.service = true; // installed by someone else: no configuration in Samurai's directory
        assertThrows(IOException.class, () -> run("up", config()));
        assertThrows(IOException.class, () -> run("down", null));
        assertThrows(IOException.class, () -> run("status", null));
        assertTrue(fake.commands.stream().noneMatch(c -> c.contains("/uninstalltunnelservice") || c.contains("/installtunnelservice")));
    }
    @Test void routeConflictsStopBeforeAnythingIsCreated() throws Exception {
        for (String routes : List.of("[{\"dst\":\"10.203.0.0/16\",\"dev\":\"Ethernet\"}]", "[{\"dst\":\"10.203.1.2/32\",\"dev\":\"Other VPN\"}]")) {
            fake.routes = routes;
            assertThrows(IOException.class, () -> run("up", config()));
        }
        fake.routes = "[{\"dst\":\"0.0.0.0/0\",\"dev\":\"Wi-Fi\"},{\"dst\":\"192.168.1.0/24\",\"dev\":\"Wi-Fi\"}]";
        fake.addresses = "[{\"ifname\":\"Wi-Fi\",\"addr_info\":[{\"family\":\"inet\",\"local\":\"10.203.1.50\",\"prefixlen\":24}]}]";
        assertThrows(IOException.class, () -> run("up", config()), "local address inside the network");
        assertFalse(Files.exists(conf()));
        assertTrue(fake.commands.stream().noneMatch(c -> c.contains("/installtunnelservice")));
        fake.addresses = "[]";
        assertEquals("up", run("up", config()).state(), "default and LAN routes are fine");
    }
    @Test void statusAndEndpointUseWgShowOnOwnedTunnelOnly() throws Exception {
        String key = friend.publicKey(), stranger = WireGuardKeys.generate().publicKey();
        assertThrows(IOException.class, () -> engine().execute(new TunnelProtocol.Request("endpoint", id, null, key, "198.51.100.20:61000")));
        run("up", config());
        fake.show = Map.of("latest-handshakes", key + "\t1700000000\n", "transfer", key + "\t4096\t2048\n",
                "endpoints", key + "\t203.0.113.10:40001\n", "peers", key + "\n");
        var state = run("status", null);
        assertEquals(1700000000L, state.latestHandshake());
        assertEquals(List.of(new TunnelProtocol.PeerState(key, "203.0.113.10:40001", 1700000000L, 4096)), state.peers());
        engine().execute(new TunnelProtocol.Request("endpoint", id, null, key, "198.51.100.20:61000"));
        assertTrue(fake.commands.contains(List.of(WindowsEngine.WG, "set", name, "peer", key, "endpoint", "198.51.100.20:61000")));
        assertThrows(IOException.class, () -> engine().execute(new TunnelProtocol.Request("endpoint", id, null, stranger, "198.51.100.20:61000")));
    }
    @Test void syncChangesMembershipRoutesAndConfigurationOfRunningTunnel() throws Exception {
        var newcomer = WireGuardKeys.generate();
        var next = config(new Api.Peer(UUID.randomUUID().toString(), "Newcomer", newcomer.publicKey(), "10.203.1.3", "203.0.113.10:40003"));
        assertThrows(IOException.class, () -> run("sync", next), "no running tunnel");
        run("up", config());
        fake.show = Map.of("public-key", own.publicKey() + "\n", "allowed-ips", friend.publicKey() + "\t10.203.1.2/32\n");
        fake.routes = "[{\"dst\":\"10.203.1.2/32\",\"dev\":\"" + name + "\"}]"; // own routes never block a sync
        fake.addRoutes = true;
        int before = fake.commands.size();
        run("sync", next);
        var issued = fake.commands.subList(before, fake.commands.size());
        assertTrue(issued.contains(List.of(WindowsEngine.NETSH, "interface", "ipv4", "delete", "route", "prefix=10.203.1.2/32", "interface=" + name, "store=active")));
        assertTrue(issued.contains(List.of(WindowsEngine.WG, "set", name, "peer", friend.publicKey(), "remove")));
        assertTrue(issued.contains(List.of(WindowsEngine.WG, "set", name, "peer", newcomer.publicKey(), "allowed-ips", "10.203.1.3/32",
                "endpoint", "203.0.113.10:40003", "persistent-keepalive", "25")));
        assertTrue(issued.contains(List.of(WindowsEngine.NETSH, "interface", "ipv4", "add", "route", "prefix=10.203.1.3/32", "interface=" + name, "store=active")));
        String text = Files.readString(conf());
        assertTrue(text.contains(newcomer.publicKey()) && !text.contains(friend.publicKey()), "a restarted service keeps the new membership");
        assertFalse(Files.exists(tunnels.resolve(name + ".conf.tmp")));

        fake.addRoutes = false; // route never appears: the new peer must not stay without it
        var third = WireGuardKeys.generate();
        fake.show = Map.of("public-key", own.publicKey() + "\n", "allowed-ips", newcomer.publicKey() + "\t10.203.1.3/32\n");
        assertThrows(IOException.class, () -> run("sync", config(next.peers().getFirst(),
                new Api.Peer(UUID.randomUUID().toString(), "Third", third.publicKey(), "10.203.1.4", ""))));
        assertTrue(fake.commands.contains(List.of(WindowsEngine.WG, "set", name, "peer", third.publicKey(), "remove")));

        fake.show = Map.of("public-key", WireGuardKeys.generate().publicKey() + "\n");
        assertThrows(IOException.class, () -> run("sync", next), "other identity");
    }

    /** Models sc.exe, wireguard.exe, wg.exe, netsh.exe and the two PowerShell queries. */
    private final class Fake implements CommandRunner {
        final List<List<String>> commands = new ArrayList<>();
        boolean service, startFails, addRoutes;
        String routes = "[]", addresses = "[]";
        Map<String, String> show = Map.of();
        public String run(List<String> command, String input) throws Exception {
            commands.add(List.copyOf(command));
            String program = command.getFirst();
            if (program.equals(WindowsEngine.SC)) { if (!service) throw new IOException("1060"); return "RUNNING"; }
            if (program.equals(WindowsEngine.WIREGUARD) && command.get(1).equals("/installtunnelservice")) {
                assertTrue(Files.readString(Path.of(command.get(2))).contains("[Interface]"), "configuration exists before the service starts");
                service = true;
                if (startFails) throw new IOException("service failed to start");
                return "";
            }
            if (program.equals(WindowsEngine.WIREGUARD) && command.get(1).equals("/uninstalltunnelservice")) { service = false; return ""; }
            if (program.equals(WindowsEngine.POWERSHELL)) return command.getLast().contains("Get-NetRoute") ? routes : addresses;
            if (program.equals(WindowsEngine.NETSH) && command.contains("add") && addRoutes) {
                String prefix = command.get(5).substring("prefix=".length());
                routes = routes.substring(0, routes.length() - 1) + (routes.equals("[]") ? "" : ",") + "{\"dst\":\"" + prefix + "\",\"dev\":\"" + name + "\"}]";
            }
            if (program.equals(WindowsEngine.WG) && command.get(1).equals("show")) return show.getOrDefault(command.get(3), "");
            return "";
        }
    }
}
