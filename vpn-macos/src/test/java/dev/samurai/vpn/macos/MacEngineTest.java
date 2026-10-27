package dev.samurai.vpn.macos;

import dev.samurai.vpn.core.*;
import dev.samurai.vpn.linux.*;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Runs everywhere: macOS commands are answered by a fake that models wireguard-go, wg, ifconfig, route and netstat. */
class MacEngineTest {
    // Shapes copied from macOS 14: abbreviated networks, link# gateways, utun interfaces.
    static final String NETSTAT = """
            Routing tables

            Internet:
            Destination        Gateway            Flags               Netif Expire
            default            192.168.1.1        UGScg                 en0
            127                127.0.0.1          UCS                   lo0
            127.0.0.1          127.0.0.1          UH                    lo0
            169.254            link#6             UCS                   en0      !
            192.168.1          link#6             UCS                   en0      !
            192.168.1.1/32     link#6             UCS                   en0      !
            224.0.0/4          link#6             UmCS                  en0      !
            255.255.255.255/32 link#6             UCS                   en0      !
            """;
    static final String IFCONFIG = """
            lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
            \toptions=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
            \tinet 127.0.0.1 netmask 0xff000000
            \tinet6 ::1 prefixlen 128
            en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
            \tether 3c:22:fb:00:00:01
            \tinet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
            utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
            \tinet6 fe80::1%utun3 prefixlen 64 scopeid 0x10
            """;
    private final String id = UUID.randomUUID().toString();
    private final WireGuardKeys.Identity own = WireGuardKeys.generate(), friend = WireGuardKeys.generate();
    @TempDir Path temp;
    private final Fake fake = new Fake();
    private Path state() { return temp.resolve("state"); }
    private Path sockets() { return temp.resolve("wireguard"); }
    private MacEngine engine() throws IOException {
        Files.createDirectories(state()); Files.createDirectories(sockets());
        return new MacEngine(fake, 501, state(), sockets());
    }
    private TunnelProtocol.Configuration config(Api.Peer... peers) {
        return new TunnelProtocol.Configuration("10.203.1.1", 51820, own, peers.length == 0
                ? List.of(new Api.Peer(UUID.randomUUID().toString(), "Friend", friend.publicKey(), "10.203.1.2", "192.0.2.2:51820")) : List.of(peers));
    }
    private TunnelProtocol.Status run(String operation, TunnelProtocol.Configuration config) throws Exception {
        return engine().execute(new TunnelProtocol.Request(operation, id, config));
    }

    @Test void netstatAndIfconfigBecomeRouteGuardInput() throws Exception {
        assertEquals("192.168.1.0/24", MacNetwork.prefix("192.168.1"));
        assertEquals("224.0.0.0/4", MacNetwork.prefix("224.0.0/4"));
        assertEquals("127.0.0.0/8", MacNetwork.prefix("127"));
        assertEquals("10.203.1.2/32", MacNetwork.prefix("10.203.1.2"));
        String routes = MacNetwork.routes(NETSTAT), addresses = MacNetwork.addresses(IFCONFIG);
        assertTrue(routes.contains("192.168.1.0/24") && routes.contains("224.0.0.0/4") && !routes.contains("default"));
        assertTrue(addresses.contains("192.168.1.23") && addresses.contains("\"prefixlen\":24") && !addresses.contains("fe80"));
        RouteGuard.check(routes, addresses, config()); // a normal home network does not conflict
        assertThrows(IOException.class, () -> RouteGuard.check(MacNetwork.routes(NETSTAT + "10.203/16          link#20            UCS                 utun7\n"), addresses, config()));
        assertThrows(IOException.class, () -> RouteGuard.check(routes, MacNetwork.addresses(IFCONFIG + "\tinet 10.203.1.77 netmask 0xffffff00\n"), config()));
        assertThrows(IOException.class, () -> MacNetwork.routes("netstat: sysctl: Operation not permitted\n"), "unreadable table is not 'no routes'");
    }
    @Test void upStartsWireguardGoAndConfiguresOnlyHostRoutes() throws Exception {
        var state = run("up", config());
        assertEquals("up", state.state());
        assertEquals("utun4", state.interfaceName());
        String name = engine().tunnelName(id);
        assertTrue(name.matches("sm[0-9a-f]{12}"));
        assertEquals(List.of(MacEngine.SH, "-c", MacEngine.START, "sh", state().resolve(name).toString(), MacEngine.WIREGUARD_GO), fake.commands.get(2));
        assertTrue(fake.commands.contains(List.of(MacEngine.WG, "setconf", "utun4", "/dev/stdin")));
        assertTrue(fake.configuration.contains(own.privateKey()) && !fake.configuration.contains("Address"));
        assertTrue(fake.commands.contains(List.of(MacEngine.IFCONFIG, "utun4", "inet", "10.203.1.1/32", "10.203.1.1", "alias")));
        assertTrue(fake.commands.contains(List.of(MacEngine.ROUTE, "-q", "-n", "add", "-inet", "10.203.1.2/32", "-interface", "utun4")));
        assertTrue(fake.commands.stream().noneMatch(c -> c.stream().anyMatch(s -> s.contains(own.privateKey()) || s.equals("default") || s.contains("networksetup"))));
        assertThrows(IOException.class, () -> run("up", config()), "second up while connected");

        assertEquals("down", run("down", null).state());
        assertFalse(Files.exists(sockets().resolve("utun4.sock")), "control socket removed: wireguard-go exits");
        assertFalse(Files.exists(state().resolve(name)));
        assertEquals("down", run("down", null).state());
        assertNotEquals(name, new MacEngine(fake, 502, state(), sockets()).tunnelName(id), "each user has own tunnel names");
    }
    @Test void failureAfterStartStopsWireguardGo() throws Exception {
        fake.failRoute = true;
        assertThrows(IOException.class, () -> run("up", config()));
        assertFalse(Files.exists(sockets().resolve("utun4.sock")));
        assertFalse(Files.exists(state().resolve(engine().tunnelName(id))));
        assertEquals("down", run("status", null).state());
    }
    @Test void staleRecordsAndForeignNamesAreHandled() throws Exception {
        String name = engine().tunnelName(id);
        Files.writeString(state().resolve(name), "utun9\n"); // left from before a reboot: no socket, no interface
        assertEquals("down", run("status", null).state());
        assertEquals("up", run("up", config()).state(), "stale record is replaced");
        Files.writeString(state().resolve(name), "en0; rm -rf /\n");
        assertThrows(IOException.class, () -> run("status", null));
    }
    @Test void syncAndEndpointWorkOnRunningTunnelOnly() throws Exception {
        String key = friend.publicKey();
        assertThrows(IOException.class, () -> engine().execute(new TunnelProtocol.Request("endpoint", id, null, key, "198.51.100.20:61000")));
        run("up", config());
        fake.show = Map.of("peers", key + "\n", "public-key", own.publicKey() + "\n", "allowed-ips", key + "\t10.203.1.2/32\n");
        engine().execute(new TunnelProtocol.Request("endpoint", id, null, key, "198.51.100.20:61000"));
        assertTrue(fake.commands.contains(List.of(MacEngine.WG, "set", "utun4", "peer", key, "endpoint", "198.51.100.20:61000")));

        var newcomer = WireGuardKeys.generate();
        fake.routes = NETSTAT + "10.203.1.2         10.203.1.1         UH                  utun4\n"; // own route never blocks a sync
        int before = fake.commands.size();
        run("sync", config(new Api.Peer(UUID.randomUUID().toString(), "Newcomer", newcomer.publicKey(), "10.203.1.3", "")));
        var issued = fake.commands.subList(before, fake.commands.size());
        assertTrue(issued.contains(List.of(MacEngine.ROUTE, "-q", "-n", "delete", "-inet", "10.203.1.2/32", "-interface", "utun4")));
        assertTrue(issued.contains(List.of(MacEngine.WG, "set", "utun4", "peer", key, "remove")));
        assertTrue(issued.contains(List.of(MacEngine.WG, "set", "utun4", "peer", newcomer.publicKey(), "allowed-ips", "10.203.1.3/32")));
        assertTrue(issued.contains(List.of(MacEngine.ROUTE, "-q", "-n", "add", "-inet", "10.203.1.3/32", "-interface", "utun4")));
        fake.show = Map.of("public-key", WireGuardKeys.generate().publicKey() + "\n");
        assertThrows(IOException.class, () -> run("sync", config()), "other identity");
    }

    private final class Fake implements CommandRunner {
        final List<List<String>> commands = new ArrayList<>();
        boolean failRoute;
        String configuration = "", routes = NETSTAT;
        Map<String, String> show = Map.of();
        public String run(List<String> command, String input) throws Exception {
            commands.add(List.copyOf(command));
            String program = command.getFirst();
            if (program.equals(MacEngine.NETSTAT)) return routes;
            if (program.equals(MacEngine.IFCONFIG) && command.get(1).equals("-a")) return IFCONFIG;
            if (program.equals(MacEngine.IFCONFIG) && command.size() == 2) {
                if (!Files.exists(sockets().resolve(command.get(1) + ".sock"))) throw new IOException("interface does not exist");
                return command.get(1) + ": flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280\n";
            }
            if (program.equals(MacEngine.SH)) {
                // wireguard-go: picks a utun, reports it, opens its control socket and daemonizes.
                Files.writeString(Path.of(command.get(4)), "utun4\n");
                Files.writeString(sockets().resolve("utun4.sock"), "");
                return "";
            }
            if (program.equals(MacEngine.WG) && command.get(1).equals("setconf")) configuration = input;
            if (program.equals(MacEngine.WG) && command.get(1).equals("show")) return show.getOrDefault(command.get(3), "");
            if (program.equals(MacEngine.ROUTE) && command.contains("add") && failRoute) throw new IOException("Injected route failure");
            return "";
        }
    }
}
