package dev.samurai.vpn.linux;

import dev.samurai.vpn.core.*;
import java.io.IOException;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class LinuxSecurityTest {
    private final String id = UUID.randomUUID().toString();
    private final WireGuardKeys.Identity own = WireGuardKeys.generate(), friend = WireGuardKeys.generate();
    private TunnelProtocol.Configuration config() {
        return new TunnelProtocol.Configuration("10.203.1.1", 51820, own,
                List.of(new Api.Peer(UUID.randomUUID().toString(), "Friend", friend.publicKey(), "10.203.1.2", "192.0.2.2:51820")));
    }
    @Test void protocolRejectsArbitraryOperationsFieldsAndRoutes() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> TunnelProtocol.validate(new TunnelProtocol.Request("shell", id, null)));
        assertThrows(IllegalArgumentException.class, () -> TunnelProtocol.validate(new TunnelProtocol.Request("down", id, config())));
        assertThrows(IllegalArgumentException.class, () -> TunnelProtocol.validate(new TunnelProtocol.Request("up", "../bad", config())));
        var bad = new TunnelProtocol.Configuration("10.203.1.1", 51820, own,
                List.of(new Api.Peer(UUID.randomUUID().toString(), "Friend", friend.publicKey(), "0.0.0.0/0", "192.0.2.2:51820")));
        assertThrows(IllegalArgumentException.class, () -> TunnelProtocol.validate(new TunnelProtocol.Request("up", id, bad)));
        String json = Json.MAPPER.writeValueAsString(new TunnelProtocol.Request("up", id, config()));
        assertThrows(Exception.class, () -> Json.MAPPER.readValue(json.substring(0, json.length()-1) + ",\"PostUp\":\"bad\"}", TunnelProtocol.Request.class));
        assertFalse(new TunnelProtocol.Request("up", id, config()).toString().contains(own.privateKey()));
        assertFalse(TunnelProtocol.nativeConfig(config()).contains("Address ="));
    }
    @Test void routeGuardAllowsDefaultsButRejectsOverlapAndLocalAddresses() throws Exception {
        RouteGuard.check("[{\"dst\":\"default\",\"gateway\":\"192.0.2.1\"},{\"dst\":\"192.0.2.0/24\"}]", "[]", config());
        for (String prefix : List.of("10.0.0.0/8", "10.203.0.0/16", "10.203.1.0/24", "10.203.1.2/32"))
            assertThrows(IOException.class, () -> RouteGuard.check("[{\"dst\":\"" + prefix + "\"}]", "[]", config()));
        assertThrows(IOException.class, () -> RouteGuard.check("[]", "[{\"addr_info\":[{\"family\":\"inet\",\"local\":\"10.203.1.99\",\"prefixlen\":24}]}]", config()));
    }
    @Test void nativeFailureRollsBackOnlyItsNewInterface() throws Exception {
        var fake = new Fake(); var engine = new LinuxEngine(fake, 1000); fake.failRoute = true;
        assertThrows(IOException.class, () -> engine.execute(new TunnelProtocol.Request("up", id, config())));
        assertNull(fake.link);
        assertTrue(fake.commands.stream().anyMatch(c -> c.contains("delete")));
        assertTrue(fake.commands.stream().noneMatch(c -> c.stream().anyMatch(s -> s.contains(own.privateKey()))));
        assertTrue(fake.configuration.contains(own.privateKey()));
        assertEquals("down", engine.status(id).state());
    }
    @Test void existingForeignInterfaceIsNeverRemoved() throws Exception {
        var fake = new Fake(); var engine = new LinuxEngine(fake, 1000);
        fake.link = Map.of("ifname", engine.interfaceName(id), "ifalias", "someone-else", "linkinfo", Map.of("info_kind", "wireguard"));
        assertThrows(IOException.class, () -> engine.execute(new TunnelProtocol.Request("up", id, config())));
        assertThrows(IOException.class, () -> engine.execute(new TunnelProtocol.Request("down", id, null)));
        assertTrue(fake.commands.stream().noneMatch(c -> c.contains("delete")));
    }
    @Test void failureToMarkOwnershipRemovesOnlyCapturedNewInterface() throws Exception {
        var fake = new Fake(); var engine = new LinuxEngine(fake, 1000); fake.failAlias = true;
        assertThrows(IOException.class, () -> engine.execute(new TunnelProtocol.Request("up", id, config())));
        assertNull(fake.link); assertTrue(fake.commands.stream().anyMatch(c -> c.contains("delete")));
    }
    @Test void applyHasOnlyHostRoutesAndIdempotentDisconnect() throws Exception {
        var fake = new Fake(); var engine = new LinuxEngine(fake, 1000);
        assertEquals("up", engine.execute(new TunnelProtocol.Request("up", id, config())).state());
        assertTrue(fake.commands.stream().anyMatch(c -> c.contains("10.203.1.2/32") && c.contains("route")));
        assertFalse(fake.commands.stream().anyMatch(c -> c.contains("default") || c.contains("iptables") || c.contains("bash")));
        assertEquals("down", engine.execute(new TunnelProtocol.Request("down", id, null)).state());
        assertEquals("down", engine.execute(new TunnelProtocol.Request("down", id, null)).state());
        assertNotEquals(engine.interfaceName(id), new LinuxEngine(fake, 1001).interfaceName(id));
    }
    @Test void endpointChangeOnlyMovesExistingPeersOfOwnedInterface() throws Exception {
        var fake = new Fake(); var engine = new LinuxEngine(fake, 1000);
        String friendKey = friend.publicKey(), stranger = WireGuardKeys.generate().publicKey();
        assertThrows(IOException.class, () -> engine.execute(new TunnelProtocol.Request("endpoint", id, null, friendKey, "198.51.100.20:61000")));
        engine.execute(new TunnelProtocol.Request("up", id, config()));
        fake.peers = friendKey + "\n";
        engine.execute(new TunnelProtocol.Request("endpoint", id, null, friendKey, "198.51.100.20:61000"));
        assertTrue(fake.commands.stream().anyMatch(c -> c.equals(List.of("/usr/bin/wg", "set", engine.interfaceName(id), "peer", friendKey, "endpoint", "198.51.100.20:61000"))));
        int before = fake.commands.size();
        assertThrows(IOException.class, () -> engine.execute(new TunnelProtocol.Request("endpoint", id, null, stranger, "198.51.100.20:61000")));
        assertTrue(fake.commands.subList(before, fake.commands.size()).stream().noneMatch(c -> c.contains("set")));
        for (String bad : List.of("10.203.1.2:51820", "0.0.0.0:1", "198.51.100.20", "a:1"))
            assertThrows(IllegalArgumentException.class, () -> TunnelProtocol.validate(new TunnelProtocol.Request("endpoint", id, null, friendKey, bad)));
        assertThrows(IllegalArgumentException.class, () -> TunnelProtocol.validate(new TunnelProtocol.Request("status", id, null, friendKey, null)));
        assertThrows(IllegalArgumentException.class, () -> TunnelProtocol.validate(new TunnelProtocol.Request("endpoint", id, config(), friendKey, "198.51.100.20:61000")));
    }
    @Test void syncAddsAndRemovesOnlyChangedMembersOfRunningTunnel() throws Exception {
        var fake = new Fake(); var engine = new LinuxEngine(fake, 1000); String name = engine.interfaceName(id);
        var newcomer = WireGuardKeys.generate();
        var next = new TunnelProtocol.Configuration("10.203.1.1", 51820, own, List.of(
                new Api.Peer(UUID.randomUUID().toString(), "Newcomer", newcomer.publicKey(), "10.203.1.3", "203.0.113.10:40003")));
        assertThrows(IOException.class, () -> engine.execute(new TunnelProtocol.Request("sync", id, next)), "no running tunnel");
        engine.execute(new TunnelProtocol.Request("up", id, config()));
        fake.publicKey = own.publicKey(); fake.allowedIps = friend.publicKey() + "\t10.203.1.2/32\n";
        fake.routes = "[{\"dst\":\"10.203.1.2\",\"dev\":\"" + name + "\"}]"; // own routes never block a sync
        int before = fake.commands.size();
        engine.execute(new TunnelProtocol.Request("sync", id, next));
        var issued = fake.commands.subList(before, fake.commands.size());
        assertTrue(issued.contains(List.of("/usr/sbin/ip", "-4", "route", "del", "10.203.1.2/32", "dev", name)));
        assertTrue(issued.contains(List.of("/usr/bin/wg", "set", name, "peer", friend.publicKey(), "remove")));
        assertTrue(issued.contains(List.of("/usr/bin/wg", "set", name, "peer", newcomer.publicKey(), "allowed-ips", "10.203.1.3/32",
                "endpoint", "203.0.113.10:40003", "persistent-keepalive", "25")));
        assertTrue(issued.contains(List.of("/usr/sbin/ip", "-4", "route", "add", "10.203.1.3/32", "dev", name, "proto", "static")));
        assertTrue(issued.stream().noneMatch(c -> c.stream().anyMatch(s -> s.contains(own.privateKey()))));

        before = fake.commands.size();
        engine.execute(new TunnelProtocol.Request("sync", id, config()));  // unchanged membership; fake reports no endpoint yet
        var unchanged = fake.commands.subList(before, fake.commands.size());
        assertTrue(unchanged.stream().noneMatch(c -> c.contains("remove") || c.contains("allowed-ips") && c.contains("set") || c.contains("add") || c.contains("del")));
        assertTrue(unchanged.contains(List.of("/usr/bin/wg", "set", name, "peer", friend.publicKey(), "endpoint", "192.0.2.2:51820", "persistent-keepalive", "25")),
                "a kept peer without endpoint receives the published one");

        fake.routes = "[{\"dst\":\"10.203.1.0/24\",\"dev\":\"eth0\"}]";
        assertThrows(IOException.class, () -> engine.execute(new TunnelProtocol.Request("sync", id, next)), "foreign route conflict");
        fake.routes = "[]"; fake.publicKey = WireGuardKeys.generate().publicKey();
        assertThrows(IOException.class, () -> engine.execute(new TunnelProtocol.Request("sync", id, next)), "other identity");
        TunnelProtocol.validate(new TunnelProtocol.Request("sync", id, new TunnelProtocol.Configuration("10.203.1.1", 51820, own, List.of())));
        assertThrows(IllegalArgumentException.class, () -> TunnelProtocol.validate(new TunnelProtocol.Request("up", id,
                new TunnelProtocol.Configuration("10.203.1.1", 51820, own, List.of()))));
    }
    @Test @org.junit.jupiter.api.condition.EnabledOnOs(org.junit.jupiter.api.condition.OS.LINUX)
    void processExecutionHasTimeoutAndOutputLimit() throws Exception {
        var runner = new CommandRunner.SystemRunner(Duration.ofMillis(150));
        assertThrows(Exception.class, () -> runner.run(List.of("/bin/sleep", "5"), ""));
        var bounded = new CommandRunner.SystemRunner(Duration.ofSeconds(3));
        assertThrows(Exception.class, () -> bounded.run(List.of("/usr/bin/head", "-c", "1048577", "/dev/zero"), ""));
        assertEquals("test-input", bounded.run(List.of("/bin/cat"), "test-input"));
    }
    private final class Fake implements CommandRunner {
        final List<List<String>> commands = new ArrayList<>();
        Map<String, Object> link;
        boolean failRoute;
        boolean failAlias;
        String configuration = "", peers = "", allowedIps = "", publicKey = "", routes = "[]";
        public String run(List<String> command, String input) throws Exception {
            commands.add(List.copyOf(command));
            if (command.contains("-j") && command.contains("link")) return Json.MAPPER.writeValueAsString(link == null ? List.of() : List.of(link));
            if (command.contains("-j") && command.contains("route")) return routes;
            if (command.contains("-j")) return "[]";
            if (command.contains("link") && command.contains("add"))
                link = new HashMap<>(Map.of("ifname", command.get(4), "ifindex", 7, "ifalias", "", "linkinfo", Map.of("info_kind", "wireguard"), "flags", List.of()));
            if (command.contains("alias")) {
                if (failAlias) throw new IOException("Injected alias failure");
                link.put("ifalias", command.get(command.indexOf("alias") + 1));
            }
            if (command.contains("setconf")) configuration = input;
            if (command.contains("show") && command.contains("peers")) return peers;
            if (command.contains("show") && command.contains("allowed-ips")) return allowedIps;
            if (command.contains("show") && command.contains("public-key")) return publicKey + "\n";
            if (command.contains("link") && command.contains("up")) link.put("flags", List.of("UP"));
            if (command.contains("route") && command.contains("add") && failRoute) throw new IOException("Injected route failure");
            if (command.contains("delete")) link = null;
            return "";
        }
    }
}
