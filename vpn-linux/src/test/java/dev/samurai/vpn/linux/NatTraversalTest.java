package dev.samurai.vpn.linux;

import dev.samurai.vpn.core.*;
import dev.samurai.vpn.server.*;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Two clients behind separate masquerading NAT routers and a relay on the "internet".
 * Real kernel WireGuard and nftables, all inside namespaces created by native/linux/test-isolated.sh.
 */
@EnabledIfSystemProperty(named="samurai.native.test", matches="true")
class NatTraversalTest {
    private final CommandRunner.SystemRunner runner = new CommandRunner.SystemRunner(Duration.ofSeconds(8));
    private final List<Process> namespaces = new ArrayList<>();

    @Test @Timeout(240) void relayThenHolePunchingThenFallbackBehindNat() throws Exception {
        String[] mapping = Files.readString(Path.of("/proc/self/uid_map")).strip().split("\\s+");
        assertEquals("1", mapping[2], "Refusing to run outside an isolated user namespace");
        String parent = System.getenv("SAMURAI_PARENT_NETNS");
        assertNotNull(parent, "Use native/linux/test-isolated.sh");
        assertNotEquals(parent, Files.readSymbolicLink(Path.of("/proc/self/ns/net")).toString(), "Refusing to modify the host network");
        try {
            // The test's own namespace is the internet; the relay listens on its bridge address.
            ip("link", "add", "sbr0", "type", "bridge"); ip("address", "add", "198.51.100.1/24", "dev", "sbr0"); ip("link", "set", "sbr0", "up");
            CommandRunner ca = site("a", "198.51.100.2", "10.0.1"), cb = site("b", "198.51.100.3", "10.0.2");
            CommandRunner ra = routers.get("a"), rb = routers.get("b");

            String admin = Tokens.generate();
            try (var relay = new Relay(InetAddress.getByName("198.51.100.1"), "198.51.100.1", 40000, 4)) {
                relay.start();
                var registry = new NetworkRegistry(admin, Clock.systemUTC(), relay);
                var network = registry.create(admin, "NAT test");
                var keyA = WireGuardKeys.generate(); var keyB = WireGuardKeys.generate();
                var a = join(registry, network, "A", keyA); var b = join(registry, network, "B", keyB);
                var engineA = new LinuxEngine(ca, 1000); var engineB = new LinuxEngine(cb, 1000);
                String id = network.networkId();
                engineA.execute(new TunnelProtocol.Request("up", id, new TunnelProtocol.Configuration(a.address(), 30101, keyA, others(registry, network, a))));
                engineB.execute(new TunnelProtocol.Request("up", id, new TunnelProtocol.Configuration(b.address(), 30102, keyB, others(registry, network, b))));

                // 1. Both clients are behind NAT without endpoints: traffic goes through the relay.
                pingEventually(ca, a.address(), b.address());
                pingEventually(cb, b.address(), a.address());
                assertTrue(peerEndpoint(engineA, id).startsWith("198.51.100.1:"), "A uses the relay");

                // 2. The relay observed each NAT mapping and offers it as a candidate.
                var fromA = others(registry, network, a).getFirst(); var fromB = others(registry, network, b).getFirst();
                assertTrue(fromA.candidate().startsWith("198.51.100.3:"), fromA.candidate());
                assertTrue(fromB.candidate().startsWith("198.51.100.2:"), fromB.candidate());

                // 3. Hole punching moves both sides to the direct path.
                var managerA = manager(engineA, id, ca, a.address()); var managerB = manager(engineB, id, cb, b.address());
                Map<String, PathManager.Path> paths;
                try { paths = until(Duration.ofSeconds(60), managerA, managerB, registry, network, a, b, PathManager.Path.DIRECT); }
                catch (AssertionError e) {
                    var report = new StringBuilder(e.getMessage());
                    for (var side : Map.of("A", ca, "B", cb).entrySet()) for (var what : List.of("endpoints", "transfer"))
                        report.append('\n').append(side.getKey()).append(' ').append(what).append(": ")
                              .append(side.getValue().run(List.of("/usr/bin/wg", "show", "all", what), "").strip());
                    throw new AssertionError(report.toString(), e);
                }
                assertEquals(fromA.candidate(), peerEndpoint(engineA, id), "A sends directly to B's NAT");
                assertEquals(fromB.candidate(), peerEndpoint(engineB, id), "B sends directly to A's NAT");
                ping(ca, a.address(), b.address(), 3);
                assertEquals(fromA.candidate(), peerEndpoint(engineA, id), "replies arrived directly, no roaming to the relay: " + paths);

                // 4. The direct path breaks (routers drop each other): both sides return to the relay.
                for (var router : List.of(ra, rb)) router.run(List.of("/usr/sbin/nft", "-f", "-"), """
                        table ip block { chain forward { type filter hook forward priority 0; ip saddr { 198.51.100.2, 198.51.100.3 } drop; ip daddr { 198.51.100.2, 198.51.100.3 } drop; }; }
                        """);
                until(Duration.ofSeconds(100), managerA, managerB, registry, network, a, b, PathManager.Path.RELAY);
                assertTrue(peerEndpoint(engineA, id).startsWith("198.51.100.1:"));
                pingEventually(ca, a.address(), b.address());
            }
        } finally {
            for (var process : namespaces) { process.destroyForcibly(); process.waitFor(); }
        }
    }

    private final Map<String, CommandRunner> routers = new HashMap<>();
    /** A NAT router with a WAN leg on the bridge and a client namespace behind it. */
    private CommandRunner site(String name, String wan, String lan) throws Exception {
        long router = spawn(), client = spawn();
        ip("link", "add", "swan-" + name, "type", "veth", "peer", "name", "sup-" + name);
        ip("link", "set", "swan-" + name, "netns", Long.toString(router));
        ip("link", "set", "sup-" + name, "master", "sbr0"); ip("link", "set", "sup-" + name, "up");
        ip("link", "add", "slan-" + name, "type", "veth", "peer", "name", "scli-" + name);
        ip("link", "set", "slan-" + name, "netns", Long.toString(router));
        ip("link", "set", "scli-" + name, "netns", Long.toString(client));
        CommandRunner r = namespace(router), c = namespace(client);
        for (var command : List.of(List.of("link", "set", "lo", "up"), List.of("address", "add", wan + "/24", "dev", "swan-" + name),
                List.of("link", "set", "swan-" + name, "up"), List.of("address", "add", lan + ".1/24", "dev", "slan-" + name),
                List.of("link", "set", "slan-" + name, "up"))) r.run(withIp(command), "");
        r.run(List.of("/usr/sbin/sysctl", "-q", "-w", "net.ipv4.ip_forward=1"), "");
        // Like a home router, drop unsolicited WAN input: otherwise conntrack keeps an entry for the peer's
        // early punch packet and masquerade must pick another source port for our own punch.
        r.run(List.of("/usr/sbin/nft", "-f", "-"), "table ip nat { chain post { type nat hook postrouting priority 100; oifname \"swan-" + name + "\" masquerade; }; }\n"
                + "table ip filter { chain input { type filter hook input priority 0; iifname \"swan-" + name + "\" drop; }; }\n");
        for (var command : List.of(List.of("link", "set", "lo", "up"), List.of("address", "add", lan + ".2/24", "dev", "scli-" + name),
                List.of("link", "set", "scli-" + name, "up"), List.of("route", "add", "default", "via", lan + ".1"))) c.run(withIp(command), "");
        routers.put(name, r);
        return c;
    }
    private PathManager manager(LinuxEngine engine, String id, CommandRunner client, String ownAddress) {
        return new PathManager(new PathManager.Tunnel() {
            public TunnelProtocol.Status status() throws Exception { return engine.status(id); }
            public void endpoint(String key, String endpoint) throws Exception { engine.execute(new TunnelProtocol.Request("endpoint", id, null, key, endpoint)); }
            public void poke(String address) {
                try { client.run(List.of("/usr/bin/ping", "-n", "-c", "1", "-W", "1", "-I", ownAddress, address), ""); } catch (Exception ignored) {}
            }
        });
    }
    private Map<String, PathManager.Path> until(Duration limit, PathManager managerA, PathManager managerB, NetworkRegistry registry,
            Api.NetworkCreated network, Api.Joined a, Api.Joined b, PathManager.Path wanted) throws Exception {
        long deadline = System.nanoTime() + limit.toNanos();
        Map<String, PathManager.Path> lastA = Map.of(), lastB = Map.of();
        while (System.nanoTime() < deadline) {
            long now = Instant.now().getEpochSecond();
            lastA = managerA.tick(others(registry, network, a), now);
            lastB = managerB.tick(others(registry, network, b), now);
            if (lastA.values().stream().allMatch(wanted::equals) && lastB.values().stream().allMatch(wanted::equals) && !lastA.isEmpty() && !lastB.isEmpty())
                return lastA;
            Thread.sleep(1000);
        }
        throw new AssertionError("Paths did not reach " + wanted + ": A=" + lastA + " B=" + lastB);
    }
    private static String peerEndpoint(LinuxEngine engine, String id) throws Exception { return engine.status(id).peers().getFirst().endpoint(); }
    private static List<Api.Peer> others(NetworkRegistry registry, Api.NetworkCreated network, Api.Joined self) {
        return registry.peers(network.networkId(), self.peerToken()).peers().stream().filter(p -> !p.peerId().equals(self.peerId())).toList();
    }
    private static Api.Joined join(NetworkRegistry registry, Api.NetworkCreated network, String name, WireGuardKeys.Identity key) {
        var invite = registry.invite(network.networkId(), network.ownerToken());
        return registry.join(network.networkId(), invite.inviteToken(), new Api.Join(name, key.publicKey(), ""));
    }
    private static void ping(CommandRunner r, String from, String to, int count) throws Exception {
        r.run(List.of("/usr/bin/ping", "-n", "-c", Integer.toString(count), "-W", "3", "-I", from, to), "");
    }
    /** The first packet may wait for a WireGuard handshake retry (5 s) through the relay. */
    private static void pingEventually(CommandRunner r, String from, String to) throws Exception {
        Exception last = null;
        for (int attempt = 0; attempt < 10; attempt++) {
            try { ping(r, from, to, 1); return; } catch (Exception e) { last = e; }
        }
        throw last;
    }
    private void ip(String... args) throws Exception { runner.run(withIp(List.of(args)), ""); }
    private static List<String> withIp(List<String> args) { var command = new ArrayList<>(List.of("/usr/sbin/ip")); command.addAll(args); return command; }
    private long spawn() throws Exception {
        Process process = new ProcessBuilder("/usr/bin/unshare", "--net", "/usr/bin/sleep", "300").start();
        namespaces.add(process);
        Path child = Path.of("/proc/" + process.pid() + "/ns/net");
        for (int i = 0; i < 100; i++) {
            if (!process.isAlive()) throw new IOException("Cannot create child network namespace");
            if (!Files.readSymbolicLink(child).equals(Files.readSymbolicLink(Path.of("/proc/self/ns/net")))) return process.pid();
            Thread.sleep(10);
        }
        throw new IOException("Namespace creation timed out");
    }
    private CommandRunner namespace(long pid) {
        return (cmd, input) -> {
            var wrapped = new ArrayList<>(List.of("/usr/bin/nsenter", "--target", Long.toString(pid), "--net", "--"));
            wrapped.addAll(cmd);
            var result = runner.result(wrapped, input);
            if (result.exitCode() == 0) return result.output();
            throw new IOException("Test native command failed (exit " + result.exitCode() + "): " + String.join(" ", cmd) + "\n" + result.errors());
        };
    }
}
