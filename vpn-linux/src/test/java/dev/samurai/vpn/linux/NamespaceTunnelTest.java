package dev.samurai.vpn.linux;

import dev.samurai.vpn.core.*;
import java.nio.file.*;
import java.io.IOException;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import static org.junit.jupiter.api.Assertions.*;

/** Must run via native/linux/test-isolated.sh, never in the host network namespace. */
@EnabledIfSystemProperty(named="samurai.native.test", matches="true")
class NamespaceTunnelTest {
    private final CommandRunner runner = new CommandRunner.SystemRunner(Duration.ofSeconds(8));
    @Test @Timeout(60) void realWireGuardHandshakePingSyncDisconnectAndRollback() throws Exception {
        String[] mapping = Files.readString(Path.of("/proc/self/uid_map")).strip().split("\\s+");
        assertEquals(3, mapping.length); assertEquals("1", mapping[2], "Refusing to run outside an isolated user namespace");
        String parentNamespace = System.getenv("SAMURAI_PARENT_NETNS");
        assertNotNull(parentNamespace, "Use native/linux/test-isolated.sh");
        assertNotEquals(parentNamespace, Files.readSymbolicLink(Path.of("/proc/self/ns/net")).toString(),
                "Refusing to modify the host network");
        Process a = new ProcessBuilder("/usr/bin/unshare", "--net", "/usr/bin/sleep", "120").start();
        Process b = new ProcessBuilder("/usr/bin/unshare", "--net", "/usr/bin/sleep", "120").start();
        try {
            ready(a); ready(b);
            runner.run(List.of("/usr/sbin/ip", "link", "add", "sveth-a", "type", "veth", "peer", "name", "sveth-b"), "");
            runner.run(List.of("/usr/sbin/ip", "link", "set", "sveth-a", "netns", Long.toString(a.pid())), "");
            runner.run(List.of("/usr/sbin/ip", "link", "set", "sveth-b", "netns", Long.toString(b.pid())), "");
            CommandRunner ra = namespace(a.pid()), rb = namespace(b.pid());
            prepare(ra, "sveth-a", "192.0.2.1", "192.0.2.2"); prepare(rb, "sveth-b", "192.0.2.2", "192.0.2.1");
            String originalA = ra.run(List.of("/usr/sbin/ip", "-j", "-4", "route", "show", "table", "all"), "");
            String originalB = rb.run(List.of("/usr/sbin/ip", "-j", "-4", "route", "show", "table", "all"), "");
            var keyA = WireGuardKeys.generate(); var keyB = WireGuardKeys.generate(); String network = UUID.randomUUID().toString();
            var configA = new TunnelProtocol.Configuration("10.203.1.1", 30101, keyA,
                    List.of(new Api.Peer(UUID.randomUUID().toString(), "B", keyB.publicKey(), "10.203.1.2", "192.0.2.2:30102")));
            var configB = new TunnelProtocol.Configuration("10.203.1.2", 30102, keyB,
                    List.of(new Api.Peer(UUID.randomUUID().toString(), "A", keyA.publicKey(), "10.203.1.1", "192.0.2.1:30101")));
            var engineA = new LinuxEngine(ra, 1000); var engineB = new LinuxEngine(rb, 1000);
            engineA.execute(new TunnelProtocol.Request("up", network, configA));
            engineB.execute(new TunnelProtocol.Request("up", network, configB));
            ra.run(List.of("/usr/bin/ping", "-n", "-c", "2", "-W", "3", "-I", "10.203.1.1", "10.203.1.2"), "");
            rb.run(List.of("/usr/bin/ping", "-n", "-c", "1", "-W", "3", "-I", "10.203.1.2", "10.203.1.1"), "");
            assertTrue(engineA.status(network).latestHandshake() > 0); assertTrue(engineB.status(network).receivedBytes() > 0);
            // Live membership changes without reconnecting: add a member, revoke everyone, restore.
            var keyC = WireGuardKeys.generate();
            var withC = new ArrayList<>(configA.peers());
            withC.add(new Api.Peer(UUID.randomUUID().toString(), "C", keyC.publicKey(), "10.203.1.3", "192.0.2.3:30103"));
            engineA.execute(new TunnelProtocol.Request("sync", network, new TunnelProtocol.Configuration("10.203.1.1", 30101, keyA, withC)));
            assertTrue(ra.run(List.of("/usr/bin/wg", "show", engineA.interfaceName(network), "peers"), "").contains(keyC.publicKey()));
            assertTrue(ra.run(List.of("/usr/sbin/ip", "-4", "route", "show", "10.203.1.3/32"), "").contains(engineA.interfaceName(network)));
            ra.run(List.of("/usr/bin/ping", "-n", "-c", "1", "-W", "3", "-I", "10.203.1.1", "10.203.1.2"), "");
            engineA.execute(new TunnelProtocol.Request("sync", network, new TunnelProtocol.Configuration("10.203.1.1", 30101, keyA, List.of())));
            assertTrue(ra.run(List.of("/usr/bin/wg", "show", engineA.interfaceName(network), "peers"), "").isBlank());
            assertThrows(IOException.class, () -> ra.run(List.of("/usr/bin/ping", "-n", "-c", "1", "-W", "1", "-I", "10.203.1.1", "10.203.1.2"), ""),
                    "revoked peer is unreachable without reconnecting");
            engineA.execute(new TunnelProtocol.Request("sync", network, configA));
            ra.run(List.of("/usr/bin/ping", "-n", "-c", "2", "-W", "3", "-I", "10.203.1.1", "10.203.1.2"), "");
            engineB.execute(new TunnelProtocol.Request("down", network, null));
            assertThrows(IOException.class, () -> ra.run(List.of("/usr/bin/ping", "-n", "-c", "1", "-W", "1", "-I", "10.203.1.1", "10.203.1.2"), ""));
            engineA.execute(new TunnelProtocol.Request("down", network, null));
            assertEquals(originalA, ra.run(List.of("/usr/sbin/ip", "-j", "-4", "route", "show", "table", "all"), ""));
            assertEquals(originalB, rb.run(List.of("/usr/sbin/ip", "-j", "-4", "route", "show", "table", "all"), ""));
            var failing = new LinuxEngine((cmd, input) -> {
                if (cmd.contains("route") && cmd.contains("add")) throw new IOException("Injected route failure");
                return ra.run(cmd, input);
            }, 1000);
            assertThrows(IOException.class, () -> failing.execute(new TunnelProtocol.Request("up", network, configA)));
            assertEquals("down", engineA.status(network).state());
            assertEquals(originalA, ra.run(List.of("/usr/sbin/ip", "-j", "-4", "route", "show", "table", "all"), ""));
        } finally {
            a.destroyForcibly(); b.destroyForcibly(); a.waitFor(); b.waitFor();
        }
    }
    private void ready(Process process) throws Exception {
        Path child = Path.of("/proc/" + process.pid() + "/ns/net");
        for (int i = 0; i < 100; i++) {
            if (!process.isAlive()) throw new IOException("Cannot create child network namespace");
            if (!Files.readSymbolicLink(child).equals(Files.readSymbolicLink(Path.of("/proc/self/ns/net")))) return;
            Thread.sleep(10);
        }
        throw new IOException("Namespace creation timed out");
    }
    private CommandRunner namespace(long pid) {
        return (cmd, input) -> {
            var wrapped = new ArrayList<>(List.of("/usr/bin/nsenter", "--target", Long.toString(pid), "--net", "--"));
            wrapped.addAll(cmd);
            try { return runner.run(wrapped, input); }
            catch (Exception e) { throw new IOException("Test native command failed: " + String.join(" ", cmd), e); }
        };
    }
    private void prepare(CommandRunner r, String device, String address, String gateway) throws Exception {
        r.run(List.of("/usr/sbin/ip", "link", "set", "lo", "up"), "");
        r.run(List.of("/usr/sbin/ip", "address", "add", address + "/24", "dev", device), "");
        r.run(List.of("/usr/sbin/ip", "link", "set", device, "up"), "");
        r.run(List.of("/usr/sbin/ip", "route", "add", "default", "via", gateway, "dev", device), "");
    }
}
