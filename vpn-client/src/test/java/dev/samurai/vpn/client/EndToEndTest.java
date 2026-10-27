package dev.samurai.vpn.client;

import dev.samurai.vpn.core.*;
import dev.samurai.vpn.server.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class EndToEndTest {
    @TempDir Path temp;
    private final ByteArrayOutputStream output = new ByteArrayOutputStream();
    private final PrintStream stream = new PrintStream(output);

    @Test void completeTwoClientWorkflowOverHttp() throws Exception {
        cli("gen-admin", "--out", file("admin.token"));
        String admin = SecretFiles.read(temp.resolve("admin.token"));
        try (var server = new ControlServer(new InetSocketAddress("127.0.0.1", 0), new NetworkRegistry(admin), null, true)) {
            server.start(); String origin = "http://127.0.0.1:" + server.port();
            cli("create-network", "--server", origin, "--token-file", file("admin.token"), "--name", "Friends", "--out", file("owner.json"), "--dev");
            for (String user : List.of("alice", "bob")) {
                cli("keygen", "--out", file(user + "-key.json"));
                cli("invite", "--owner", file("owner.json"), "--out", file(user + "-invite.json"), "--dev");
                cli("join", "--invite", file(user + "-invite.json"), "--identity", file(user + "-key.json"), "--name", user,
                        "--endpoint", user.equals("alice") ? "192.168.1.10:51820" : "192.168.1.11:51820", "--out", file(user + ".json"), "--dev");
            }
            cli("peers", "--session", file("alice.json"), "--dev");
            cli("export", "--session", file("alice.json"), "--out", file("alice.conf"), "--dev");
            cli("export", "--session", file("bob.json"), "--out", file("bob.conf"), "--dev");
            var bob = Json.MAPPER.readValue(SecretFiles.read(temp.resolve("bob.json")), Credentials.Session.class);
            var alice = Json.MAPPER.readValue(SecretFiles.read(temp.resolve("alice.json")), Credentials.Session.class);
            String config = SecretFiles.read(temp.resolve("alice.conf"));
            assertTrue(config.contains("PublicKey = " + bob.identity().publicKey()));
            assertFalse(config.contains(bob.identity().privateKey()));
            assertFalse(output.toString().contains(alice.identity().privateKey()));
            assertFalse(output.toString().contains(admin));
            assertFalse(output.toString().contains(bob.membership().peerToken()));
            cli("revoke", "--owner", file("owner.json"), "--peer", bob.membership().peerId(), "--dev");
            assertEquals(1, ClientMain.run(new String[]{"peers", "--session", file("bob.json"), "--dev"}, stream, stream));
            cli("export", "--session", file("alice.json"), "--out", file("alice-after-revoke.conf"), "--dev");
            assertFalse(SecretFiles.read(temp.resolve("alice-after-revoke.conf")).contains(bob.identity().publicKey()));
        }
    }
    @Test void rejectsUnsafeOriginsAndRemotePlaintextServer() {
        for (String url : List.of("http://example.com", "http://localhost:8787", "http://127.0.0.1.evil.example", "https://user:secret@example.com",
                "https://example.com/path", "https://example.com?token=secret", "file:///tmp/server"))
            assertThrows(IllegalArgumentException.class, () -> ApiClient.validateOrigin(url, true));
        assertThrows(IllegalArgumentException.class, () -> ApiClient.validateOrigin("http://127.0.0.1:8787", false));
        assertThrows(IllegalArgumentException.class, () -> new ControlServer(new InetSocketAddress("0.0.0.0", 8787), new NetworkRegistry(Tokens.generate()), null, true));
    }
    @Test void malformedAndOversizedRequestsDoNotMutateState() throws Exception {
        String admin = Tokens.generate(); var registry = new NetworkRegistry(admin);
        try (var server = new ControlServer(new InetSocketAddress("127.0.0.1", 0), registry, null, true); var client = HttpClient.newHttpClient()) {
            server.start(); var uri = URI.create("http://127.0.0.1:" + server.port() + "/v1/networks");
            assertEquals(401, client.send(HttpRequest.newBuilder(uri).POST(HttpRequest.BodyPublishers.ofString("{}" )).build(), HttpResponse.BodyHandlers.discarding()).statusCode());
            for (String body : List.of("{\"name\":\"a\",\"name\":\"b\"}", "{\"name\":\"a\",\"extra\":1}", "null")) {
                var req = HttpRequest.newBuilder(uri).header("Authorization", "Bearer " + admin).header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body)).build();
                assertEquals(400, client.send(req, HttpResponse.BodyHandlers.discarding()).statusCode());
            }
            var huge = HttpRequest.newBuilder(uri).header("Authorization", "Bearer " + admin).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(" ".repeat(9000))).build();
            assertEquals(413, client.send(huge, HttpResponse.BodyHandlers.discarding()).statusCode());
            var origin = HttpRequest.newBuilder(uri).header("Authorization", "Bearer " + admin).header("Origin", "https://evil.example")
                    .POST(HttpRequest.BodyPublishers.noBody()).build();
            assertEquals(403, client.send(origin, HttpResponse.BodyHandlers.discarding()).statusCode());
        }
    }
    @Test void existingOutputIsCheckedBeforeCreatingRemoteResource() throws Exception {
        String admin = Tokens.generate(); SecretFiles.writeNew(temp.resolve("admin.token"), admin);
        SecretFiles.writeNew(temp.resolve("existing.json"), "keep");
        var registry = new NetworkRegistry(admin);
        try (var server = new ControlServer(new InetSocketAddress("127.0.0.1", 0), registry, null, true)) {
            server.start();
            String[] args = {"create-network", "--server", "http://127.0.0.1:" + server.port(), "--token-file", file("admin.token"), "--name", "Friends", "--out", file("existing.json"), "--dev"};
            assertEquals(1, ClientMain.run(args, stream, stream));
            assertEquals("keep", SecretFiles.read(temp.resolve("existing.json")));
            for (int i = 0; i < 32; i++) registry.create(admin, "Network " + i);
        }
    }
    private String file(String name) { return temp.resolve(name).toString(); }
    private void cli(String... args) { assertEquals(0, ClientMain.run(args, stream, stream), output.toString()); }
}
