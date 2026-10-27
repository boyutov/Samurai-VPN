package dev.samurai.vpn.server;

import dev.samurai.vpn.core.*;
import java.net.*;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

public final class ServerMain {
    private ServerMain() {}
    public static void main(String[] args) {
        try {
            if (args.length == 0 || args[0].equals("--help")) {
                System.out.println("""
                        Samurai VPN — Java coordination server (development milestone)
                        --admin-token-file PATH [--bind 127.0.0.1] [--port 8787]
                        Choose: --dev (loopback only) OR --tls-keystore server.p12
                        TLS password: SAMURAI_TLS_PASSWORD environment variable.
                        Optional relay for members without a reachable endpoint:
                          --relay-host PUBLIC_IPV4 --relay-ports 40000-40199 [--relay-bind 0.0.0.0]
                          Open these UDP ports in the firewall. The relay forwards only WireGuard ciphertext.
                        Durable state: --state-file PATH (private JSON with token hashes, replaced atomically).
                          Without it state is in memory: restart invalidates API credentials, not WireGuard profiles.
                        """); return;
            }
            Arguments options = new Arguments(args, 0, Set.of("--dev"),
                    Set.of("--admin-token-file", "--bind", "--port", "--tls-keystore", "--relay-host", "--relay-ports", "--relay-bind", "--state-file"));
            System.setProperty("sun.net.httpserver.maxReqTime", "10");
            System.setProperty("sun.net.httpserver.maxRspTime", "10");
            System.setProperty("sun.net.httpserver.idleInterval", "15");
            System.setProperty("sun.net.httpserver.maxReqHeaders", "32");
            System.setProperty("jdk.httpserver.maxConnections", "128");
            String token = SecretFiles.read(Path.of(options.require("--admin-token-file")));
            var bind = new InetSocketAddress(InetAddress.getByName(options.get("--bind", "127.0.0.1")),
                    Validation.port(Integer.parseInt(options.get("--port", "8787"))));
            javax.net.ssl.SSLContext tls = null;
            if (options.has("--tls-keystore")) {
                String password = System.getenv("SAMURAI_TLS_PASSWORD");
                if (password == null || password.isEmpty()) throw new IllegalArgumentException("SAMURAI_TLS_PASSWORD is required");
                tls = Tls.serverContext(Path.of(options.require("--tls-keystore")), password.toCharArray());
            }
            Relay relay = null;
            if (options.has("--relay-host")) {
                String[] range = options.require("--relay-ports").split("-", -1);
                if (range.length != 2) throw new IllegalArgumentException("--relay-ports must be FIRST-LAST");
                int first = Validation.port(Integer.parseInt(range[0])), last = Validation.port(Integer.parseInt(range[1]));
                // Development servers stay on loopback unless a relay bind address is given explicitly.
                var relayBind = InetAddress.getByName(options.get("--relay-bind", options.has("--dev") ? "127.0.0.1" : "0.0.0.0"));
                relay = new Relay(relayBind, options.require("--relay-host"), first, last - first + 1);
            } else if (options.has("--relay-ports") || options.has("--relay-bind")) throw new IllegalArgumentException("--relay-host is required");
            StateStore store = options.has("--state-file") ? new StateStore(Path.of(options.require("--state-file"))) : null;
            var registry = store == null ? new NetworkRegistry(token, java.time.Clock.systemUTC(), relay)
                    : new NetworkRegistry(token, java.time.Clock.systemUTC(), relay, store);
            var server = new ControlServer(bind, registry, tls, options.has("--dev"));
            Relay startedRelay = relay;
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                // Stopping HTTP first means no request can change state while the lock is released.
                server.close(); if (startedRelay != null) startedRelay.close();
                if (store != null) try { store.close(); } catch (java.io.IOException ignored) {}
            }));
            if (relay != null) relay.start();
            server.start();
            System.out.printf("Samurai VPN control server listening on %s://%s:%d%n", tls == null ? "http" : "https", bind.getHostString(), server.port());
            if (relay != null) System.out.printf("UDP relay: %s, ports %s%n", options.require("--relay-host"), options.require("--relay-ports"));
            System.out.println(store == null ? "Development milestone: in-memory state. Ctrl+C to stop."
                    : "State: " + options.require("--state-file") + ". Ctrl+C to stop.");
            new CountDownLatch(1).await();
        } catch (Exception e) {
            System.err.println("Server failed: " + e.getMessage());
            System.exit(1);
        }
    }
}
