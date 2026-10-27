package dev.samurai.vpn.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.sun.net.httpserver.*;
import dev.samurai.vpn.core.*;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.*;

public final class ControlServer implements AutoCloseable {
    private final HttpServer server;
    private final ExecutorService executor;
    private final NetworkRegistry registry;
    private final RateLimiter limiter = new RateLimiter();

    public ControlServer(InetSocketAddress bind, NetworkRegistry registry, SSLContext tls, boolean dev) throws IOException {
        if (bind.isUnresolved()) throw new IllegalArgumentException("Bind address must resolve");
        if (tls == null && (!dev || !bind.getAddress().isLoopbackAddress()))
            throw new IllegalArgumentException("HTTPS is required; --dev permits HTTP only on loopback");
        if (tls != null && dev) throw new IllegalArgumentException("Choose HTTPS or --dev, not both");
        this.registry = registry;
        if (tls == null) server = HttpServer.create(bind, 32);
        else {
            HttpsServer https = HttpsServer.create(bind, 32);
            https.setHttpsConfigurator(new HttpsConfigurator(tls) {
                @Override public void configure(HttpsParameters parameters) {
                    var settings = tls.getDefaultSSLParameters();
                    settings.setProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
                    parameters.setSSLParameters(settings);
                }
            });
            server = https;
        }
        executor = new ThreadPoolExecutor(4, 16, 30, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(64), new ThreadPoolExecutor.AbortPolicy());
        server.setExecutor(executor);
        server.createContext("/", this::handle);
    }
    public void start() { server.start(); }
    public int port() { return server.getAddress().getPort(); }
    @Override public void close() { server.stop(0); executor.shutdownNow(); }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            try {
                if (!limiter.allow()) {
                    exchange.getResponseHeaders().set("Retry-After", "1");
                    throw new ApiException(429, "rate_limit", "Too many requests");
                }
                if (exchange.getRequestURI().getRawQuery() != null) throw new ApiException(400, "bad_request", "Query parameters are not supported");
                if (exchange.getRequestHeaders().getFirst("Origin") != null) throw new ApiException(403, "origin_rejected", "Browser requests are not supported");
                dispatch(exchange);
            } catch (ApiException e) { respond(exchange, e.status(), new Api.Error(e.code(), e.getMessage())); }
            catch (JsonProcessingException e) { respond(exchange, 400, new Api.Error("bad_json", "Invalid JSON body")); }
            catch (IllegalArgumentException e) { respond(exchange, 400, new Api.Error("bad_request", "Request validation failed")); }
            catch (Exception e) { respond(exchange, 500, new Api.Error("internal_error", "Request could not be completed")); }
        }
    }
    private void dispatch(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod(), path = exchange.getRequestURI().getRawPath();
        if (method.equals("GET") && path.equals("/healthz")) {
            respond(exchange, 200, Map.of("status", "ok", "stage", "development", "storage", registry.persistent() ? "file" : "ephemeral")); return;
        }
        String token = bearer(exchange);
        if (method.equals("POST") && path.equals("/v1/networks")) {
            Api.CreateNetwork request = body(exchange, Api.CreateNetwork.class);
            respond(exchange, 201, registry.create(token, request.name())); return;
        }
        String[] parts = path.split("/", -1);
        if (parts.length >= 5 && parts[1].equals("v1") && parts[2].equals("networks")) {
            String id = Validation.id(parts[3]);
            if (parts.length == 5 && parts[4].equals("invites") && method.equals("POST")) {
                respond(exchange, 201, registry.invite(id, token)); return;
            }
            if (parts.length == 5 && parts[4].equals("peers")) {
                if (method.equals("POST")) { respond(exchange, 201, registry.join(id, token, body(exchange, Api.Join.class))); return; }
                if (method.equals("GET")) { respond(exchange, 200, registry.peers(id, token)); return; }
            }
            if (parts.length == 6 && parts[4].equals("peers") && method.equals("DELETE")) {
                registry.revoke(id, token, Validation.id(parts[5]));
                respond(exchange, 200, Map.of("status", "revoked", "note", "Export and reapply profiles on remaining peers")); return;
            }
        }
        throw new ApiException(404, "not_found", "Endpoint not found");
    }
    private String bearer(HttpExchange exchange) {
        var headers = exchange.getRequestHeaders().get("Authorization");
        if (headers == null || headers.size() != 1 || !headers.getFirst().startsWith("Bearer "))
            throw new ApiException(401, "unauthorized", "Bearer credential required");
        String token = headers.getFirst().substring(7);
        if (!Tokens.valid(token)) throw new ApiException(401, "unauthorized", "Invalid credential");
        return token;
    }
    private <T> T body(HttpExchange exchange, Class<T> type) throws IOException {
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || !contentType.toLowerCase(Locale.ROOT).split(";", 2)[0].strip().equals("application/json"))
            throw new ApiException(415, "content_type", "Content-Type must be application/json");
        if (exchange.getRequestHeaders().getFirst("Content-Encoding") != null)
            throw new ApiException(415, "content_encoding", "Compressed request bodies are not supported");
        byte[] bytes = exchange.getRequestBody().readNBytes(8193);
        if (bytes.length > 8192) throw new ApiException(413, "body_too_large", "Request exceeds 8192 bytes");
        T result = Json.MAPPER.readValue(bytes, type);
        if (result == null) throw new ApiException(400, "bad_json", "Object required");
        return result;
    }
    private void respond(HttpExchange exchange, int status, Object response) throws IOException {
        byte[] bytes = Json.MAPPER.writeValueAsBytes(response);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
    }
}
