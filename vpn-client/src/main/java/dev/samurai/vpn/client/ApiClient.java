package dev.samurai.vpn.client;

import dev.samurai.vpn.core.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.Flow;

public final class ApiClient implements AutoCloseable {
    private final URI origin;
    private final HttpClient client;
    public ApiClient(String server, boolean dev) {
        this(server, dev, null);
    }
    ApiClient(String server, boolean dev, javax.net.ssl.SSLContext trustContext) {
        origin = validateOrigin(server, dev);
        var builder = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER);
        if (trustContext != null) builder.sslContext(trustContext);
        client = builder.build();
    }
    public static URI validateOrigin(String value, boolean dev) {
        URI uri = URI.create(value);
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getFragment() != null || uri.getQuery() != null
                || (!uri.getPath().isEmpty() && !uri.getPath().equals("/")))
            throw new IllegalArgumentException("Server must be an origin URL without credentials, query or path");
        if (uri.getPort() != -1) Validation.port(uri.getPort());
        if (!"https".equals(uri.getScheme())) {
            if (!dev || !"http".equals(uri.getScheme()) || !List.of("127.0.0.1", "[::1]").contains(uri.getHost()))
                throw new IllegalArgumentException("HTTPS required; --dev allows HTTP only at 127.0.0.1 or [::1]");
        }
        return URI.create(uri.getScheme() + "://" + uri.getRawAuthority());
    }
    public String origin() { return origin.toString(); }
    public <T> T request(String method, String path, String token, Object body, Class<T> type) throws IOException, InterruptedException {
        if (!Tokens.valid(token)) throw new IllegalArgumentException("Invalid credential");
        if (!path.startsWith("/v1/") || path.contains("?") || path.contains("#") || path.contains(".."))
            throw new IllegalArgumentException("Invalid API path");
        var builder = HttpRequest.newBuilder(origin.resolve(path)).timeout(Duration.ofSeconds(10))
                .header("Authorization", "Bearer " + token).header("Accept", "application/json");
        var publisher = HttpRequest.BodyPublishers.noBody();
        if (body != null) {
            publisher = HttpRequest.BodyPublishers.ofByteArray(Json.MAPPER.writeValueAsBytes(body));
            builder.header("Content-Type", "application/json");
        }
        var response = client.send(builder.method(method, publisher).build(), info -> new LimitedBody(131_072));
        if (response.statusCode() >= 300) throw new IOException("Server returned HTTP " + response.statusCode() + "; operation failed");
        if (!response.headers().firstValue("Content-Type").orElse("").startsWith("application/json"))
            throw new IOException("Unexpected server response type");
        try { return Json.MAPPER.readValue(response.body(), type); }
        catch (IOException e) { throw new IOException("Invalid response from server"); }
    }
    @Override public void close() { client.close(); }

    private static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final int limit;
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private Flow.Subscription subscription;
        LimitedBody(int limit) { this.limit = limit; }
        public CompletionStage<byte[]> getBody() { return result; }
        public void onSubscribe(Flow.Subscription subscription) { this.subscription = subscription; subscription.request(1); }
        public void onNext(List<ByteBuffer> buffers) {
            for (ByteBuffer buffer : buffers) {
                if (buffer.remaining() > limit - bytes.size()) {
                    subscription.cancel(); result.completeExceptionally(new IOException("Server response too large")); return;
                }
                byte[] chunk = new byte[buffer.remaining()]; buffer.get(chunk); bytes.writeBytes(chunk);
            }
            subscription.request(1);
        }
        public void onError(Throwable error) { result.completeExceptionally(error); }
        public void onComplete() { result.complete(bytes.toByteArray()); }
    }
}
