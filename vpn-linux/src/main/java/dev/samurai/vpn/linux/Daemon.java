package dev.samurai.vpn.linux;

import dev.samurai.vpn.core.Json;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Resident tunnel service on a Unix socket. The caller is identified only by the kernel
 * (SO_PEERCRED); a caller can reach only interfaces derived from its own UID.
 * Requests are executed one at a time; each connection carries one request.
 */
public final class Daemon implements AutoCloseable {
    public interface Executor { TunnelProtocol.Status execute(long uid, TunnelProtocol.Request request) throws Exception; }
    /** Who is calling; Linux asks the kernel, Windows restricts the socket directory to one user instead. */
    public interface Identity { long of(SocketChannel channel) throws IOException; }
    static final int MAX_REQUEST = 65_536, MAX_CONNECTIONS = 16;
    private final ServerSocketChannel server;
    private final Executor executor;
    private final Identity identity;
    private final ReentrantLock lock = new ReentrantLock();
    private final Semaphore connections = new Semaphore(MAX_CONNECTIONS);
    private final ScheduledExecutorService deadlines = Executors.newSingleThreadScheduledExecutor(r -> Thread.ofPlatform().daemon().unstarted(r));

    Daemon(Path socket, Executor executor) throws IOException { this(socket, executor, Daemon::peerUid, true); }
    /** {@code shared}: make the socket connectable by every local user (authorization happens per request). */
    public Daemon(Path socket, Executor executor, Identity identity, boolean shared) throws IOException {
        this.executor = executor; this.identity = identity;
        // The socket directory belongs to the service; a stale socket from a previous run is replaced.
        if (Files.exists(socket, LinkOption.NOFOLLOW_LINKS)
                && !Files.readAttributes(socket, java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).isOther())
            throw new IOException("Socket path is occupied");
        Files.deleteIfExists(socket);
        server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        server.bind(UnixDomainSocketAddress.of(socket));
        // Any local user may connect; authorization is the per-UID interface ownership.
        if (shared) Files.setPosixFilePermissions(socket, PosixFilePermissions.fromString("rw-rw-rw-"));
    }
    public void serve() {
        while (server.isOpen()) {
            SocketChannel channel;
            try { channel = server.accept(); } catch (IOException e) { if (!server.isOpen()) return; continue; }
            if (!connections.tryAcquire()) { try { channel.close(); } catch (IOException ignored) {} continue; }
            Thread.ofVirtual().start(() -> { try { handle(channel); } finally { connections.release(); } });
        }
    }
    private void handle(SocketChannel channel) {
        try (channel) {
            // Bounds both a slow client and a stuck native command.
            var deadline = deadlines.schedule(() -> { try { channel.close(); } catch (IOException ignored) {} }, 30, TimeUnit.SECONDS);
            TunnelProtocol.Response response;
            try {
                long uid = identity.of(channel);
                var request = Json.MAPPER.readValue(read(channel), TunnelProtocol.Request.class);
                TunnelProtocol.validate(request);
                if (!lock.tryLock(20, TimeUnit.SECONDS)) throw new IOException("Another tunnel operation is running");
                try { response = new TunnelProtocol.Response(true, executor.execute(uid, request), "ok"); }
                finally { lock.unlock(); }
            } catch (Exception error) {
                response = new TunnelProtocol.Response(false, null, error instanceof IOException && error.getMessage() != null
                        ? HelperMain.safeMessage(error.getMessage()) : "Invalid request or native operation failed");
            }
            ByteBuffer bytes = ByteBuffer.wrap(Json.MAPPER.writeValueAsBytes(response));
            while (bytes.hasRemaining()) channel.write(bytes);
            deadline.cancel(false);
        } catch (IOException ignored) { /* Client disconnected or deadline closed the connection. */ }
    }
    private static byte[] read(SocketChannel channel) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(MAX_REQUEST + 1);
        while (buffer.hasRemaining() && channel.read(buffer) >= 0) { /* until EOF */ }
        if (!buffer.hasRemaining()) throw new IOException("Request too large");
        byte[] bytes = new byte[buffer.position()]; buffer.flip(); buffer.get(bytes);
        return bytes;
    }
    /** Kernel-verified UID of the connected process; fails closed if the JDK cannot expose it. */
    public static long peerUid(SocketChannel channel) throws IOException {
        var principal = channel.getOption(jdk.net.ExtendedSocketOptions.SO_PEERCRED);
        try {
            // The JDK resolves SO_PEERCRED to a principal that keeps the numeric UID privately.
            var uid = principal.user().getClass().getDeclaredMethod("uid");
            uid.setAccessible(true);
            return Integer.toUnsignedLong((Integer) uid.invoke(principal.user()));
        } catch (ReflectiveOperationException | RuntimeException e) {
            throw new IOException("Cannot verify caller identity; start with --add-opens java.base/sun.nio.fs=ALL-UNNAMED");
        }
    }
    @Override public void close() throws IOException { deadlines.shutdownNow(); server.close(); }
}
