package dev.samurai.vpn.windows;

import dev.samurai.vpn.core.Json;
import dev.samurai.vpn.linux.*;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.file.*;
import java.util.List;
import java.util.concurrent.*;

/** Unprivileged GUI bridge to the Samurai tunnel service; the private key travels only over the local socket. */
public final class WindowsClient implements TunnelBackend {
    private final Path socket;
    public WindowsClient() { this(ServiceMain.SOCKET); }
    WindowsClient(Path socket) { this.socket = socket; }

    public static boolean supported() { return System.getProperty("os.name").startsWith("Windows"); }
    public static boolean wireGuardInstalled() { return supported() && Files.isRegularFile(Path.of(WindowsEngine.WIREGUARD)); }
    /** The service creates its socket when it starts; without it the window can only export profiles. */
    public static boolean serviceAvailable() { return wireGuardInstalled() && Files.exists(ServiceMain.SOCKET, LinkOption.NOFOLLOW_LINKS); }

    public TunnelProtocol.Status execute(TunnelProtocol.Request request) throws Exception {
        TunnelProtocol.validate(request);
        // The directory ACL set by the installer is what keeps other users away from this socket.
        if (!Files.exists(socket, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Samurai tunnel service is not running");
        var timer = Executors.newSingleThreadScheduledExecutor(r -> Thread.ofPlatform().daemon().unstarted(r));
        TunnelProtocol.Response response;
        try (var channel = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            timer.schedule(() -> { try { channel.close(); } catch (IOException ignored) {} }, 60, TimeUnit.SECONDS);
            channel.connect(UnixDomainSocketAddress.of(socket));
            ByteBuffer out = ByteBuffer.wrap(Json.MAPPER.writeValueAsBytes(request));
            while (out.hasRemaining()) channel.write(out);
            channel.shutdownOutput();
            ByteBuffer in = ByteBuffer.allocate(1_048_577);
            while (in.hasRemaining() && channel.read(in) >= 0) { /* until EOF */ }
            if (!in.hasRemaining()) throw new IOException("Service response too large");
            try { response = Json.MAPPER.readValue(in.array(), 0, in.position(), TunnelProtocol.Response.class); }
            catch (Exception e) { throw new IOException("Service response unavailable; check tunnel status before retrying"); }
        } catch (java.nio.channels.AsynchronousCloseException e) {
            throw new IOException("Service did not answer; check tunnel status before retrying");
        } finally { timer.shutdownNow(); }
        if (response == null || !response.success() || response.status() == null)
            throw new IOException(response == null ? "Service operation failed" : response.message());
        if (!List.of("up", "down").contains(response.status().state())) throw new IOException("Unexpected service state");
        return response.status();
    }
}
