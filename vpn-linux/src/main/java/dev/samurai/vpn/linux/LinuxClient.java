package dev.samurai.vpn.linux;

import dev.samurai.vpn.core.Json;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.*;

/** Unprivileged GUI bridge. No configuration file or secret appears in process arguments. */
public final class LinuxClient implements TunnelBackend {
    public static final Path HELPER = Path.of("/opt/samurai-vpn-helper/bin/samurai-vpn-helper");
    private final Path daemonSocket;
    public LinuxClient() { this(DaemonMain.SOCKET); }
    LinuxClient(Path daemonSocket) { this.daemonSocket = daemonSocket; }

    public static boolean supported() { return System.getProperty("os.name").equals("Linux"); }
    /** The resident service runs without password prompts and enables direct-path switching. */
    public static boolean daemonAvailable() { return supported() && Files.exists(DaemonMain.SOCKET); }
    public static boolean installed() {
        return daemonAvailable() || supported() && Files.isExecutable(HELPER) && Files.isExecutable(Path.of("/usr/bin/pkexec"));
    }
    public TunnelProtocol.Status execute(TunnelProtocol.Request request) throws Exception {
        TunnelProtocol.validate(request);
        if (Files.exists(daemonSocket)) return daemon(daemonSocket, request);
        if (request.operation().equals("endpoint")) throw new IOException("Direct connections require the samurai-vpnd service");
        return viaPkexec(request);
    }
    /** One request to a resident service on a Unix socket (samurai-vpnd, or the macOS service). */
    public static TunnelProtocol.Status daemon(Path daemonSocket, TunnelProtocol.Request request) throws Exception {
        TunnelProtocol.validate(request);
        return checked(viaDaemon(daemonSocket, request));
    }
    private static TunnelProtocol.Response viaDaemon(Path daemonSocket, TunnelProtocol.Request request) throws Exception {
        // The private key is sent on "up"; the socket must live in a directory only the service can modify.
        Path directory = daemonSocket.toAbsolutePath().getParent();
        if (Files.isSymbolicLink(directory) || !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Service socket is not trusted");
        var permissions = Files.getPosixFilePermissions(directory, LinkOption.NOFOLLOW_LINKS);
        if (permissions.contains(PosixFilePermission.GROUP_WRITE) || permissions.contains(PosixFilePermission.OTHERS_WRITE))
            throw new IOException("Service socket directory is writable by other users");
        // close() would wait for the pending deadline task, so the timer is shut down explicitly.
        var timer = Executors.newSingleThreadScheduledExecutor(r -> Thread.ofPlatform().daemon().unstarted(r));
        try (var channel = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            timer.schedule(() -> { try { channel.close(); } catch (IOException ignored) {} }, 40, TimeUnit.SECONDS);
            channel.connect(UnixDomainSocketAddress.of(daemonSocket));
            ByteBuffer out = ByteBuffer.wrap(Json.MAPPER.writeValueAsBytes(request));
            while (out.hasRemaining()) channel.write(out);
            channel.shutdownOutput();
            ByteBuffer in = ByteBuffer.allocate(1_048_577);
            while (in.hasRemaining() && channel.read(in) >= 0) { /* until EOF */ }
            if (!in.hasRemaining()) throw new IOException("Service response too large");
            try { return Json.MAPPER.readValue(in.array(), 0, in.position(), TunnelProtocol.Response.class); }
            catch (Exception e) { throw new IOException("Service response unavailable; check tunnel status before retrying"); }
        } catch (java.nio.channels.AsynchronousCloseException e) {
            throw new IOException("Service did not answer; check tunnel status before retrying");
        } finally { timer.shutdownNow(); }
    }
    private TunnelProtocol.Status viaPkexec(TunnelProtocol.Request request) throws Exception {
        if (!Files.isExecutable(HELPER) || !Files.isExecutable(Path.of("/usr/bin/pkexec"))) throw new IOException("Linux helper is not installed");
        // Root ownership prevents escalating code from a user-writable application folder.
        for (Path path = HELPER; path != null; path = path.getParent()) {
            if (Files.isSymbolicLink(path) || (Integer) Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS) != 0)
                throw new IOException("Helper installation is not trusted");
            var permissions = Files.getPosixFilePermissions(path);
            if (permissions.contains(PosixFilePermission.GROUP_WRITE) || permissions.contains(PosixFilePermission.OTHERS_WRITE))
                throw new IOException("Helper installation is writable by other users");
        }
        var result = new CommandRunner.SystemRunner(Duration.ofSeconds(90)).result(
                List.of("/usr/bin/pkexec", "--disable-internal-agent", HELPER.toString()), Json.MAPPER.writeValueAsString(request));
        if (result.exitCode() == 126 || result.exitCode() == 127) throw new IOException("Administrator authorization was cancelled or unavailable");
        TunnelProtocol.Response response;
        try { response = Json.MAPPER.readValue(result.output(), TunnelProtocol.Response.class); }
        catch (Exception e) { throw new IOException("Helper response unavailable; check tunnel status before retrying"); }
        if (response != null && response.success() && result.exitCode() != 0) throw new IOException("Helper operation failed");
        return checked(response);
    }
    private static TunnelProtocol.Status checked(TunnelProtocol.Response response) throws IOException {
        if (response == null || !response.success() || response.status() == null)
            throw new IOException(response == null ? "Helper operation failed" : response.message());
        if (!List.of("up", "down").contains(response.status().state())) throw new IOException("Unexpected helper state");
        return response.status();
    }
}
