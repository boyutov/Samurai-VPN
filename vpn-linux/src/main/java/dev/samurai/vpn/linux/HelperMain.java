package dev.samurai.vpn.linux;

import dev.samurai.vpn.core.Json;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.concurrent.*;

public final class HelperMain {
    public static void main(String[] args) {
        int result = 1;
        try {
            if (args.length != 0 || !System.getProperty("os.name").equals("Linux")) throw new IOException("Linux helper accepts only stdin");
            // /proc gives the effective UID; user.name and caller-controlled Java properties are not trusted.
            String line = Files.readAllLines(Path.of("/proc/self/status")).stream().filter(s -> s.startsWith("Uid:")).findFirst().orElseThrow();
            if (!line.strip().split("\\s+")[2].equals("0")) throw new IOException("Administrator authorization required");
            String caller = System.getenv("PKEXEC_UID");
            if (caller == null || !caller.matches("0|[1-9][0-9]{0,9}")) throw new IOException("Launch through pkexec");
            long uid = Long.parseLong(caller);
            byte[] bytes;
            // Deadline ends before any network mutation. It also handles an input pipe
            // whose writer never closes; interrupt alone cannot unblock every native read.
            Thread watchdog = Thread.ofPlatform().daemon().start(() -> {
                try { Thread.sleep(10_000); System.exit(2); } catch (InterruptedException ignored) {}
            });
            try { bytes = System.in.readNBytes(65_537); }
            finally { watchdog.interrupt(); System.in.close(); }
            if (bytes.length > 65_536) throw new IOException("Request too large");
            var request = Json.MAPPER.readValue(bytes, TunnelProtocol.Request.class); TunnelProtocol.validate(request);
            Path directory = Path.of("/run/samurai-vpn");
            try { Files.createDirectory(directory, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))); }
            catch (FileAlreadyExistsException ignored) {}
            if (Files.isSymbolicLink(directory) || !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)
                    || (Integer) Files.getAttribute(directory, "unix:uid", LinkOption.NOFOLLOW_LINKS) != 0
                    || !Files.getPosixFilePermissions(directory).equals(PosixFilePermissions.fromString("rwx------")))
                throw new IOException("Unsafe helper state directory");
            try (var channel = FileChannel.open(directory.resolve("lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
                 var lock = channel.tryLock()) {
                if (lock == null) throw new IOException("Another tunnel operation is running");
                var state = new LinuxEngine(new CommandRunner.SystemRunner(Duration.ofSeconds(8)), uid).execute(request);
                System.out.println(Json.MAPPER.writeValueAsString(new TunnelProtocol.Response(true, state, "ok"))); result = 0;
            }
        } catch (Exception error) {
            // Never return a parser message, request body, command output or private key.
            try { System.out.println(Json.MAPPER.writeValueAsString(new TunnelProtocol.Response(false, null,
                    error instanceof IOException && error.getMessage() != null ? safeMessage(error.getMessage()) : "Invalid request or native operation failed"))); }
            catch (Exception ignored) { System.err.println("Helper failed"); }
        }
        System.exit(result);
    }
    static String safeMessage(String message) {
        if (message.startsWith("Route conflict") || message.startsWith("Address conflict") || message.startsWith("Interface already")
                || message.startsWith("Refusing to") || message.startsWith("Tunnel setup failed")) return message;
        return "Native operation failed; check permissions, WireGuard support and interface state";
    }
}
