package dev.samurai.vpn.linux;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.*;

@FunctionalInterface
public interface CommandRunner {
    String run(List<String> command, String input) throws Exception;

    /** No shell, no command/output logging, bounded output and execution time. */
    final class SystemRunner implements CommandRunner {
        public record Result(int exitCode, String output, String errors) {}
        private static final boolean WINDOWS = System.getProperty("os.name").startsWith("Windows");
        private final Duration timeout;
        public SystemRunner(Duration timeout) { this.timeout = timeout; }
        public String run(List<String> command, String input) throws Exception {
            Result result = result(command, input);
            if (result.exitCode() != 0) throw new IOException("Native command failed (exit " + result.exitCode() + ")");
            return result.output();
        }
        public Result result(List<String> command, String input) throws Exception {
            var builder = new ProcessBuilder(command);
            String systemRoot = System.getenv("SystemRoot");
            builder.environment().clear();
            if (WINDOWS) {
                // Windows programs fail to start without SystemRoot; commands are always absolute paths.
                builder.environment().put("SystemRoot", systemRoot == null ? "C:\\Windows" : systemRoot);
                builder.environment().put("PATH", (systemRoot == null ? "C:\\Windows" : systemRoot) + "\\System32");
            } else {
                builder.environment().put("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
                builder.environment().put("LANG", "C.UTF-8");
            }
            Process process = builder.start();
            try (var tasks = Executors.newVirtualThreadPerTaskExecutor()) {
                var out = tasks.submit(() -> bounded(process.getInputStream(), process));
                var err = tasks.submit(() -> bounded(process.getErrorStream(), process));
                var writer = tasks.submit(() -> {
                    try (var stdin = process.getOutputStream()) { stdin.write(input.getBytes(StandardCharsets.UTF_8)); }
                    return true;
                });
                try {
                    if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) throw new IOException("Native operation timed out");
                    writer.get(2, TimeUnit.SECONDS);
                    byte[] bytes = out.get(2, TimeUnit.SECONDS), errors = err.get(2, TimeUnit.SECONDS);
                    return new Result(process.exitValue(), new String(bytes, StandardCharsets.UTF_8), new String(errors, StandardCharsets.UTF_8));
                } finally {
                    process.destroyForcibly();
                    process.getOutputStream().close(); process.getInputStream().close(); process.getErrorStream().close();
                }
            }
        }
        private static byte[] bounded(InputStream stream, Process process) throws IOException {
            byte[] bytes = stream.readNBytes(1_048_577);
            if (bytes.length > 1_048_576) { process.destroyForcibly(); throw new IOException("Native output exceeds limit"); }
            return bytes;
        }
    }
}
