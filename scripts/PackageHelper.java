import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;

class PackageHelper {
    public static void main(String[] args) throws Exception {
        if (!System.getProperty("os.name").equals("Linux") || args.length > 1) throw new IllegalArgumentException("Usage (Linux): package-helper.sh [destination]");
        Path jar = Path.of("vpn-linux/target/samurai-helper.jar");
        if (!Files.isRegularFile(jar)) throw new IllegalStateException("Run ./build.sh first");
        Path destination = Path.of(args.length == 0 ? "dist/helper" : args[0]).toAbsolutePath();
        Files.createDirectories(destination.getParent()); Files.createDirectory(destination);
        Path jlink = Path.of(System.getProperty("java.home"), "bin/jlink");
        int result = new ProcessBuilder(List.of(jlink.toString(), "--add-modules", "java.base,java.sql,jdk.crypto.ec,jdk.unsupported,jdk.net",
                "--strip-debug", "--no-header-files", "--no-man-pages", "--output", destination.resolve("runtime").toString())).inheritIO().start().waitFor();
        if (result != 0) throw new IllegalStateException("jlink failed");
        Files.copy(jar, destination.resolve("samurai-helper.jar")); Files.createDirectory(destination.resolve("bin"));
        Path launcher = destination.resolve("bin/samurai-vpn-helper");
        Files.copy(Path.of("native/linux/samurai-vpn-helper"), launcher);
        Files.setPosixFilePermissions(launcher, PosixFilePermissions.fromString("rwxr-xr-x"));
        Path daemon = destination.resolve("bin/samurai-vpnd");
        Files.copy(Path.of("native/linux/samurai-vpnd"), daemon);
        Files.setPosixFilePermissions(daemon, PosixFilePermissions.fromString("rwxr-xr-x"));
        Files.copy(Path.of("docs/LINUX.md"), destination.resolve("LINUX.md"));
        System.out.println("Prepared helper bundle: " + destination);
        System.out.println("Review docs/LINUX.md, then: sudo ./native/linux/install-helper.sh && sudo ./native/linux/install-daemon.sh");
    }
}
