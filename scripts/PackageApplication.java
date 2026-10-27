import java.nio.file.*;
import java.util.*;

/** Run from the project root using a JDK: java scripts/PackageApplication.java [destination]. */
class PackageApplication {
    static final String VERSION = "0.3.0";
    public static void main(String[] args) throws Exception {
        if (args.length > 1) throw new IllegalArgumentException("Usage: package.sh [destination directory]");
        Path jar = Path.of("vpn-desktop/target/samurai-desktop.jar").toAbsolutePath();
        if (!Files.isRegularFile(jar)) throw new IllegalStateException("Build first: ./build.sh or mvn verify");
        String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
        boolean windows = os.startsWith("windows"), mac = os.contains("mac");
        Path jpackage = Path.of(System.getProperty("java.home"), "bin", windows ? "jpackage.exe" : "jpackage");
        if (!Files.isExecutable(jpackage)) throw new IllegalStateException("Packaging requires a full JDK with jpackage");
        Path destination = Path.of(args.length == 0 ? "dist" : args[0]).toAbsolutePath();
        Path image = destination.resolve(mac ? "SamuraiVPN.app" : "SamuraiVPN");
        if (Files.exists(image, LinkOption.NOFOLLOW_LINKS)) throw new FileAlreadyExistsException(image.toString(), null, "Choose a new destination");
        Files.createDirectories(destination);
        Path input = Files.createTempDirectory("samurai-package-input-");
        try {
            Files.copy(jar, input.resolve(jar.getFileName()));
            var command = new ArrayList<>(List.of(jpackage.toString(), "--type", "app-image",
                    "--input", input.toString(), "--dest", destination.toString(), "--name", "SamuraiVPN",
                    "--main-jar", jar.getFileName().toString(), "--main-class", "dev.samurai.vpn.desktop.DesktopMain",
                    "--vendor", "Samurai VPN",
                    "--description", "Samurai VPN development preview",
                    // jdk.net: the macOS service reads the caller's UID (SO_PEERCRED) through it.
                    "--add-modules", "java.desktop,java.net.http,java.sql,jdk.httpserver,jdk.crypto.ec,jdk.localedata,jdk.unsupported,jdk.net",
                    "--java-options", "-Dfile.encoding=UTF-8",
                    // jpackage's defaults minus --strip-native-commands: the tunnel services run runtime/bin/java.
                    "--jlink-options", "--strip-debug --no-man-pages --no-header-files"));
            // macOS bundles require a first version number of at least 1; until 1.0 they keep jpackage's default.
            if (!mac) command.addAll(List.of("--app-version", VERSION));
            Process process = new ProcessBuilder(command).inheritIO().start();
            int result = process.waitFor();
            if (result != 0) throw new IllegalStateException("jpackage failed with exit code " + result);
            Path launcher = mac ? image.resolve("Contents/MacOS/SamuraiVPN")
                    : image.resolve(windows ? "SamuraiVPN.exe" : "bin/SamuraiVPN");
            System.out.println("Application with bundled runtime: " + image);
            System.out.println("Launch: " + launcher);
            System.out.println("Keep the entire application folder. Separate Java installation is not required.");
        } finally {
            Files.deleteIfExists(input.resolve(jar.getFileName()));
            Files.delete(input);
        }
    }
}
