import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;

/**
 * Builds the installer of this OS into dist/installers (or the given folder), after ./build.sh:
 * Linux .deb (dpkg-deb), macOS .pkg (pkgbuild), Windows setup .exe (Inno Setup 6, ISCC).
 * Run with a JDK from the project root: java scripts/PackageInstaller.java [destination]
 */
class PackageInstaller {
    static final String VERSION = "0.3.0";

    public static void main(String[] args) throws Exception {
        if (args.length > 1) throw new IllegalArgumentException("Usage: package-installer.sh [destination directory]");
        Path destination = Path.of(args.length == 0 ? "dist/installers" : args[0]).toAbsolutePath();
        Files.createDirectories(destination);
        Path work = Files.createTempDirectory("samurai-installer-");
        try {
            String os = System.getProperty("os.name");
            Path output = os.startsWith("Windows") ? windows(work, destination) : os.startsWith("Mac") ? mac(work, destination) : linux(work, destination);
            System.out.println("Installer: " + output);
        } finally { delete(work); }
    }

    private static Path linux(Path work, Path destination) throws Exception {
        Path output = destination.resolve("samurai-vpn_" + VERSION + "_" + capture("dpkg", "--print-architecture") + ".deb");
        refuseExisting(output);
        Path root = work.resolve("root");
        java("scripts/PackageApplication.java", work.resolve("app").toString());
        java("scripts/PackageHelper.java", work.resolve("helper").toString());
        Files.createDirectories(root.resolve("opt"));
        Files.move(work.resolve("app/SamuraiVPN"), root.resolve("opt/samurai-vpn"));
        Files.move(work.resolve("helper"), root.resolve("opt/samurai-vpn-helper"));
        copy("native/linux/samurai-vpnd.service", root.resolve("lib/systemd/system/samurai-vpnd.service"));
        copy("native/linux/deb/samurai-vpn.desktop", root.resolve("usr/share/applications/samurai-vpn.desktop"));
        normalize(root);
        Path control = root.resolve("DEBIAN");
        Files.createDirectories(control);
        long size = 0;
        try (var files = Files.walk(root)) { for (Path file : files.filter(Files::isRegularFile).toList()) size += Files.size(file); }
        Files.writeString(control.resolve("control"), """
                Package: samurai-vpn
                Version: %s
                Architecture: %s
                Maintainer: boyutov <201770339+boyutov@users.noreply.github.com>
                Depends: wireguard-tools, iproute2, systemd
                Recommends: pkexec | policykit-1
                Section: net
                Priority: optional
                Installed-Size: %d
                Homepage: https://github.com/boyutov/Samurai-VPN
                Description: Private networks of friends over WireGuard (preview)
                 Desktop application, the samurai-vpnd tunnel service (temporary systemd user,
                 CAP_NET_ADMIN only) and the pkexec helper in /opt/samurai-vpn-helper.
                """.formatted(VERSION, capture("dpkg", "--print-architecture"), size / 1024));
        for (String script : List.of("postinst", "prerm", "postrm")) {
            copy("native/linux/deb/" + script, control.resolve(script));
            Files.setPosixFilePermissions(control.resolve(script), PosixFilePermissions.fromString("rwxr-xr-x"));
        }
        run(List.of("dpkg-deb", "--root-owner-group", "--build", root.toString(), output.toString()));
        return output;
    }

    private static Path mac(Path work, Path destination) throws Exception {
        Path output = destination.resolve("SamuraiVPN-" + VERSION + ".pkg");
        refuseExisting(output);
        Path root = work.resolve("root"), scripts = work.resolve("scripts"), setup = root.resolve("Library/Application Support/SamuraiVPN Setup");
        java("scripts/PackageApplication.java", work.resolve("app").toString());
        Files.createDirectories(root.resolve("Applications"));
        // ditto keeps the bundle's signature and extended attributes intact.
        run(List.of("/usr/bin/ditto", work.resolve("app/SamuraiVPN.app").toString(), root.resolve("Applications/SamuraiVPN.app").toString()));
        for (String script : List.of("native/macos/install-service.sh", "native/macos/uninstall-service.sh", "native/macos/pkg/uninstall.sh"))
            executable(script, setup.resolve(Path.of(script).getFileName()));
        for (String script : List.of("preinstall", "postinstall")) executable("native/macos/pkg/" + script, scripts.resolve(script));
        // Not relocatable: the service and its scripts expect /Applications/SamuraiVPN.app.
        Path components = work.resolve("components.plist");
        run(List.of("/usr/bin/pkgbuild", "--analyze", "--root", root.toString(), components.toString()));
        run(List.of("/usr/bin/plutil", "-replace", "0.BundleIsRelocatable", "-bool", "NO", components.toString()));
        run(List.of("/usr/bin/pkgbuild", "--root", root.toString(), "--component-plist", components.toString(), "--scripts", scripts.toString(),
                "--identifier", "dev.samurai.vpn", "--version", VERSION, "--install-location", "/", output.toString()));
        return output;
    }

    private static Path windows(Path work, Path destination) throws Exception {
        Path output = destination.resolve("SamuraiVPN-" + VERSION + "-setup.exe");
        refuseExisting(output);
        java("scripts/PackageApplication.java", work.resolve("app").toString());
        String iscc = Optional.ofNullable(System.getenv("ISCC")).orElse(Path.of(Optional.ofNullable(System.getenv("ProgramFiles(x86)"))
                .orElse("C:\\Program Files (x86)"), "Inno Setup 6", "ISCC.exe").toString());
        if (!Files.isRegularFile(Path.of(iscc))) throw new IllegalStateException("Inno Setup 6 is required (choco install innosetup), or set ISCC");
        run(List.of(iscc, "/Q", "/DVersion=" + VERSION, "/DAppImage=" + work.resolve("app/SamuraiVPN"),
                "/DSetupDir=" + Path.of("native/windows").toAbsolutePath(), "/DOutputDir=" + destination, Path.of("native/windows/samurai-vpn.iss").toAbsolutePath().toString()));
        return output;
    }

    private static void java(String script, String argument) throws Exception {
        run(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(), script, argument));
    }
    private static void run(List<String> command) throws Exception {
        int result = new ProcessBuilder(command).inheritIO().start().waitFor();
        if (result != 0) throw new IllegalStateException(command.getFirst() + " failed with exit code " + result);
    }
    private static String capture(String... command) throws Exception {
        var process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes()).strip();
        if (process.waitFor() != 0) throw new IllegalStateException(command[0] + " failed");
        return output;
    }
    private static void refuseExisting(Path output) throws IOException {
        if (Files.exists(output)) throw new FileAlreadyExistsException(output.toString(), null, "Remove it or choose another destination");
    }
    private static void copy(String source, Path target) throws IOException {
        Files.createDirectories(target.getParent());
        Files.copy(Path.of(source), target);
    }
    private static void executable(String source, Path target) throws IOException {
        copy(source, target);
        Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rwxr-xr-x"));
    }
    /** Package contents: nothing writable by group or others; executables stay executable. */
    private static void normalize(Path root) throws IOException {
        try (var paths = Files.walk(root)) {
            for (Path path : paths.toList()) {
                if (Files.isSymbolicLink(path)) continue;
                boolean executable = Files.isDirectory(path) || Files.getPosixFilePermissions(path).contains(java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE);
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(executable ? "rwxr-xr-x" : "rw-r--r--"));
            }
        }
    }
    private static void delete(Path root) throws IOException {
        if (!Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                // jpackage marks the Windows launcher read-only, which blocks deletion there.
                if (System.getProperty("os.name").startsWith("Windows") && !Files.isSymbolicLink(path)) Files.setAttribute(path, "dos:readonly", false);
                Files.delete(path);
            }
        }
    }
}
