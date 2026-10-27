package dev.samurai.vpn.desktop;

import dev.samurai.vpn.core.SecretFiles;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * Starts the background agent and registers it to start at login, for the signed-in user only:
 * an XDG autostart entry on Linux, a LaunchAgent on macOS, the HKCU Run key on Windows.
 * Registered while at least one tunnel is connected from the window, removed on the last disconnect.
 */
final class AgentProcess {
    static final String LABEL = "dev.samurai.vpn.agent";
    private AgentProcess() {}

    /** This application: the jpackage launcher, or the running JVM with its class path. */
    static List<String> launcher() {
        String app = System.getProperty("jpackage.app-path");
        if (app != null) return List.of(Path.of(app).toAbsolutePath().toString());
        String java = ProcessHandle.current().info().command().orElse(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        var classPath = new ArrayList<String>();
        for (String part : System.getProperty("java.class.path").split(File.pathSeparator))
            if (!part.isEmpty()) classPath.add(Path.of(part).toAbsolutePath().toString());
        return List.of(java, "-cp", String.join(File.pathSeparator, classPath), DesktopMain.class.getName());
    }
    static List<String> command(Path data) {
        var command = new ArrayList<>(launcher());
        command.addAll(List.of("--agent", "--data-dir", data.toAbsolutePath().normalize().toString()));
        for (String argument : command)
            if (argument.chars().anyMatch(c -> c < 0x20 || c == '"')) throw new IllegalArgumentException("Unsupported character in application path");
        return command;
    }
    /** Starts the agent unless one already serves this data directory; it outlives the window. */
    static void ensureRunning(Path data) throws IOException {
        var files = new AgentFiles(data);
        if (files.agentRunning()) return;
        if (!Files.exists(files.log())) SecretFiles.writeNew(files.log(), "");
        var process = new ProcessBuilder(command(data)).redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.appendTo(files.log().toFile())).start();
        process.getOutputStream().close();
    }

    static void autostart(Path data, boolean enabled) throws Exception {
        String os = System.getProperty("os.name");
        if (os.startsWith("Windows")) windowsRun(enabled ? windowsCommand(command(data)) : null);
        else if (os.startsWith("Mac")) file(Path.of(System.getProperty("user.home"), "Library", "LaunchAgents", LABEL + ".plist"),
                enabled ? launchAgent(command(data)) : null);
        else file(xdgConfig().resolve("autostart").resolve("samurai-vpn-agent.desktop"), enabled ? desktopEntry(command(data)) : null);
    }
    private static Path xdgConfig() {
        String configured = System.getenv("XDG_CONFIG_HOME");
        return configured != null && Path.of(configured).isAbsolute() ? Path.of(configured) : Path.of(System.getProperty("user.home"), ".config");
    }
    private static void file(Path path, String content) throws IOException {
        if (content == null) { Files.deleteIfExists(path); return; }
        Files.createDirectories(path.getParent());
        Path temporary = path.resolveSibling(path.getFileName() + ".tmp");
        Files.deleteIfExists(temporary);
        Files.writeString(temporary, content, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
        Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    /** Desktop Entry Exec quoting: every argument quoted, with ", `, $ and \ escaped, then the string escape of \. */
    static String desktopEntry(List<String> command) {
        var exec = new StringBuilder();
        for (String argument : command) {
            if (exec.length() > 0) exec.append(' ');
            exec.append('"');
            for (char c : argument.toCharArray()) {
                if ("\"`$\\".indexOf(c) >= 0) exec.append('\\');
                exec.append(c == '%' ? "%%" : String.valueOf(c));
            }
            exec.append('"');
        }
        return "[Desktop Entry]\nType=Application\nName=Samurai VPN agent\nComment=Keeps connected Samurai networks current\n"
                + "Exec=" + exec.toString().replace("\\", "\\\\") + "\nNoDisplay=true\nTerminal=false\nX-GNOME-Autostart-enabled=true\n";
    }
    static String launchAgent(List<String> command) {
        var arguments = new StringBuilder();
        for (String argument : command) arguments.append("    <string>").append(xml(argument)).append("</string>\n");
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                <plist version="1.0"><dict>
                  <key>Label</key><string>%s</string>
                  <key>ProgramArguments</key><array>
                %s  </array>
                  <key>RunAtLoad</key><true/>
                  <key>ProcessType</key><string>Background</string>
                </dict></plist>
                """.formatted(LABEL, arguments);
    }
    /** Windows paths cannot contain quotes, so quoting each argument is unambiguous. */
    static String windowsCommand(List<String> command) {
        return String.join(" ", command.stream().map(argument -> "\"" + argument + "\"").toList());
    }
    private static void windowsRun(String value) throws Exception {
        // The value travels in an environment variable, never inside the script text.
        String script = "$ErrorActionPreference = 'Stop'; try { $key = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'; "
                // A silently ignored error still makes -Command exit with 1, so absence is checked first.
                // A new account may not have the Run key yet.
                + (value == null ? "if ((Test-Path $key) -and (Get-ItemProperty -Path $key -Name 'SamuraiVPNAgent' -ErrorAction SilentlyContinue)) "
                        + "{ Remove-ItemProperty -Path $key -Name 'SamuraiVPNAgent' }"
                        : "if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }; "
                        + "Set-ItemProperty -Path $key -Name 'SamuraiVPNAgent' -Value $env:SAMURAI_AGENT_COMMAND")
                + "; exit 0 } catch { [Console]::Out.WriteLine($_.Exception.Message); exit 3 }";
        var builder = new ProcessBuilder(Path.of(System.getenv().getOrDefault("SystemRoot", "C:\\Windows"),
                "System32", "WindowsPowerShell", "v1.0", "powershell.exe").toString(), "-NoProfile", "-NonInteractive", "-Command", script);
        if (value != null) builder.environment().put("SAMURAI_AGENT_COMMAND", value);
        var process = builder.redirectErrorStream(true).start();
        process.getOutputStream().close();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int exit = process.waitFor();
        if (exit != 0) throw new IOException("Cannot change the login item (exit " + exit + "): " + output.strip());
    }
    private static String xml(String text) {
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
