package dev.samurai.vpn.desktop;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AgentProcessTest {
    @Test void loginEntriesQuoteEveryArgument() {
        var command = List.of("/opt/Samurai VPN/bin/SamuraiVPN", "--agent", "--data-dir", "/home/a b/$x`y\\z%");
        String desktop = AgentProcess.desktopEntry(command);
        assertTrue(desktop.contains("Exec=\"/opt/Samurai VPN/bin/SamuraiVPN\" \"--agent\" \"--data-dir\" \"/home/a b/\\\\$x\\\\`y\\\\\\\\z%%\"\n"), desktop);
        assertTrue(desktop.contains("NoDisplay=true"));

        String plist = AgentProcess.launchAgent(List.of("/Applications/Samurai VPN.app/Contents/MacOS/SamuraiVPN", "--agent", "--data-dir", "/Users/a&b/<x>"));
        assertTrue(plist.contains("<string>/Users/a&amp;b/&lt;x&gt;</string>"), plist);
        assertTrue(plist.contains("<key>RunAtLoad</key><true/>") && plist.contains(AgentProcess.LABEL));

        assertEquals("\"C:\\Program Files\\SamuraiVPN\\SamuraiVPN.exe\" \"--agent\"",
                AgentProcess.windowsCommand(List.of("C:\\Program Files\\SamuraiVPN\\SamuraiVPN.exe", "--agent")));
    }
    @Test void commandStartsThisApplicationInAgentMode() {
        var command = AgentProcess.command(Path.of("data"));
        assertEquals(List.of("--agent", "--data-dir", Path.of("data").toAbsolutePath().toString()), command.subList(command.size() - 3, command.size()));
        assertTrue(command.contains(DesktopMain.class.getName()), "development run: JVM, class path and main class");
        assertThrows(IllegalArgumentException.class, () -> AgentProcess.command(Path.of("/tmp/bad\"name")));
    }
}
