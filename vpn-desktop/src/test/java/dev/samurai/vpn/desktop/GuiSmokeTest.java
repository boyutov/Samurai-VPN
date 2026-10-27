package dev.samurai.vpn.desktop;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.nio.file.*;
import java.util.concurrent.atomic.AtomicReference;
import javax.imageio.ImageIO;
import javax.swing.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

@EnabledIfSystemProperty(named="samurai.gui.test", matches="true")
class GuiSmokeTest {
    @TempDir Path directory;
    @Test @Timeout(40) void demoLoadsTwoDevicesAndKeepsWindowResponsive() throws Exception {
        AtomicReference<MainWindow> reference = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try { Theme.install(); } catch (Exception e) { throw new RuntimeException(e); }
            var window = new MainWindow(directory, false); reference.set(window); window.setVisible(true);
            ((JButton) find(window, "demo")).doClick(); assertTrue(window.isBusy()); assertFalse(find(window, "demo").isEnabled());
        });
        MainWindow window = reference.get();
        try {
            long deadline = System.nanoTime() + java.time.Duration.ofSeconds(25).toNanos(); boolean[] ready = {false};
            while (!ready[0] && System.nanoTime() < deadline) {
                SwingUtilities.invokeAndWait(() -> ready[0] = !window.isBusy() && window.peerTable().getRowCount() == 2);
                if (!ready[0]) Thread.sleep(50);
            }
            assertTrue(ready[0]);
            SwingUtilities.invokeAndWait(() -> {
                assertEquals("10.203.1.1", window.peerTable().getValueAt(0, 1)); assertTrue(find(window, "invite").isEnabled());
                assertFalse(find(window, "tunnel-connect").isEnabled(), "Demo must never activate host interfaces");
                assertFalse(find(window, "tunnel-disconnect").isEnabled());
                window.peerTable().setRowSelectionInterval(0, 0); assertFalse(find(window, "revoke").isEnabled());
                window.peerTable().setRowSelectionInterval(1, 1); assertTrue(find(window, "revoke").isEnabled());
                window.peerTable().clearSelection(); capture(window, "overview");
                ((JButton) find(window, "nav-create")).doClick(); capture(window, "create");
                ((JButton) find(window, "nav-join")).doClick(); assertFalse(find(window, "join-submit").isEnabled()); capture(window, "join");
            });
        } finally { SwingUtilities.invokeAndWait(window::closeWindow); }
        assertFalse(window.isDisplayable());
    }
    private static Component find(Container container, String name) {
        for (Component child : container.getComponents()) {
            if (name.equals(child.getName())) return child;
            if (child instanceof Container nested) { var match = find(nested, name); if (match != null) return match; }
        }
        return null;
    }
    private static void capture(MainWindow window, String name) {
        String output = System.getProperty("samurai.gui.capture"); if (output == null) return;
        try {
            window.validate(); var image = new BufferedImage(window.getWidth(), window.getHeight(), BufferedImage.TYPE_INT_RGB);
            var graphics = image.createGraphics(); window.paint(graphics); graphics.dispose();
            Files.createDirectories(Path.of(output)); ImageIO.write(image, "png", Path.of(output, name + ".png").toFile());
        } catch (Exception e) { throw new RuntimeException(e); }
    }
}
