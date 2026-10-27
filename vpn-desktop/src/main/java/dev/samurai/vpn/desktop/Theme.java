package dev.samurai.vpn.desktop;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.plaf.FontUIResource;
import javax.swing.plaf.basic.BasicButtonUI;
import java.awt.*;

final class Theme {
    static final Color BG = new Color(0x101722), PANEL = new Color(0x192331), LINE = new Color(0x2C3A4C);
    static final Color TEXT = new Color(0xF0F4F8), MUTED = new Color(0xA6B4C7), ACCENT = new Color(0x91E6BB), WARN = new Color(0xF5D18A);
    static void install() throws Exception {
        UIManager.setLookAndFeel("javax.swing.plaf.metal.MetalLookAndFeel");
        for (Object key : java.util.Collections.list(UIManager.getDefaults().keys()))
            if (UIManager.get(key) instanceof FontUIResource) UIManager.put(key, new FontUIResource(Font.SANS_SERIF, Font.PLAIN, 14));
        for (String key : new String[]{"Panel.background", "OptionPane.background", "Viewport.background", "Table.background", "List.background"}) UIManager.put(key, PANEL);
        for (String key : new String[]{"Label.foreground", "OptionPane.messageForeground", "CheckBox.foreground", "Table.foreground", "List.foreground", "TextField.foreground"}) UIManager.put(key, TEXT);
        UIManager.put("TextField.background", BG); UIManager.put("TextField.caretForeground", ACCENT);
        UIManager.put("Table.selectionBackground", new Color(0x2C4F4C)); UIManager.put("Table.selectionForeground", TEXT);
        UIManager.put("TableHeader.background", PANEL); UIManager.put("TableHeader.foreground", MUTED);
        UIManager.put("CheckBox.background", PANEL); UIManager.put("Button.background", LINE); UIManager.put("Button.foreground", TEXT);
        UIManager.put("Button.disabledText", MUTED); UIManager.put("List.selectionBackground", LINE);
    }
    static JLabel label(String text, int size, Color color) {
        JLabel label = new JLabel(text); label.putClientProperty("html.disable", true);
        label.setFont(new Font(Font.SANS_SERIF, size >= 22 ? Font.BOLD : Font.PLAIN, size)); label.setForeground(color); return label;
    }
    static JTextArea paragraph(String text) {
        JTextArea area = new JTextArea(text); area.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14)); area.setForeground(MUTED);
        area.setOpaque(false); area.setEditable(false); area.setLineWrap(true); area.setWrapStyleWord(true); area.setFocusable(false);
        area.setBorder(new EmptyBorder(4, 0, 4, 0)); return area;
    }
    static JPanel column(Color color) {
        JPanel panel = new JPanel(); panel.setBackground(color); panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS)); return panel;
    }
    static void add(JPanel panel, JComponent component) { component.setAlignmentX(Component.LEFT_ALIGNMENT); panel.add(component); }
    static JTextField field(String text, String name) {
        JTextField field = new JTextField(text); field.setName(name);
        field.setBorder(new CompoundBorder(new LineBorder(LINE), new EmptyBorder(10, 12, 10, 12)));
        field.setPreferredSize(new Dimension(360, 42)); field.setMaximumSize(new Dimension(Integer.MAX_VALUE, 42)); return field;
    }
    static JButton button(String text, boolean primary, String name, Runnable action) {
        JButton button = new JButton(text) {
            @Override protected void paintComponent(Graphics graphics) {
                Graphics2D g = (Graphics2D) graphics.create();
                g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                Color base = primary ? ACCENT : LINE;
                g.setColor(!isEnabled() ? PANEL : getModel().isRollover() ? base.brighter() : base);
                g.fillRoundRect(0, 0, getWidth(), getHeight(), 12, 12); g.dispose(); super.paintComponent(graphics);
                if (hasFocus()) { graphics.setColor(ACCENT); graphics.drawRoundRect(2, 2, getWidth()-5, getHeight()-5, 10, 10); }
            }
        };
        button.setName(name); button.setUI(new BasicButtonUI()); button.setContentAreaFilled(false);
        button.setForeground(primary ? BG : TEXT); button.setFocusPainted(false); button.setBorder(new EmptyBorder(12, 16, 12, 16));
        button.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)); button.addActionListener(e -> action.run()); return button;
    }
}
