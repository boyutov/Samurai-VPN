package dev.samurai.vpn.desktop;

import dev.samurai.vpn.client.Credentials;
import dev.samurai.vpn.core.Api;
import dev.samurai.vpn.linux.*;
import java.awt.*;
import java.awt.event.*;
import java.nio.file.*;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.function.Consumer;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.*;

public final class MainWindow extends JFrame {
    private final Path data;
    private final DesktopService service = new DesktopService();
    private final CardLayout layout = new CardLayout();
    private final JPanel pages = new JPanel(layout);
    private final List<JButton> controls = new ArrayList<>();
    private final JCheckBox devMode = new JCheckBox("Локальный HTTP");
    private final JLabel status = Theme.label("Готово к работе", 13, Theme.MUTED);
    private final JLabel address = Theme.label("—", 25, Theme.TEXT), count = Theme.label("0", 25, Theme.TEXT), access = Theme.label("—", 25, Theme.TEXT);
    private final JLabel network = Theme.label("Сеть пока не выбрана", 14, Theme.MUTED), updated = Theme.label("Список ещё не загружен", 12, Theme.MUTED);
    private final JTextArea location = Theme.paragraph("Создайте сеть, присоединитесь по приглашению или откройте сохранённый профиль.");
    private final JTextArea notice = Theme.paragraph("Сохраните профиль и импортируйте его в WireGuard. Для игры необходим доступный UDP endpoint.");
    private final DefaultTableModel rows = new DefaultTableModel(new String[]{"Устройство", "Виртуальный IP", "Соединение", "Роль"}, 0) {
        @Override public boolean isCellEditable(int row, int column) { return false; }
    };
    private final JTable peers = new JTable(rows);
    private JButton refreshButton, inviteButton, exportButton, revokeButton, joinButton;
    private JButton connectButton, disconnectButton, tunnelStatusButton;
    private final JLabel tunnelTitle = Theme.label("СОСТОЯНИЕ ТУННЕЛЯ НЕ ПРОВЕРЕНО", 12, Theme.WARN);
    private final JLabel helperHint = Theme.label("", 11, Theme.MUTED);
    private DesktopService.Profile profile;
    private List<Api.Peer> members = List.of();
    private java.util.Map<String, PathManager.Path> paths = java.util.Map.of();
    private final AgentFiles agentFiles;
    private javax.swing.Timer agentView;
    private long shownChange;
    private LocalDemo demo;
    private boolean busy, closing;
    private Path invitationFile;
    private Credentials.Invite invitation;
    private JTextField invitationPath, invitationServer;

    public MainWindow(Path data, boolean dev) {
        super("Samurai VPN — сети друзей"); this.data = data; this.agentFiles = new AgentFiles(data);
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE); setMinimumSize(new Dimension(1060, 760));
        setSize(1160, 820); setLocationRelativeTo(null);
        JPanel root = new JPanel(new BorderLayout()); root.setBackground(Theme.BG); setContentPane(root);
        root.add(sidebar(dev), BorderLayout.WEST); pages.setBackground(Theme.BG);
        pages.add(overview(), "overview"); pages.add(createPage(), "create"); pages.add(joinPage(), "join");
        root.add(pages, BorderLayout.CENTER); status.setBorder(new EmptyBorder(12, 24, 12, 24)); status.setName("status");
        root.add(status, BorderLayout.SOUTH);
        addWindowListener(new WindowAdapter() { @Override public void windowClosing(WindowEvent e) { closeWindow(); } });
        updateActions();
    }
    private JButton button(String text, boolean primary, String name, Runnable action) {
        JButton button = Theme.button(text, primary, name, action); controls.add(button); return button;
    }
    private JPanel sidebar(boolean dev) {
        JPanel panel = Theme.column(Theme.PANEL); panel.setBorder(new EmptyBorder(30, 20, 24, 20)); panel.setPreferredSize(new Dimension(228, 700));
        Theme.add(panel, Theme.label("SAMURAI", 26, Theme.ACCENT)); Theme.add(panel, Theme.label("VPN / DESKTOP PREVIEW", 11, Theme.MUTED));
        panel.add(Box.createVerticalStrut(42));
        nav(panel, "Моя сеть", "nav-overview", () -> layout.show(pages, "overview"));
        nav(panel, "Создать сеть", "nav-create", () -> layout.show(pages, "create"));
        nav(panel, "Присоединиться", "nav-join", () -> layout.show(pages, "join"));
        nav(panel, "Открыть профиль", "open-profile", this::openProfile);
        panel.add(Box.createVerticalGlue());
        Theme.add(panel, Theme.paragraph("Начните с демонстрации: два устройства на локальном сервере."));
        panel.add(Box.createVerticalStrut(12)); nav(panel, "Демонстрация", "demo", this::startDemo);
        panel.add(Box.createVerticalStrut(18)); devMode.setSelected(dev); devMode.setName("dev-mode");
        devMode.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        devMode.setToolTipText("HTTP только на 127.0.0.1 и ::1. Для других компьютеров требуется HTTPS.");
        devMode.addActionListener(e -> {
            invitationFile = null; invitation = null;
            if (invitationPath != null) { invitationPath.setText(""); invitationServer.setText(""); }
            updateActions();
        });
        Theme.add(panel, devMode); Theme.add(panel, Theme.label("Windows / Linux / macOS", 11, Theme.MUTED)); return panel;
    }
    private void nav(JPanel panel, String text, String name, Runnable action) {
        JButton b = button(text, false, name, action); b.setHorizontalAlignment(SwingConstants.LEFT);
        b.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44)); Theme.add(panel, b); panel.add(Box.createVerticalStrut(8));
    }
    private JPanel page(String title, String subtitle) {
        JPanel page = new JPanel(new BorderLayout(0, 20)); page.setBackground(Theme.BG); page.setBorder(new EmptyBorder(30, 30, 22, 30));
        JPanel heading = Theme.column(Theme.BG); Theme.add(heading, Theme.label(title, 30, Theme.TEXT));
        heading.add(Box.createVerticalStrut(8)); Theme.add(heading, Theme.paragraph(subtitle)); page.add(heading, BorderLayout.NORTH); return page;
    }
    private JPanel overview() {
        JPanel page = page("Ваша сеть", "Управляйте участниками своей частной сети.");
        JPanel content = new JPanel(new BorderLayout(0, 18)); content.setOpaque(false);
        JPanel top = Theme.column(Theme.BG); Theme.add(top, network); top.add(Box.createVerticalStrut(18));
        JPanel stats = new JPanel(new GridLayout(1, 3, 14, 0)); stats.setOpaque(false); stats.setMaximumSize(new Dimension(Integer.MAX_VALUE, 100));
        stats.add(stat("МОЙ ВИРТУАЛЬНЫЙ IP", address)); stats.add(stat("УЧАСТНИКИ", count)); stats.add(stat("МОИ ПРАВА", access));
        Theme.add(top, stats); top.add(Box.createVerticalStrut(18));
        JPanel warning = Theme.column(Theme.PANEL); warning.setBorder(new EmptyBorder(13, 17, 13, 17));
        Theme.add(warning, tunnelTitle);
        Theme.add(warning, notice);
        JPanel tunnelActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0)); tunnelActions.setOpaque(false);
        connectButton = button("Подключить", true, "tunnel-connect", this::connectTunnel);
        disconnectButton = button("Отключить", false, "tunnel-disconnect", () -> tunnelOperation("down"));
        tunnelStatusButton = button("Проверить туннель", false, "tunnel-status", () -> tunnelOperation("status"));
        tunnelActions.add(connectButton); tunnelActions.add(disconnectButton); tunnelActions.add(tunnelStatusButton);
        Theme.add(warning, tunnelActions); Theme.add(warning, helperHint);
        Theme.add(top, warning); content.add(top, BorderLayout.NORTH);
        JPanel table = new JPanel(new BorderLayout(0, 10)); table.setOpaque(false);
        JPanel header = new JPanel(new BorderLayout()); header.setOpaque(false);
        header.add(Theme.label("Участники сети", 20, Theme.TEXT), BorderLayout.WEST);
        refreshButton = button("Обновить", false, "refresh", this::refresh); header.add(refreshButton, BorderLayout.EAST); table.add(header, BorderLayout.NORTH);
        peers.setName("peers"); peers.setRowHeight(48); peers.setShowGrid(false); peers.setIntercellSpacing(new Dimension(0, 0));
        peers.setSelectionMode(ListSelectionModel.SINGLE_SELECTION); peers.setFillsViewportHeight(true);
        peers.getTableHeader().setReorderingAllowed(false); peers.getTableHeader().setPreferredSize(new Dimension(400, 38));
        peers.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object value, boolean selected, boolean focus, int row, int column) {
                putClientProperty("html.disable", true); super.getTableCellRendererComponent(t, value, selected, focus, row, column);
                setBorder(new EmptyBorder(0, 12, 0, 10)); if (!selected) setForeground(column == 1 ? Theme.ACCENT : Theme.TEXT); return this;
            }
        });
        peers.getSelectionModel().addListSelectionListener(e -> updateActions());
        JScrollPane scroll = new JScrollPane(peers); scroll.setBorder(BorderFactory.createLineBorder(Theme.LINE));
        table.add(scroll, BorderLayout.CENTER); table.add(updated, BorderLayout.SOUTH); content.add(table, BorderLayout.CENTER);
        JPanel bottom = Theme.column(Theme.BG), actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0)); actions.setOpaque(false);
        inviteButton = button("Пригласить друга", true, "invite", this::invite);
        exportButton = button("Сохранить .conf", false, "export", this::export);
        revokeButton = button("Удалить участника", false, "revoke", this::revoke);
        actions.add(inviteButton); actions.add(exportButton); actions.add(revokeButton);
        Theme.add(bottom, actions); bottom.add(Box.createVerticalStrut(12)); Theme.add(bottom, location);
        content.add(bottom, BorderLayout.SOUTH); page.add(content, BorderLayout.CENTER); return page;
    }
    private JPanel stat(String title, JLabel value) {
        JPanel card = Theme.column(Theme.PANEL); card.setBorder(new EmptyBorder(16, 16, 16, 16));
        Theme.add(card, Theme.label(title, 11, Theme.MUTED)); card.add(Box.createVerticalStrut(10)); Theme.add(card, value); return card;
    }
    private void field(JPanel form, String title, JComponent input, String hint) {
        JLabel label = Theme.label(title, 14, Theme.TEXT); label.setLabelFor(input); Theme.add(form, label); form.add(Box.createVerticalStrut(6));
        Theme.add(form, input); if (!hint.isBlank()) Theme.add(form, Theme.paragraph(hint)); form.add(Box.createVerticalStrut(12));
    }
    private void addForm(JPanel page, JPanel form) {
        JScrollPane scroll = new JScrollPane(form); scroll.setBorder(null); scroll.getViewport().setBackground(Theme.BG);
        scroll.getVerticalScrollBar().setUnitIncrement(20); page.add(scroll, BorderLayout.CENTER);
    }
    private JPanel browse(JTextField field, String name, Runnable action) {
        JPanel row = new JPanel(new BorderLayout(8, 0)); row.setOpaque(false); row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        row.add(field, BorderLayout.CENTER); row.add(button("Выбрать…", false, name, action), BorderLayout.EAST); return row;
    }
    private JPanel createPage() {
        JPanel page = page("Создать сеть", "Нужен работающий сервер Samurai и файл токена администратора этого сервера."), form = Theme.column(Theme.BG);
        JTextField server = Theme.field("https://", "create-server"), name = Theme.field("Друзья", "create-name");
        JTextField device = Theme.field("Мой компьютер", "create-device"), endpoint = Theme.field("", "create-endpoint"), token = Theme.field("", "create-token");
        token.setEditable(false);
        field(form, "Адрес сервера", server, "Для подключения через интернет требуется HTTPS.");
        field(form, "Файл токена администратора", browse(token, "choose-token", () -> {
            Path file = choose(false, false, "Выберите admin.token", null); if (file != null) token.setText(file.toString());
        }), "Токен хранится в файле и не показывается в окне.");
        field(form, "Название сети", name, ""); field(form, "Имя этого устройства", device, "");
        field(form, "UDP endpoint этого устройства (необязательно)", endpoint, "IPv4:порт, например 192.168.1.20:51820. Автоматический обход NAT пока не реализован.");
        Theme.add(form, button("Создать и добавить это устройство", true, "create-submit", () -> {
            if (token.getText().isBlank()) { message("Выберите файл токена администратора."); return; }
            String url = server.getText().strip(), n = name.getText().strip(), d = device.getText().strip(), ep = endpoint.getText().strip();
            Path admin = Path.of(token.getText()), directory = next("network"); boolean dev = devMode.isSelected();
            task("Создаём сеть…", () -> service.create(directory, url, dev, admin, n, d, ep), created -> { select(created); refresh(); });
        }));
        form.add(Box.createVerticalStrut(16)); Theme.add(form, Theme.paragraph("Профили сохраняются в " + data + ". Существующие файлы не перезаписываются."));
        addForm(page, form); return page;
    }
    private JPanel joinPage() {
        JPanel page = page("Присоединиться", "Получите файл приглашения у владельца сети. Он действует 10 минут."), form = Theme.column(Theme.BG);
        invitationPath = Theme.field("", "join-invitation"); invitationPath.setEditable(false);
        invitationServer = Theme.field("", "join-server"); invitationServer.setEditable(false);
        JTextField device = Theme.field("Мой компьютер", "join-device"), endpoint = Theme.field("", "join-endpoint");
        field(form, "Файл приглашения", browse(invitationPath, "choose-invitation", () -> {
            Path file = choose(false, false, "Выберите приглашение .json", null); if (file == null) return;
            boolean dev = devMode.isSelected(); invitationFile = null; invitation = null; invitationPath.setText(""); invitationServer.setText("");
            task("Проверяем приглашение…", () -> service.inspectInvite(file, dev), result -> {
                invitationFile = file; invitation = result; invitationPath.setText(file.toString()); invitationServer.setText(result.server());
            });
        }), "Проверьте адрес сервера ниже перед отправкой запроса.");
        field(form, "Сервер из приглашения", invitationServer, "Подключайтесь только к серверу, которому доверяете.");
        field(form, "Имя этого устройства", device, "");
        field(form, "UDP endpoint этого устройства (необязательно)", endpoint, "Если оставить пустым, адрес для прямого туннеля не будет опубликован.");
        joinButton = button("Присоединиться к сети", true, "join-submit", () -> {
            if (invitationFile == null) return;
            Path file = invitationFile, directory = next("network"); Credentials.Invite reviewed = invitation;
            String d = device.getText().strip(), ep = endpoint.getText().strip(); boolean dev = devMode.isSelected();
            task("Присоединяемся…", () -> {
                if (!reviewed.equals(service.inspectInvite(file, dev))) throw new IllegalStateException("Invitation changed");
                return service.join(directory, file, dev, d, ep);
            }, joined -> { select(joined); refresh(); });
        });
        Theme.add(form, joinButton); form.add(Box.createVerticalStrut(16));
        Theme.add(form, Theme.paragraph("Ключ создаётся на этом компьютере. Сервер получает только публичный ключ."));
        addForm(page, form); return page;
    }
    private void openProfile() {
        Path file = choose(false, true, "Выберите папку с session.json", null); if (file == null) return; boolean dev = devMode.isSelected();
        task("Открываем профиль…", () -> service.open(file, dev), opened -> { select(opened); refresh(); });
    }
    private void select(DesktopService.Profile selected) {
        if (selected != profile) stopAgentView();
        profile = selected; members = List.of(); rows.setRowCount(0); count.setText("—");
        address.setText(selected.session().membership().address()); access.setText(selected.owner() ? "Владелец" : "Участник");
        network.setText(selected.session().server() + " / " + selected.session().membership().networkId().substring(0, 8));
        location.setText("Профиль: " + selected.directory()); updated.setText("Список ещё не загружен");
        boolean local = demo != null && selected.directory().equals(demo.profile().directory());
        tunnelTitle.setText(local ? "ЛОКАЛЬНАЯ ДЕМОНСТРАЦИЯ БЕЗ ТУННЕЛЯ" : "СОСТОЯНИЕ ТУННЕЛЯ НЕ ПРОВЕРЕНО");
        tunnelTitle.setForeground(Theme.WARN);
        notice.setText(local ? "Локальная демонстрация: два тестовых устройства. Игровой трафик не передаётся. Сервер остановится при закрытии окна."
                : "Linux: подключите туннель после проверки плана. Для связи с другом нужен доступный UDP endpoint. На других ОС сохраните профиль для WireGuard.");
        layout.show(pages, "overview"); updateActions();
    }
    private void refresh() {
        if (profile == null || busy) return; var selected = profile; boolean dev = devMode.isSelected();
        updated.setText("Получаем актуальный список…");
        task("Обновляем участников…", () -> service.refresh(selected, dev), result -> {
            members = List.copyOf(result.peers()); renderRows();
            count.setText(Integer.toString(members.size()));
            updated.setText("Обновлено в " + LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")) + " · Статус онлайн не проверяется");
            status.setText("Список участников обновлён");
        });
    }
    private void renderRows() {
        int selectedRow = peers.getSelectedRow(); rows.setRowCount(0);
        for (var peer : members) {
            boolean self = peer.peerId().equals(profile.session().membership().peerId());
            var path = paths.get(peer.publicKey());
            String connection = self ? "—" : path == PathManager.Path.DIRECT ? "Напрямую" : path == PathManager.Path.RELAY ? "Через сервер"
                    : path == PathManager.Path.TRYING ? "Пробуем напрямую…" : !peer.candidate().isEmpty() ? "Через сервер (relay)"
                    : peer.endpoint().isBlank() ? "Endpoint не задан" : "Endpoint " + peer.endpoint();
            rows.addRow(new Object[]{peer.name(), peer.address(), connection, self ? "Это устройство" : "Участник"});
        }
        if (selectedRow >= 0 && selectedRow < rows.getRowCount()) peers.setRowSelectionInterval(selectedRow, selectedRow);
    }
    /**
     * A connected tunnel is kept current by the background agent (BackgroundAgent), also after
     * this window closes; the window registers the profile, starts the agent and shows its state.
     */
    private void startAgent() {
        if (agentView != null || profile == null || !NativeTunnel.resident()) return;
        var selected = profile; boolean dev = devMode.isSelected();
        if (demo != null && selected.directory().equals(demo.profile().directory())) return;
        Thread.ofVirtual().start(() -> {
            try {
                agentFiles.update(selected, dev, true);
                AgentProcess.autostart(data, true);
                AgentProcess.ensureRunning(data);
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> updated.setText("Фоновый агент не запущен: прямые соединения и обновление состава недоступны"));
            }
        });
        shownChange = -1;
        agentView = new javax.swing.Timer(5000, event -> showAgent(selected));
        agentView.setInitialDelay(1500); agentView.start();
    }
    private void showAgent(DesktopService.Profile selected) {
        if (profile != selected || agentView == null) return;
        AgentFiles.Network state;
        try { state = agentFiles.network(selected).orElse(null); } catch (Exception e) { state = null; }
        if (state == null) { updated.setText("Ожидаем фоновый агент…"); return; }
        if (!state.error().isEmpty()) { updated.setText("Фоновый агент не получил данные, повторит через 5 с"); return; }
        if (!state.peers().isEmpty()) { members = List.copyOf(state.peers()); count.setText(Integer.toString(members.size())); }
        var current = new java.util.HashMap<String, PathManager.Path>();
        state.paths().forEach((key, path) -> { try { current.put(key, PathManager.Path.valueOf(path)); } catch (IllegalArgumentException ignored) {} });
        paths = java.util.Map.copyOf(current); renderRows();
        if (shownChange >= 0 && state.membershipChanged() > shownChange) status.setText("Состав сети изменился: туннель обновлён без переподключения");
        shownChange = state.membershipChanged();
        updated.setText("Фоновый агент: обновлено в " + LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")));
    }
    private void stopAgentView() {
        if (agentView != null) { agentView.stop(); agentView = null; }
        paths = java.util.Map.of();
    }
    /** The tunnel is down: the agent no longer serves this profile, and nothing starts at login once none is left. */
    private void releaseAgent(DesktopService.Profile selected) {
        stopAgentView();
        Thread.ofVirtual().start(() -> {
            try { if (agentFiles.update(selected, false, false) == 0) AgentProcess.autostart(data, false); }
            catch (Exception e) { SwingUtilities.invokeLater(() -> updated.setText("Не удалось обновить список фонового агента")); }
        });
    }
    private void invite() {
        Path output = choose(true, false, "Сохранить приглашение", "samurai-invite-" + shortId() + ".json");
        if (output == null) return; var selected = profile; boolean dev = devMode.isSelected();
        task("Создаём приглашение…", () -> { service.invite(selected, dev, output); return true; },
                ignored -> message("Приглашение сохранено:\n" + output + "\n\nПередайте другу только этот файл доверенным каналом.\nПриглашение одноразовое и действует 10 минут."));
    }
    private void export() {
        JSpinner port = new JSpinner(new SpinnerNumberModel(51820, 1, 65535, 1));
        JPanel prompt = Theme.column(Theme.PANEL); Theme.add(prompt, Theme.paragraph("UDP-порт WireGuard на этом устройстве:")); Theme.add(prompt, port);
        if (JOptionPane.showConfirmDialog(this, prompt, "Профиль WireGuard", JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) return;
        try { port.commitEdit(); } catch (java.text.ParseException e) { message("Укажите порт от 1 до 65535."); return; }
        Path output = choose(true, false, "Сохранить профиль WireGuard", "samurai-" + shortId() + ".conf");
        if (output == null) return; var selected = profile; boolean dev = devMode.isSelected(); int value = (Integer) port.getValue();
        task("Сохраняем профиль…", () -> { service.export(selected, dev, value, output); return true; },
                ignored -> message("Профиль сохранён:\n" + output + "\n\nИмпортируйте его в WireGuard на этом компьютере.\nОн содержит приватный ключ: не передавайте его другу.\nПриложение не включает туннель автоматически."));
    }
    private void revoke() {
        int row = peers.getSelectedRow(); if (row < 0) return; var peer = members.get(row);
        JTextArea text = Theme.paragraph("Удалить устройство «" + peer.name() + "»?\n\nRelay сразу перестанет пересылать его трафик. Прямой доступ закроется, когда остальные устройства обновят туннель (автоматически, пока их туннель подключён через " + NativeTunnel.serviceName() + ").");
        text.setPreferredSize(new Dimension(450, 120));
        if (JOptionPane.showConfirmDialog(this, text, "Удаление участника", JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) return;
        var selected = profile; boolean dev = devMode.isSelected();
        task("Удаляем участника…", () -> { service.revoke(selected, dev, peer.peerId()); return true; }, ignored -> {
            notice.setText(NativeTunnel.resident()
                    ? "Участник удалён. Устройства с подключённым туннелем уберут его ключ примерно за 30 секунд, даже с закрытым окном. Устройства без " + NativeTunnel.serviceName() + " нужно переподключить."
                    : "Участник удалён из сервера. Переподключите туннель или примените новые профили WireGuard на остальных устройствах, чтобы закрыть ему доступ."); refresh();
        });
    }
    private void connectTunnel() {
        JSpinner port = new JSpinner(new SpinnerNumberModel(51820, 1, 65535, 1));
        JPanel prompt = Theme.column(Theme.PANEL);
        Theme.add(prompt, Theme.paragraph("UDP-порт WireGuard на этом устройстве. Если настроено перенаправление порта, оно должно вести на этот порт."));
        Theme.add(prompt, port); prompt.setPreferredSize(new Dimension(460, 100));
        if (JOptionPane.showConfirmDialog(this, prompt, "Настройка туннеля", JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) return;
        try { port.commitEdit(); } catch (java.text.ParseException e) { message("Укажите порт от 1 до 65535."); return; }
        var selected = profile; boolean dev = devMode.isSelected(); int value = (Integer) port.getValue();
        task("Готовим план подключения…", () -> service.prepareTunnel(selected, dev, value), request -> {
            var config = request.configuration();
            String routes = String.join("\n", config.peers().stream().map(p -> p.address() + "/32").toList());
            JTextArea summary = Theme.paragraph("Будет создан отдельный интерфейс WireGuard.\n\nАдрес: " + config.address() + "/32"
                    + "\nUDP-порт: " + config.listenPort() + "\nMTU: 1280\nМаршруты только к участникам:\n" + routes
                    + (NativeTunnel.WINDOWS ? "\n\nТуннель включит служба Samurai VPN через WireGuard for Windows."
                            : NativeTunnel.MAC ? "\n\nТуннель включит служба Samurai VPN через wireguard-go." : "\n\nПотребуется системное подтверждение администратора.")
                    + " DNS и основной маршрут интернета не меняются."
                    + (NativeTunnel.resident() ? "\n\nПосле закрытия окна туннель обслуживает фоновый агент Samurai VPN (без прав администратора):"
                            + " он обновляет состав сети и прямые соединения и запускается при входе в систему, пока туннель не отключён." : "")
                    + "\nДоступность UDP-портов и firewall нужно настроить отдельно.");
            JScrollPane scroll = new JScrollPane(summary); scroll.setPreferredSize(new Dimension(500, 300));
            if (JOptionPane.showConfirmDialog(this, scroll, "Применить этот план?", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION)
                task(NativeTunnel.waiting(), () -> NativeTunnel.client().execute(request), this::showTunnelStatus);
        });
    }
    private void tunnelOperation(String operation) {
        if (profile == null) return;
        if (operation.equals("down") && JOptionPane.showConfirmDialog(this,
                "Отключить туннель этой сети? Игровое соединение может прерваться.", "Отключение",
                JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) return;
        var request = new TunnelProtocol.Request(operation, profile.session().membership().networkId(), null);
        task(NativeTunnel.waiting(), () -> NativeTunnel.client().execute(request), this::showTunnelStatus);
    }
    private void showTunnelStatus(TunnelProtocol.Status state) {
        boolean up = state.state().equals("up");
        tunnelTitle.setText(up ? "ИНТЕРФЕЙС WIREGUARD ВКЛЮЧЕН" : "ИНТЕРФЕЙС WIREGUARD ОТКЛЮЧЕН");
        tunnelTitle.setForeground(up ? Theme.ACCENT : Theme.WARN);
        if (up) startAgent(); else { releaseAgent(profile); renderRows(); }
        String handshake = state.latestHandshake() == 0 ? "Обмена ключами с участниками пока не было."
                : "Последний обмен ключами: " + java.time.Instant.ofEpochSecond(state.latestHandshake()).atZone(java.time.ZoneId.systemDefault())
                    .format(DateTimeFormatter.ofPattern("HH:mm:ss")) + ". Это не проверка доступности игры.";
        notice.setText(state.interfaceName() + " · Проверено в " + LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"))
                + (up ? "\n" + handshake + "\nПолучено: " + state.receivedBytes() + " байт · Отправлено: " + state.sentBytes() + " байт." : ""));
    }
    void startDemo() {
        if (busy || closing) return;
        if (demo != null) { devMode.setSelected(true); select(demo.profile()); refresh(); return; }
        Path directory = next("demo");
        task("Запускаем локальную демонстрацию…", () -> LocalDemo.start(directory, service), running -> {
            demo = running; devMode.setSelected(true); select(running.profile()); refresh();
        });
    }
    private static String shortId() { return UUID.randomUUID().toString().substring(0, 12); }
    private Path next(String prefix) { return data.resolve(prefix + "-" + shortId()); }
    private Path choose(boolean save, boolean directory, String title, String filename) {
        JFileChooser chooser = new JFileChooser(data.toFile()); chooser.setDialogTitle(title);
        chooser.setFileSelectionMode(directory ? JFileChooser.DIRECTORIES_ONLY : JFileChooser.FILES_ONLY);
        if (filename != null) chooser.setSelectedFile(new java.io.File(filename));
        int result = save ? chooser.showSaveDialog(this) : chooser.showOpenDialog(this);
        return result == JFileChooser.APPROVE_OPTION ? chooser.getSelectedFile().toPath().toAbsolutePath() : null;
    }
    private <T> void task(String title, Callable<T> operation, Consumer<T> success) {
        if (busy || closing) return; busy = true; status.setText(title); status.setForeground(Theme.MUTED); updateActions();
        new SwingWorker<T, Void>() {
            @Override protected T doInBackground() throws Exception { return operation.call(); }
            @Override protected void done() {
                busy = false;
                try {
                    T result = get();
                    if (closing) { if (result instanceof LocalDemo running) running.close(); }
                    else { status.setText("Готово"); success.accept(result); }
                } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                catch (ExecutionException e) { if (!closing) showError(e.getCause()); }
                catch (RuntimeException e) { if (!closing) showError(e); }
                finally { updateActions(); if (closing) finishClose(); }
            }
        }.execute();
    }
    private void showError(Throwable error) {
        String reason = "Проверьте адрес сервера, приглашение и права на файлы.";
        if (error instanceof FileAlreadyExistsException) reason = "Файл или папка уже существует. Выберите новое имя.";
        else if (error.getMessage() != null && error.getMessage().contains("chmod 600")) reason = "Файл доступен другим пользователям. На Linux/macOS установите ему права chmod 600.";
        else if (error instanceof IllegalArgumentException) reason = "Проверьте поля: HTTPS, имя до 64 символов, endpoint IPv4:порт. Для HTTP на этом компьютере включите локальный режим.";
        else if (error instanceof javax.net.ssl.SSLException) reason = "Не удалось подтвердить сертификат HTTPS-сервера.";
        else if (error instanceof java.io.IOException && error.getMessage() != null
                && (error.getMessage().startsWith("Route conflict") || error.getMessage().startsWith("Address conflict")
                    || error.getMessage().startsWith("Interface already") || error.getMessage().startsWith("Administrator authorization")
                    || error.getMessage().startsWith("Refusing to") || error.getMessage().startsWith("Tunnel setup failed")))
            reason = "Операция с туннелем не выполнена:\n" + error.getMessage() + "\nПроверьте состояние кнопкой «Проверить туннель».";
        updated.setText("Данные могут быть устаревшими. Обновление не выполнено."); status.setText("Операция не выполнена"); status.setForeground(Theme.WARN);
        message(reason + "\n\nПри создании сети или входе часть файлов могла сохраниться в:\n" + data + "\nСуществующие ключи не перезаписываются.");
    }
    private void message(String text) {
        JTextArea area = Theme.paragraph(text); area.setFocusable(true);
        JScrollPane scroll = new JScrollPane(area); scroll.setPreferredSize(new Dimension(500, 220)); scroll.setBorder(null);
        JOptionPane.showMessageDialog(this, scroll, "Samurai VPN", JOptionPane.INFORMATION_MESSAGE);
    }
    private void updateActions() {
        for (var control : controls) control.setEnabled(!busy && !closing); devMode.setEnabled(!busy && !closing);
        boolean active = !busy && !closing && profile != null;
        if (refreshButton != null) refreshButton.setEnabled(active);
        if (inviteButton != null) inviteButton.setEnabled(active && profile.owner());
        if (exportButton != null) exportButton.setEnabled(active);
        int row = peers.getSelectedRow();
        if (revokeButton != null) revokeButton.setEnabled(active && profile.owner() && row >= 0 && row < members.size()
                && !members.get(row).peerId().equals(profile.session().membership().peerId()));
        if (joinButton != null) joinButton.setEnabled(!busy && !closing && invitationFile != null);
        boolean demonstration = profile != null && demo != null && profile.directory().equals(demo.profile().directory());
        boolean nativeReady = NativeTunnel.installed();
        boolean tunnelAllowed = active && !demonstration && nativeReady;
        if (connectButton != null) connectButton.setEnabled(tunnelAllowed);
        if (disconnectButton != null) disconnectButton.setEnabled(tunnelAllowed);
        if (tunnelStatusButton != null) tunnelStatusButton.setEnabled(tunnelAllowed);
        helperHint.setText(NativeTunnel.hint(demonstration));
    }
    void closeWindow() { closing = true; updateActions(); status.setText("Завершаем текущую операцию…"); if (!busy) finishClose(); }
    private void finishClose() {
        stopAgentView(); // the background agent keeps running for connected tunnels
        if (demo != null) { demo.close(); demo = null; } dispose(); }
    boolean isBusy() { return busy; }
    JTable peerTable() { return peers; }
}
