package dev.samurai.vpn.desktop;

import dev.samurai.vpn.linux.*;
import dev.samurai.vpn.macos.MacClient;
import dev.samurai.vpn.windows.WindowsClient;

/** Picks the privileged tunnel component of this OS and describes it to the user. */
final class NativeTunnel {
    private NativeTunnel() {}
    static final boolean WINDOWS = WindowsClient.supported(), MAC = MacClient.supported();
    static boolean supported() { return WINDOWS || MAC || LinuxClient.supported(); }
    /** A component that can bring tunnels up is installed. */
    static boolean installed() { return WINDOWS ? WindowsClient.serviceAvailable() : MAC ? MacClient.serviceAvailable() : LinuxClient.installed(); }
    /** The resident service answers without prompts, which status polling and direct paths require. */
    static boolean resident() { return WINDOWS ? WindowsClient.serviceAvailable() : MAC ? MacClient.serviceAvailable() : LinuxClient.daemonAvailable(); }
    static TunnelBackend client() { return WINDOWS ? new WindowsClient() : MAC ? new MacClient() : new LinuxClient(); }
    /** Windows and macOS always use their resident service: no per-operation password prompt. */
    static boolean serviceOnly() { return WINDOWS || MAC; }
    static String serviceName() { return WINDOWS || MAC ? "службы Samurai VPN" : "службы samurai-vpnd"; }
    static String waiting() { return serviceOnly() ? "Выполняем операцию с туннелем…" : "Ожидаем системное подтверждение…"; }
    static String hint(boolean demonstration) {
        if (!supported()) return "На этой ОС пока доступен экспорт профиля WireGuard.";
        if (WINDOWS && !WindowsClient.wireGuardInstalled()) return "Для подключения установите WireGuard for Windows и службу Samurai VPN (docs/WINDOWS.md).";
        if (!installed()) return WINDOWS ? "Служба Samurai VPN не запущена. Установите её по инструкции docs/WINDOWS.md."
                : MAC ? "Служба Samurai VPN не запущена. Установите её по инструкции docs/MACOS.md."
                : "Для подключения установите системный компонент по инструкции docs/LINUX.md.";
        if (demonstration) return "Демонстрация не меняет сетевые интерфейсы.";
        if (!resident()) return "Работает через pkexec: прямые соединения недоступны, весь трафик через relay. Установите samurai-vpnd (docs/LINUX.md).";
        return "Пока окно открыто, приложение пробует прямые соединения. После закрытия окна туннель продолжит работать через relay.";
    }
}
