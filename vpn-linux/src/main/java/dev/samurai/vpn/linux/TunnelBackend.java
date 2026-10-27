package dev.samurai.vpn.linux;

/** The GUI side of a privileged tunnel component (LinuxClient, WindowsClient). */
public interface TunnelBackend {
    TunnelProtocol.Status execute(TunnelProtocol.Request request) throws Exception;
}
