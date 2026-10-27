package dev.samurai.vpn.desktop;

import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/**
 * The background agent: an unprivileged process of the signed-in user (DesktopMain --agent)
 * that keeps connected networks current while no window is open. It talks to the tunnel
 * service over the same socket as the window. One agent per data directory (agent.lock).
 */
final class BackgroundAgent {
    interface Factory { NetworkAgent create(AgentFiles.Entry entry) throws Exception; }
    static final long TICK_SECONDS = 5;
    // Grace for a tunnel that is still starting after login (Windows starts tunnel services at boot).
    static final long IDLE_EXIT_SECONDS = 90;
    private final AgentFiles files;
    private final Factory factory;
    private final Map<String, NetworkAgent> agents = new HashMap<>();
    private long lastUp;

    BackgroundAgent(AgentFiles files, Factory factory, long now) { this.files = files; this.factory = factory; this.lastUp = now; }

    /** One step; returns false when the agent should exit: nothing registered, or no tunnel up for a while. */
    boolean tick(long now) throws Exception {
        var entries = files.profiles();
        var wanted = new HashSet<String>();
        for (var entry : entries) wanted.add(entry.directory());
        // Disconnected in the window: give its peers back to the relay before forgetting it.
        for (var iterator = agents.entrySet().iterator(); iterator.hasNext(); ) {
            var agent = iterator.next();
            if (!wanted.contains(agent.getKey())) { agent.getValue().restoreRelay(); iterator.remove(); }
        }
        var networks = new LinkedHashMap<String, AgentFiles.Network>();
        for (var entry : entries) {
            try {
                var agent = agents.get(entry.directory());
                if (agent == null) { agent = factory.create(entry); agents.put(entry.directory(), agent); }
                var snapshot = agent.tick(now);
                if (snapshot.up()) lastUp = now;
                var paths = new LinkedHashMap<String, String>();
                snapshot.paths().forEach((key, path) -> paths.put(key, path.name()));
                networks.put(entry.directory(), new AgentFiles.Network(snapshot.up(), snapshot.peers(), paths, snapshot.membershipChanged(), ""));
            } catch (Exception e) {
                // Server or service unreachable: keep the tunnel as it is and retry on the next tick.
                networks.put(entry.directory(), new AgentFiles.Network(false, List.of(), Map.of(), 0, failure(e)));
            }
        }
        files.status(now, networks);
        return !entries.isEmpty() && recentlyUp(now);
    }
    boolean recentlyUp(long now) { return now - lastUp < IDLE_EXIT_SECONDS; }
    void stop() {
        for (var agent : agents.values()) agent.restoreRelay();
        agents.clear();
    }
    private static String failure(Exception e) {
        String message = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        return message.length() > 200 ? message.substring(0, 200) : message;
    }

    /** Entry point of DesktopMain --agent; returns the exit code. */
    static int run(Path data) throws Exception {
        var files = new AgentFiles(data);
        var service = new DesktopService();
        try (var lock = files.agentLock()) {
            if (lock == null) return 0; // another agent already serves this data directory
            if (!NativeTunnel.resident()) { System.err.println("Samurai agent: the tunnel service is not running"); return 1; }
            var agent = new BackgroundAgent(files, entry -> {
                var profile = service.open(Path.of(entry.directory()), entry.dev());
                return NetworkAgent.of(service, profile, entry.dev());
            }, Instant.now().getEpochSecond());
            // Logout and shutdown: hand direct peers back to the relay first.
            var stopping = Thread.ofPlatform().unstarted(agent::stop);
            Runtime.getRuntime().addShutdownHook(stopping);
            while (true) {
                boolean keep;
                try { keep = agent.tick(Instant.now().getEpochSecond()); }
                catch (Exception e) { System.err.println("Samurai agent: " + failure(e)); keep = agent.recentlyUp(Instant.now().getEpochSecond()); }
                if (!keep) break;
                Thread.sleep(TICK_SECONDS * 1000);
            }
            Runtime.getRuntime().removeShutdownHook(stopping);
            agent.stop();
            return 0;
        }
    }
}
