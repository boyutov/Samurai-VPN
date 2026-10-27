package dev.samurai.vpn.desktop;

import dev.samurai.vpn.core.*;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.util.*;

/**
 * Files shared by the window and the background agent, in a private folder of the data directory.
 * profiles.json (written by the window): connected profiles the agent keeps current.
 * status.json (written by the agent): what the window shows. Neither holds keys or tokens;
 * those stay in the profile folders.
 */
final class AgentFiles {
    record Entry(String directory, boolean dev) {}
    record Profiles(int version, List<Entry> profiles) {}
    record Network(boolean up, List<Api.Peer> peers, Map<String, String> paths, long membershipChanged, String error) {}
    record Status(int version, long updated, Map<String, Network> networks) {}
    /** An exclusive lock on a file of the agent folder; closing releases it. */
    static final class Held implements AutoCloseable {
        private final FileChannel channel;
        private Held(FileChannel channel) { this.channel = channel; }
        @Override public void close() throws IOException { channel.close(); }
    }
    private final Path folder;

    AgentFiles(Path data) { this.folder = data.toAbsolutePath().normalize().resolve("agent"); }
    Path folder() { return folder; }
    Path log() { return folder.resolve("agent.log"); }

    List<Entry> profiles() throws IOException {
        Path file = folder.resolve("profiles.json");
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) return List.of();
        var profiles = Json.MAPPER.readValue(SecretFiles.read(file, 65_536), Profiles.class);
        if (profiles == null || profiles.version() != 1 || profiles.profiles() == null || profiles.profiles().size() > 32)
            throw new IOException("Unsupported agent profile list");
        for (var entry : profiles.profiles())
            if (entry == null || entry.directory() == null || !Path.of(entry.directory()).isAbsolute()) throw new IOException("Invalid agent profile entry");
        return List.copyOf(profiles.profiles());
    }
    /** Adds or removes a connected profile; returns how many remain. */
    int update(DesktopService.Profile profile, boolean dev, boolean connected) throws IOException {
        String directory = profile.directory().toAbsolutePath().normalize().toString();
        try (var lock = lock("profiles.lock", false)) {
            var entries = new ArrayList<>(profiles());
            entries.removeIf(entry -> entry.directory().equals(directory));
            if (connected) entries.add(new Entry(directory, dev));
            replace("profiles.json", Json.MAPPER.writeValueAsString(new Profiles(1, entries)));
            return entries.size();
        }
    }
    Optional<Network> network(DesktopService.Profile profile) throws IOException {
        Path file = folder.resolve("status.json");
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) return Optional.empty();
        var status = Json.MAPPER.readValue(SecretFiles.read(file, 1_048_576), Status.class);
        if (status == null || status.version() != 1 || status.networks() == null) return Optional.empty();
        return Optional.ofNullable(status.networks().get(profile.directory().toAbsolutePath().normalize().toString()));
    }
    void status(long now, Map<String, Network> networks) throws IOException {
        replace("status.json", Json.MAPPER.writeValueAsString(new Status(1, now, networks)));
    }
    /** Held by the running agent for its whole life; null if another agent holds it. */
    Held agentLock() throws IOException { return lock("agent.lock", true); }
    boolean agentRunning() throws IOException {
        try (var lock = agentLock()) { return lock == null; }
    }
    private Held lock(String name, boolean tryOnly) throws IOException {
        directory();
        var channel = FileChannel.open(folder.resolve(name), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        try {
            if ((tryOnly ? channel.tryLock() : channel.lock()) != null) return new Held(channel);
            channel.close();
            return null;
        } catch (java.nio.channels.OverlappingFileLockException e) {
            channel.close(); // held elsewhere in this JVM
            return null;
        } catch (IOException | RuntimeException e) { channel.close(); throw e; }
    }
    private void replace(String name, String text) throws IOException {
        directory();
        Path file = folder.resolve(name), temporary = folder.resolve(name + "." + UUID.randomUUID() + ".tmp");
        try {
            SecretFiles.writeNew(temporary, text);
            Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally { Files.deleteIfExists(temporary); }
    }
    private void directory() throws IOException {
        if (Files.isSymbolicLink(folder)) throw new IOException("Agent folder cannot be a symbolic link");
        if (Files.isDirectory(folder)) return;
        DesktopService.newDirectory(folder);
    }
}
