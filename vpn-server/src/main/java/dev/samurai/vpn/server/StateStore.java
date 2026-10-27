package dev.samurai.vpn.server;

import dev.samurai.vpn.core.*;
import java.io.IOException;
import java.nio.channels.*;
import java.nio.file.*;
import java.util.*;

/**
 * Durable control-plane state in one private JSON file. Every change writes a complete
 * snapshot to a create-only temporary file, fsyncs it, renames it over the old file and
 * fsyncs the directory, so a crash leaves either the old or the new state, never a mix.
 * Only token hashes are stored. A lock file keeps a second server off the same state.
 */
class StateStore implements AutoCloseable {
    static final int VERSION = 1, MAX_BYTES = 4 << 20;
    record State(int version, List<NetworkState> networks, List<Relay.Pair> relayPairs) {}
    record NetworkState(String networkId, String name, String ownerHash, int subnet, int nextHost,
                        Map<String, String> invites, List<MemberState> members) {}
    record MemberState(String peerId, String name, String publicKey, String address, String endpoint, String tokenHash) {}

    private final Path file, temporary;
    private final FileChannel lockFile;

    StateStore(Path file) throws IOException {
        this.file = file.toAbsolutePath();
        temporary = this.file.resolveSibling(this.file.getFileName() + ".tmp");
        Files.createDirectories(this.file.getParent());
        lockFile = FileChannel.open(this.file.resolveSibling(this.file.getFileName() + ".lock"),
                StandardOpenOption.CREATE, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
        try {
            if (lockFile.tryLock() == null) throw new IOException("State file is used by another server");
        } catch (OverlappingFileLockException e) {
            lockFile.close(); throw new IOException("State file is used by another server");
        } catch (IOException e) { lockFile.close(); throw e; }
    }
    /** Empty only when no state file exists yet; an unreadable or foreign file stops the server. */
    Optional<State> load() throws IOException {
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) return Optional.empty();
        State state = Json.MAPPER.readValue(SecretFiles.read(file, MAX_BYTES), State.class);
        if (state == null || state.version() != VERSION) throw new IOException("Unsupported state file version");
        return Optional.of(state);
    }
    void save(State state) throws IOException {
        String json = Json.MAPPER.writeValueAsString(state);
        if (json.length() > MAX_BYTES) throw new IOException("State exceeds size limit");
        // Only this server holds the lock, so a leftover temporary file is from an interrupted save.
        Files.deleteIfExists(temporary);
        try (var channel = SecretFiles.reserve(temporary)) { SecretFiles.write(channel, json); }
        Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        // Windows cannot open directories; there the rename itself is the durability point.
        if (Files.getFileStore(file).supportsFileAttributeView("posix"))
            try (var directory = FileChannel.open(file.getParent(), StandardOpenOption.READ)) { directory.force(true); }
    }
    @Override public void close() throws IOException { lockFile.close(); }
}
