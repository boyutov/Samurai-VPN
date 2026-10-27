package dev.samurai.vpn.desktop;

import dev.samurai.vpn.client.*;
import dev.samurai.vpn.core.*;
import dev.samurai.vpn.linux.TunnelProtocol;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;

/** Uses the same validated commands as the CLI, without spawning shell processes. */
public final class DesktopService {
    public record Profile(Path directory, Credentials.Session session, boolean owner) {
        public Path ownerFile() { return directory.resolve("owner.json"); }
        @Override public String toString() { return "Profile[credentials redacted]"; }
    }
    public Profile create(Path directory, String server, boolean dev, Path admin, String name, String device, String endpoint) throws Exception {
        ApiClient.validateOrigin(server, dev); Validation.name(name); Validation.name(device); Validation.endpoint(endpoint);
        if (!Tokens.valid(SecretFiles.read(admin))) throw new IOException("Invalid admin token");
        newDirectory(directory);
        command(dev, "create-network", "--server", server, "--token-file", admin.toString(), "--name", name, "--out", directory.resolve("owner.json").toString());
        command(false, "keygen", "--out", directory.resolve("identity.json").toString());
        command(dev, "invite", "--owner", directory.resolve("owner.json").toString(), "--out", directory.resolve("self-invite.json").toString());
        enroll(directory, directory.resolve("self-invite.json"), dev, device, endpoint);
        return open(directory, dev);
    }
    public Profile join(Path directory, Path invitation, boolean dev, String device, String endpoint) throws Exception {
        inspectInvite(invitation, dev); Validation.name(device); Validation.endpoint(endpoint);
        newDirectory(directory);
        command(false, "keygen", "--out", directory.resolve("identity.json").toString());
        enroll(directory, invitation, dev, device, endpoint);
        return open(directory, dev);
    }
    private void enroll(Path directory, Path invite, boolean dev, String device, String endpoint) throws IOException {
        command(dev, "join", "--invite", invite.toString(), "--identity", directory.resolve("identity.json").toString(),
                "--name", device, "--endpoint", endpoint, "--out", directory.resolve("session.json").toString());
    }
    public Profile open(Path directory, boolean dev) throws Exception {
        directory = directory.toAbsolutePath().normalize();
        var session = read(directory.resolve("session.json"), Credentials.Session.class);
        ApiClient.validateOrigin(session.server(), dev); WireGuardKeys.validateIdentity(session.identity());
        if (session.membership() == null || !Tokens.valid(session.membership().peerToken())) throw new IOException("Invalid session");
        Validation.id(session.membership().networkId()); Validation.id(session.membership().peerId());
        Validation.overlayAddress(session.membership().address());
        boolean owner = Files.exists(directory.resolve("owner.json"), LinkOption.NOFOLLOW_LINKS);
        if (owner) {
            var credential = read(directory.resolve("owner.json"), Credentials.Owner.class);
            if (!Tokens.valid(credential.ownerToken()) || !credential.networkId().equals(session.membership().networkId())
                    || !ApiClient.validateOrigin(credential.server(), dev).equals(ApiClient.validateOrigin(session.server(), dev)))
                throw new IOException("Owner credential belongs to another network");
        }
        return new Profile(directory, session, owner);
    }
    public Credentials.Invite inspectInvite(Path path, boolean dev) throws IOException {
        var invite = read(path, Credentials.Invite.class);
        ApiClient.validateOrigin(invite.server(), dev); Validation.id(invite.networkId());
        if (!Tokens.valid(invite.inviteToken())) throw new IOException("Invalid invitation");
        java.time.Instant.parse(invite.expiresAt());
        return invite;
    }
    public Api.Peers refresh(Profile profile, boolean dev) throws Exception {
        var response = Json.MAPPER.readValue(command(dev, "peers", "--session", profile.directory().resolve("session.json").toString()), Api.Peers.class);
        var membership = profile.session().membership();
        if (!membership.networkId().equals(response.networkId()) || response.peers() == null || response.peers().size() > 64)
            throw new IOException("Invalid peer list");
        var ids = new HashSet<String>();
        for (var peer : response.peers()) {
            if (peer == null || !ids.add(Validation.id(peer.peerId()))) throw new IOException("Invalid peer identity");
            Validation.name(peer.name()); Validation.endpoint(peer.endpoint()); Validation.endpoint(peer.candidate());
        }
        var self = response.peers().stream().filter(p -> p.peerId().equals(membership.peerId())).toList();
        if (self.size() != 1 || !self.getFirst().address().equals(membership.address())
                || !self.getFirst().publicKey().equals(profile.session().identity().publicKey())) throw new IOException("Server membership mismatch");
        WireGuardConfig.render(profile.session().identity(), membership.address(), 51820,
                response.peers().stream().filter(p -> !p.peerId().equals(membership.peerId())).toList());
        return response;
    }
    public void invite(Profile profile, boolean dev, Path output) throws IOException {
        requireOwner(profile);
        command(dev, "invite", "--owner", profile.ownerFile().toString(), "--out", output.toString());
    }
    public void export(Profile profile, boolean dev, int port, Path output) throws IOException {
        Validation.port(port);
        command(dev, "export", "--session", profile.directory().resolve("session.json").toString(),
                "--listen-port", Integer.toString(port), "--out", output.toString());
    }
    public TunnelProtocol.Request prepareTunnel(Profile profile, boolean dev, int port) throws Exception {
        Api.Peers current = refresh(profile, dev);
        var membership = profile.session().membership();
        var others = current.peers().stream().filter(p -> !p.peerId().equals(membership.peerId())).toList();
        var request = new TunnelProtocol.Request("up", membership.networkId(),
                new TunnelProtocol.Configuration(membership.address(), port, profile.session().identity(), others));
        TunnelProtocol.validate(request);
        return request;
    }
    public void revoke(Profile profile, boolean dev, String peerId) throws IOException {
        requireOwner(profile);
        if (peerId.equals(profile.session().membership().peerId())) throw new IllegalArgumentException("Cannot remove your own device here");
        command(dev, "revoke", "--owner", profile.ownerFile().toString(), "--peer", peerId);
    }
    private static void requireOwner(Profile profile) {
        if (!profile.owner()) throw new IllegalArgumentException("Owner required");
    }
    private static <T> T read(Path path, Class<T> type) throws IOException {
        T value = Json.MAPPER.readValue(SecretFiles.read(path), type);
        if (value == null) throw new IOException("Empty credential file");
        return value;
    }
    static String command(boolean dev, String... args) throws IOException {
        var arguments = new ArrayList<>(List.of(args)); if (dev) arguments.add("--dev");
        var output = new ByteArrayOutputStream(); var error = new ByteArrayOutputStream();
        try (var out = new PrintStream(output, true, StandardCharsets.UTF_8); var err = new PrintStream(error, true, StandardCharsets.UTF_8)) {
            if (ClientMain.run(arguments.toArray(String[]::new), out, err) != 0)
                throw new IOException(error.toString(StandardCharsets.UTF_8).strip());
            return output.toString(StandardCharsets.UTF_8);
        }
    }
    static void newDirectory(Path directory) throws IOException {
        var parent = directory.toAbsolutePath().getParent(); Files.createDirectories(parent);
        if (Files.getFileStore(parent).supportsFileAttributeView("posix"))
            Files.createDirectory(directory, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        else Files.createDirectory(directory); // Secret files individually receive a private ACL.
    }
}
