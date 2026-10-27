package dev.samurai.vpn.client;

import dev.samurai.vpn.core.*;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.Set;

public final class ClientMain {
    private ClientMain() {}
    public static void main(String[] args) { System.exit(run(args, System.out, System.err)); }
    public static int run(String[] args, PrintStream out, PrintStream err) {
        try {
            if (args.length == 0 || args[0].equals("--help")) { help(out); return 0; }
            String command = args[0];
            Set<String> allowed = switch (command) {
                case "gen-admin", "keygen" -> Set.of("--out");
                case "create-network" -> Set.of("--server", "--token-file", "--name", "--out");
                case "invite" -> Set.of("--owner", "--out");
                case "join" -> Set.of("--invite", "--identity", "--name", "--endpoint", "--out");
                case "peers" -> Set.of("--session");
                case "export" -> Set.of("--session", "--out", "--listen-port");
                case "revoke" -> Set.of("--owner", "--peer");
                default -> throw new IllegalArgumentException("Unknown command: " + command);
            };
            Arguments options = new Arguments(args, 1, Set.of("--dev"), allowed);
            switch (command) {
                case "gen-admin" -> {
                    SecretFiles.writeNew(output(options), Tokens.generate() + "\n");
                    out.println("Admin token saved to " + output(options));
                }
                case "keygen" -> {
                    save(output(options), WireGuardKeys.generate());
                    out.println("WireGuard identity saved to " + output(options));
                }
                case "create-network" -> create(options, out);
                case "invite" -> invite(options, out);
                case "join" -> join(options, out);
                case "peers" -> {
                    var session = session(options);
                    try (var api = new ApiClient(session.server(), options.has("--dev"))) {
                        out.println(Json.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(peers(api, session)));
                    }
                }
                case "export" -> export(options, out);
                case "revoke" -> {
                    var owner = read(Path.of(options.require("--owner")), Credentials.Owner.class);
                    String id = Validation.id(owner.networkId()), peerId = Validation.id(options.require("--peer"));
                    try (var api = new ApiClient(owner.server(), options.has("--dev"))) {
                        api.request("DELETE", "/v1/networks/" + id + "/peers/" + peerId, owner.ownerToken(), null, com.fasterxml.jackson.databind.JsonNode.class);
                    }
                    out.println("API membership revoked. Export and reapply profiles on ALL remaining devices to remove tunnel access.");
                }
                default -> throw new IllegalStateException();
            }
            return 0;
        } catch (InterruptedException e) { Thread.currentThread().interrupt(); err.println("Interrupted"); return 1; }
        catch (Exception e) { err.println("Operation failed: " + safeMessage(e)); return 1; }
    }
    private static String safeMessage(Exception e) {
        if (e instanceof com.fasterxml.jackson.core.JsonProcessingException) return "Invalid local JSON file";
        if (e instanceof NullPointerException) return "Incomplete credential file";
        return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
    }
    private static void create(Arguments options, PrintStream out) throws Exception {
        String token = SecretFiles.read(Path.of(options.require("--token-file")));
        String name = Validation.name(options.require("--name"));
        try (var api = new ApiClient(options.require("--server"), options.has("--dev"));
             var file = SecretFiles.reserve(output(options))) {
            var network = api.request("POST", "/v1/networks", token, new Api.CreateNetwork(name), Api.NetworkCreated.class);
            SecretFiles.write(file, json(new Credentials.Owner(api.origin(), Validation.id(network.networkId()), network.ownerToken())));
            out.println("Network created: " + network.networkId() + "; owner credential saved to " + output(options));
        }
    }
    private static void invite(Arguments options, PrintStream out) throws Exception {
        var owner = read(Path.of(options.require("--owner")), Credentials.Owner.class);
        String id = Validation.id(owner.networkId());
        try (var api = new ApiClient(owner.server(), options.has("--dev")); var file = SecretFiles.reserve(output(options))) {
            var invite = api.request("POST", "/v1/networks/" + id + "/invites", owner.ownerToken(), null, Api.InviteCreated.class);
            if (!id.equals(invite.networkId())) throw new IOException("Server returned the wrong network");
            SecretFiles.write(file, json(new Credentials.Invite(api.origin(), id, invite.inviteToken(), invite.expiresAt())));
            out.println("One-use invitation saved to " + output(options) + "; expires " + invite.expiresAt());
        }
    }
    private static void join(Arguments options, PrintStream out) throws Exception {
        var invite = read(Path.of(options.require("--invite")), Credentials.Invite.class);
        var identity = read(Path.of(options.require("--identity")), WireGuardKeys.Identity.class);
        WireGuardKeys.validateIdentity(identity);
        String id = Validation.id(invite.networkId());
        var request = new Api.Join(Validation.name(options.require("--name")), identity.publicKey(),
                Validation.endpoint(options.get("--endpoint", "")));
        try (var api = new ApiClient(invite.server(), options.has("--dev")); var file = SecretFiles.reserve(output(options))) {
            var joined = api.request("POST", "/v1/networks/" + id + "/peers", invite.inviteToken(), request, Api.Joined.class);
            if (!id.equals(joined.networkId()) || !Tokens.valid(joined.peerToken())) throw new IOException("Invalid enrollment response");
            Validation.overlayAddress(joined.address()); Validation.id(joined.peerId());
            SecretFiles.write(file, json(new Credentials.Session(api.origin(), identity, joined)));
            out.println("Joined as " + joined.peerId() + " at " + joined.address());
        }
    }
    private static void export(Arguments options, PrintStream out) throws Exception {
        var session = session(options);
        int port = Validation.port(Integer.parseInt(options.get("--listen-port", "51820")));
        try (var api = new ApiClient(session.server(), options.has("--dev"))) {
            var response = peers(api, session);
            var self = response.peers().stream().filter(p -> p.peerId().equals(session.membership().peerId())).toList();
            if (self.size() != 1 || !self.getFirst().publicKey().equals(session.identity().publicKey())
                    || !self.getFirst().address().equals(session.membership().address())) throw new IOException("Server membership mismatch");
            var others = response.peers().stream().filter(p -> !p.peerId().equals(session.membership().peerId())).toList();
            String config = WireGuardConfig.render(session.identity(), session.membership().address(), port, others);
            SecretFiles.writeNew(output(options), config);
            out.println("WireGuard profile saved to " + output(options) + "; peers: " + others.size());
            out.println("Import into WireGuard to activate. Peers without a reachable endpoint use the server relay if it is enabled.");
        }
    }
    private static Credentials.Session session(Arguments options) throws IOException {
        var session = read(Path.of(options.require("--session")), Credentials.Session.class);
        WireGuardKeys.validateIdentity(session.identity());
        Validation.id(session.membership().networkId()); Validation.id(session.membership().peerId());
        return session;
    }
    private static Api.Peers peers(ApiClient api, Credentials.Session session) throws Exception {
        String id = session.membership().networkId();
        var response = api.request("GET", "/v1/networks/" + id + "/peers", session.membership().peerToken(), null, Api.Peers.class);
        if (!id.equals(response.networkId()) || response.peers() == null || response.peers().size() > 64)
            throw new IOException("Invalid peer list from server");
        return response;
    }
    private static Path output(Arguments options) { return Path.of(options.require("--out")); }
    private static <T> T read(Path path, Class<T> type) throws IOException {
        T value = Json.MAPPER.readValue(SecretFiles.read(path), type);
        if (value == null) throw new IOException("Credential file is empty");
        return value;
    }
    private static String json(Object value) throws IOException { return Json.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(value) + "\n"; }
    private static void save(Path path, Object value) throws IOException { SecretFiles.writeNew(path, json(value)); }
    private static void help(PrintStream out) {
        out.println("""
                Samurai VPN — Java client, development milestone 0.3
                gen-admin      --out PATH
                keygen         --out PATH
                create-network --server https://host:8787 --token-file PATH --name NAME --out OWNER.json
                invite         --owner OWNER.json --out INVITE.json
                join           --invite INVITE.json --identity IDENTITY.json --name NAME [--endpoint IPv4:PORT] --out SESSION.json
                peers          --session SESSION.json
                export         --session SESSION.json --out PROFILE.conf [--listen-port 51820]
                revoke         --owner OWNER.json --peer UUID

                Add --dev for LOCAL HTTP development. Credentials are files, never command-line secrets.
                All output files are create-only; choose a new name for each export/invitation.
                Imported invitation and credential files need owner-only access (chmod 600 on Linux/macOS).
                Desktop UI: ./samurai.sh desktop
                Linux tunnel controls are available in the desktop after helper installation.
                The server may relay WireGuard ciphertext (--relay-host); hole punching and persistent storage are not yet implemented.
                """);
    }
}
