package dev.samurai.vpn.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class CoreSecurityTest {
    @TempDir Path temp;

    @Test void rfc7748PublicKeyVector() {
        String privateHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        String publicHex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        String privateKey = Base64.getEncoder().encodeToString(HexFormat.of().parseHex(privateHex));
        String expected = Base64.getEncoder().encodeToString(HexFormat.of().parseHex(publicHex));
        assertEquals(expected, WireGuardKeys.publicFromPrivate(privateKey));
        assertEquals(expected, WireGuardKeys.validatePublic(expected));
    }
    @Test void rejectsLowOrderAndNoncanonicalPublicKeys() {
        assertThrows(IllegalArgumentException.class, () -> WireGuardKeys.validatePublic(Base64.getEncoder().encodeToString(new byte[32])));
        byte[] one = new byte[32]; one[0] = 1;
        assertThrows(IllegalArgumentException.class, () -> WireGuardKeys.validatePublic(Base64.getEncoder().encodeToString(one)));
        byte[] invalid = new byte[32]; Arrays.fill(invalid, (byte) 255);
        assertThrows(IllegalArgumentException.class, () -> WireGuardKeys.validatePublic(Base64.getEncoder().encodeToString(invalid)));
    }
    @Test void tokensAreDistinctAndComparedAsHashes() {
        String first = Tokens.generate(), second = Tokens.generate();
        assertNotEquals(first, second);
        assertTrue(Tokens.valid(first)); assertTrue(Tokens.matches(first, Tokens.hash(first)));
        assertFalse(Tokens.matches(second, Tokens.hash(first))); assertFalse(Tokens.matches(null, Tokens.hash(first)));
        assertFalse(Tokens.matches("bad", Tokens.hash(first)));
    }
    @Test void profileIsSplitTunnelAndCannotInjectCommands() {
        var identity = WireGuardKeys.generate();
        var peer = new Api.Peer(UUID.randomUUID().toString(), "Bob", WireGuardKeys.generate().publicKey(), "10.203.1.2", "192.168.1.9:51820");
        String config = WireGuardConfig.render(identity, "10.203.1.1", 51820, List.of(peer));
        assertTrue(config.contains("AllowedIPs = 10.203.1.2/32")); assertFalse(config.contains("0.0.0.0/0"));
        assertFalse(config.contains("PostUp")); assertFalse(config.contains("DNS ="));
        assertThrows(IllegalArgumentException.class, () -> Validation.endpoint("1.2.3.4:51820\nPostUp = evil"));
        assertThrows(IllegalArgumentException.class, () -> Validation.endpoint("attacker.example:51820"));
        assertThrows(IllegalArgumentException.class, () -> Validation.endpoint("224.0.0.1:51820"));
        var bad = new Api.Peer(peer.peerId(), peer.name(), peer.publicKey(), "10.203.2.2", peer.endpoint());
        assertThrows(IllegalArgumentException.class, () -> WireGuardConfig.render(identity, "10.203.1.1", 51820, List.of(bad)));
        assertThrows(IllegalArgumentException.class, () -> WireGuardConfig.render(identity, "10.203.1.1", 51820, List.of(peer, peer)));
    }
    @Test void jsonRejectsDuplicateUnknownTrailingAndCoercedValues() {
        for (String json : List.of("{\"name\":\"one\",\"name\":\"two\"}", "{\"name\":\"one\",\"privateKey\":\"secret\"}",
                "{\"name\":\"one\"} {}", "{\"name\":123}"))
            assertThrows(Exception.class, () -> Json.MAPPER.readValue(json, Api.CreateNetwork.class), json);
    }
    @Test void credentialFilesArePrivateAndNeverOverwritten() throws Exception {
        Path file = temp.resolve("credential.json");
        SecretFiles.writeNew(file, "original");
        assertEquals("original", SecretFiles.read(file));
        assertThrows(FileAlreadyExistsException.class, () -> SecretFiles.writeNew(file, "replacement"));
        assertEquals("original", SecretFiles.read(file));
        if (Files.getFileStore(file).supportsFileAttributeView("posix")) {
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(file));
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--"));
            assertThrows(java.io.IOException.class, () -> SecretFiles.read(file));
        }
    }
    @Test void outputSymlinkIsNotFollowed() throws Exception {
        if (!Files.getFileStore(temp).supportsFileAttributeView("posix")) return;
        Path original = temp.resolve("original"), link = temp.resolve("link");
        SecretFiles.writeNew(original, "keep"); Files.createSymbolicLink(link, original);
        assertThrows(FileAlreadyExistsException.class, () -> SecretFiles.writeNew(link, "replace"));
        assertThrows(java.io.IOException.class, () -> SecretFiles.read(link));
        assertEquals("keep", SecretFiles.read(original));
    }
    @Test void secretRecordsDoNotLeakInToString() {
        var identity = WireGuardKeys.generate();
        assertFalse(identity.toString().contains(identity.privateKey()));
        String token = Tokens.generate();
        assertFalse(new Api.Joined("n", "p", "ip", token).toString().contains(token));
    }
}
