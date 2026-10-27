package dev.samurai.vpn.desktop;

import dev.samurai.vpn.core.SecretFiles;
import java.nio.file.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class DesktopServiceTest {
    @TempDir Path directory;
    private final DesktopService service = new DesktopService();
    @Test void enrollmentReopenExportAndRevocation() throws Exception {
        try (var demo = LocalDemo.start(directory.resolve("demo"), service)) {
            var owner = demo.profile(); assertTrue(owner.owner()); assertEquals(2, service.refresh(owner, true).peers().size());
            Path invite = directory.resolve("third.json"); service.invite(owner, true, invite);
            var third = service.join(directory.resolve("third"), invite, true, "Третий компьютер", "192.168.1.30:51820");
            var reopened = service.open(third.directory(), true); assertFalse(reopened.owner()); assertEquals(third.session(), reopened.session());
            assertEquals(3, service.refresh(reopened, true).peers().size());
            Path output = directory.resolve("owner.conf"); service.export(owner, true, 51820, output);
            String config = SecretFiles.read(output);
            assertTrue(config.contains("Endpoint = 192.168.1.30:51820")); assertTrue(config.contains(owner.session().identity().privateKey()));
            assertFalse(config.contains(third.session().identity().privateKey()));
            assertThrows(IllegalArgumentException.class, () -> service.invite(third, true, directory.resolve("forbidden.json")));
            assertFalse(Files.exists(directory.resolve("forbidden.json")));
            assertThrows(IllegalArgumentException.class, () -> service.revoke(owner, true, owner.session().membership().peerId()));
            service.revoke(owner, true, third.session().membership().peerId());
            assertThrows(java.io.IOException.class, () -> service.refresh(reopened, true));
            assertEquals(2, service.refresh(owner, true).peers().size());
        }
    }
    @Test void outputCollisionDoesNotConsumeInviteOrOverwriteFiles() throws Exception {
        try (var demo = LocalDemo.start(directory.resolve("demo"), service)) {
            Path invite = directory.resolve("invite.json"); service.invite(demo.profile(), true, invite);
            Path existing = Files.createDirectory(directory.resolve("existing")); Files.writeString(existing.resolve("keep.txt"), "keep");
            assertThrows(FileAlreadyExistsException.class, () -> service.join(existing, invite, true, "Friend", ""));
            assertEquals("keep", Files.readString(existing.resolve("keep.txt")));
            assertNotNull(service.join(directory.resolve("new"), invite, true, "Friend", ""));
            assertThrows(java.io.IOException.class, () -> service.join(directory.resolve("reused"), invite, true, "Again", ""));
        }
    }
    @Test void mixedCredentialsCannotOpenAsOwner() throws Exception {
        try (var one = LocalDemo.start(directory.resolve("one"), service); var two = LocalDemo.start(directory.resolve("two"), service)) {
            Path mixed = Files.createDirectory(directory.resolve("mixed"));
            SecretFiles.writeNew(mixed.resolve("session.json"), SecretFiles.read(one.profile().directory().resolve("session.json")));
            SecretFiles.writeNew(mixed.resolve("owner.json"), SecretFiles.read(two.profile().ownerFile()));
            assertThrows(java.io.IOException.class, () -> service.open(mixed, true));
        }
    }
    @Test void invalidInputFailsBeforeWritingProfile() throws Exception {
        try (var demo = LocalDemo.start(directory.resolve("demo"), service)) {
            Path invite = directory.resolve("invite.json"); service.invite(demo.profile(), true, invite);
            assertThrows(IllegalArgumentException.class, () -> service.join(directory.resolve("http"), invite, false, "Friend", ""));
            assertFalse(Files.exists(directory.resolve("http")));
            assertThrows(IllegalArgumentException.class, () -> service.join(directory.resolve("bad"), invite, true, "Friend", "127.0.0.1:51820\nPostUp = bad"));
            assertFalse(Files.exists(directory.resolve("bad")));
            assertFalse(demo.profile().toString().contains(demo.profile().session().identity().privateKey()));
        }
    }
}
