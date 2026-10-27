package dev.samurai.vpn.core;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.EnumSet;
import java.util.List;

/** Create-only credential files: restrictive permissions are applied at creation, not afterwards. */
public final class SecretFiles {
    private SecretFiles() {}
    public static FileChannel reserve(Path path) throws IOException {
        Path parent = path.toAbsolutePath().getParent();
        Files.createDirectories(parent);
        FileAttribute<?> attribute;
        if (Files.getFileStore(parent).supportsFileAttributeView("posix")) {
            attribute = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"));
        } else if (Files.getFileStore(parent).supportsFileAttributeView("acl")) {
            UserPrincipal user = path.getFileSystem().getUserPrincipalLookupService()
                    .lookupPrincipalByName(System.getProperty("user.name"));
            List<AclEntry> entries = List.of(AclEntry.newBuilder().setType(AclEntryType.ALLOW)
                    .setPrincipal(user).setPermissions(EnumSet.allOf(AclEntryPermission.class)).build());
            attribute = new FileAttribute<List<AclEntry>>() {
                public String name() { return "acl:acl"; }
                public List<AclEntry> value() { return entries; }
            };
        } else throw new IOException("Filesystem cannot create private credential files");
        return FileChannel.open(path, EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), attribute);
    }
    public static void write(FileChannel file, String text) throws IOException {
        ByteBuffer buffer = StandardCharsets.UTF_8.encode(text);
        while (buffer.hasRemaining()) file.write(buffer);
        file.force(true);
    }
    public static void writeNew(Path path, String text) throws IOException {
        try (var file = reserve(path)) { write(file, text); }
    }
    public static String read(Path path) throws IOException { return read(path, 16_384); }
    public static String read(Path path, int maxBytes) throws IOException {
        if (Files.isSymbolicLink(path)) throw new IOException("Credential file cannot be a symbolic link");
        if (Files.getFileStore(path).supportsFileAttributeView("posix")) {
            var permissions = Files.getPosixFilePermissions(path);
            if (permissions.stream().anyMatch(p -> p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_")))
                throw new IOException("Credential file must be private (chmod 600)");
        }
        try (var stream = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            byte[] bytes = stream.readNBytes(maxBytes + 1);
            if (bytes.length > maxBytes) throw new IOException("Credential file too large");
            return new String(bytes, StandardCharsets.UTF_8).strip();
        }
    }
}
