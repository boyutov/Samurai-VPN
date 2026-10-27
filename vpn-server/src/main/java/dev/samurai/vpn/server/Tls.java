package dev.samurai.vpn.server;

import javax.net.ssl.*;
import java.nio.file.*;
import java.security.KeyStore;
import java.util.Arrays;

public final class Tls {
    private Tls() {}
    public static SSLContext serverContext(Path file, char[] password) throws Exception {
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            try (var input = Files.newInputStream(file)) { store.load(input, password); }
            KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keys.init(store, password);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keys.getKeyManagers(), null, null);
            return context;
        } finally { Arrays.fill(password, '\0'); }
    }
}
