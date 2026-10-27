package dev.samurai.vpn.client;

import dev.samurai.vpn.core.*;
import dev.samurai.vpn.server.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.security.KeyStore;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

class TlsIntegrationTest {
    @TempDir Path temp;
    @Test void acceptsTrustedCertificateAndRejectsWrongHostAndUntrustedCertificate() throws Exception {
        Path keystore = temp.resolve("server.p12");
        String password = "test-certificate-only";
        boolean windows = System.getProperty("os.name").toLowerCase().contains("win");
        Path keytool = Path.of(System.getProperty("java.home"), "bin", windows ? "keytool.exe" : "keytool");
        var process = new ProcessBuilder(keytool.toString(), "-genkeypair", "-alias", "server", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "2", "-dname", "CN=localhost", "-ext", "SAN=dns:localhost", "-storetype", "PKCS12",
                "-keystore", keystore.toString(), "-storepass", password, "-noprompt")
                .redirectErrorStream(true).redirectOutput(temp.resolve("keytool.log").toFile()).start();
        if (!process.waitFor(30, TimeUnit.SECONDS)) { process.destroyForcibly(); fail("keytool timed out"); }
        assertEquals(0, process.exitValue(), Files.readString(temp.resolve("keytool.log")));
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(keystore)) { keys.load(input, password.toCharArray()); }
        KeyStore trust = KeyStore.getInstance("PKCS12"); trust.load(null, null);
        trust.setCertificateEntry("server", keys.getCertificate("server"));
        var managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); managers.init(trust);
        SSLContext trusted = SSLContext.getInstance("TLS"); trusted.init(null, managers.getTrustManagers(), null);
        String admin = Tokens.generate();
        try (var server = new ControlServer(new InetSocketAddress("127.0.0.1", 0), new NetworkRegistry(admin),
                Tls.serverContext(keystore, password.toCharArray()), false)) {
            server.start(); String origin = "https://localhost:" + server.port();
            try (var client = new ApiClient(origin, false, trusted)) {
                var network = client.request("POST", "/v1/networks", admin, new Api.CreateNetwork("TLS network"), Api.NetworkCreated.class);
                assertEquals("TLS network", network.name());
            }
            try (var client = new ApiClient(origin, false)) {
                assertThrows(IOException.class, () -> client.request("POST", "/v1/networks", admin, new Api.CreateNetwork("untrusted"), Api.NetworkCreated.class));
            }
            try (var client = new ApiClient("https://127.0.0.1:" + server.port(), false, trusted)) {
                assertThrows(IOException.class, () -> client.request("POST", "/v1/networks", admin, new Api.CreateNetwork("wrong-host"), Api.NetworkCreated.class));
            }
        }
    }
}
