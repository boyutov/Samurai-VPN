package dev.samurai.vpn.core;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Base64;

/** Raw Curve25519 key representation expected by WireGuard, using the JDK X25519 provider. */
public final class WireGuardKeys {
    private WireGuardKeys() {}
    public record Identity(String privateKey, String publicKey) {
        @Override public String toString() { return "Identity[private key redacted]"; }
    }
    public static Identity generate() {
        byte[] scalar = new byte[32];
        new SecureRandom().nextBytes(scalar);
        scalar[0] &= (byte) 248;
        scalar[31] &= (byte) 127;
        scalar[31] |= (byte) 64;
        String privateKey = Base64.getEncoder().encodeToString(scalar);
        return new Identity(privateKey, publicFromPrivate(privateKey));
    }
    public static String publicFromPrivate(String privateKey) {
        try {
            KeyFactory factory = KeyFactory.getInstance("X25519");
            KeyAgreement agreement = KeyAgreement.getInstance("X25519");
            agreement.init(factory.generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, decode(privateKey))));
            agreement.doPhase(factory.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, BigInteger.valueOf(9))), true);
            return Base64.getEncoder().encodeToString(agreement.generateSecret());
        } catch (GeneralSecurityException e) { throw new IllegalArgumentException("Invalid X25519 key", e); }
    }
    public static String validatePublic(String key) {
        byte[] littleEndian = decode(key);
        byte[] bigEndian = littleEndian.clone();
        for (int i = 0; i < 32; i++) bigEndian[i] = littleEndian[31 - i];
        BigInteger u = new BigInteger(1, bigEndian);
        if (u.compareTo(BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))) >= 0)
            throw new IllegalArgumentException("Noncanonical public key");
        try {
            // The JDK rejects low-order points that produce an all-zero shared secret.
            KeyFactory factory = KeyFactory.getInstance("X25519");
            KeyAgreement agreement = KeyAgreement.getInstance("X25519");
            byte[] validationScalar = new byte[32];
            validationScalar[0] = 8;
            agreement.init(factory.generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, validationScalar)));
            agreement.doPhase(factory.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, u)), true);
            agreement.generateSecret();
            return key;
        } catch (GeneralSecurityException e) { throw new IllegalArgumentException("Invalid public key"); }
    }
    public static void validateIdentity(Identity identity) {
        if (identity == null || !publicFromPrivate(identity.privateKey()).equals(identity.publicKey()))
            throw new IllegalArgumentException("Private and public keys do not match");
    }
    private static byte[] decode(String key) {
        if (key == null || key.length() != 44) throw new IllegalArgumentException("Key must encode exactly 32 bytes");
        byte[] decoded = Base64.getDecoder().decode(key);
        if (decoded.length != 32 || !Base64.getEncoder().encodeToString(decoded).equals(key))
            throw new IllegalArgumentException("Invalid key encoding");
        return decoded;
    }
}
