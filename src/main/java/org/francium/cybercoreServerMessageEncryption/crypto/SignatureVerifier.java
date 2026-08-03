package org.francium.cybercoreServerMessageEncryption.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;

/**
 * Ed25519 signature verification, the only cryptography the server performs.
 * <p>
 * There is no decryption path here and no private key anywhere in this plugin. Verification
 * establishes only that a relayed frame came from the account it claims to, which prevents one
 * player forging messages from another. Message bodies stay opaque to the server.
 */
public final class SignatureVerifier {
    /** SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING (33) } — Ed25519. */
    private static final byte[] ED25519_SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");
    private static final int RAW_LEN = 32;

    public static boolean verify(byte[] rawPublicKey, byte[] message, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKey(rawPublicKey));
            verifier.update(message);
            return verifier.verify(signature);
        } catch (GeneralSecurityException | RuntimeException e) {
            // Malformed keys and signatures arrive straight off the network, so they count as a
            // failed verification rather than an error to propagate.
            return false;
        }
    }

    /**
     * Rebuilds a JCA key from the raw 32-byte point by prepending the fixed X.509
     * {@code SubjectPublicKeyInfo} header for Ed25519.
     */
    private static PublicKey publicKey(byte[] raw) throws GeneralSecurityException {
        if (raw.length != RAW_LEN) {
            throw new GeneralSecurityException("Ed25519 public key must be " + RAW_LEN + " bytes");
        }
        byte[] spki = new byte[ED25519_SPKI_PREFIX.length + RAW_LEN];
        System.arraycopy(ED25519_SPKI_PREFIX, 0, spki, 0, ED25519_SPKI_PREFIX.length);
        System.arraycopy(raw, 0, spki, ED25519_SPKI_PREFIX.length, RAW_LEN);
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
    }

    /** Short human-comparable form of an identity key; identical to the form the mod displays. */
    public static String fingerprint(byte[] rawIdentityKey) {
        byte[] digest;
        try {
            digest = MessageDigest.getInstance("SHA-256").digest(rawIdentityKey);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
        HexFormat hex = HexFormat.of().withUpperCase();
        StringBuilder out = new StringBuilder(19);
        for (int i = 0; i < 8; i++) {
            if (i > 0 && i % 2 == 0) {
                out.append('-');
            }
            out.append(hex.toHexDigits(digest[i]));
        }
        return out.toString();
    }

    private SignatureVerifier() {
    }
}
