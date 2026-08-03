package org.francium.cybercoreMessageEncryption.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Conversions between raw 32-byte curve points and JCA key objects, plus HKDF.
 * <p>
 * The JCA exposes Ed25519/X25519 public keys as {@code EdECPoint}/{@code BigInteger}, which would
 * mean re-implementing little-endian point encoding by hand. The X.509
 * {@code SubjectPublicKeyInfo} form avoids that: for these two algorithms its header is a fixed
 * 12-byte prefix followed by the raw point, so encoding is dropping the prefix and decoding is
 * prepending it. The raw point is also the representation libsodium, age and SSH use.
 */
public final class CryptoKeys {
    /** SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING (33) } — Ed25519. */
    private static final byte[] ED25519_SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");
    /** SEQUENCE { SEQUENCE { OID 1.3.101.110 } BIT STRING (33) } — X25519. */
    private static final byte[] X25519_SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b656e032100");

    private static final int RAW_LEN = 32;

    public static final String ED25519 = "Ed25519";
    public static final String X25519 = "X25519";

    /** Extracts the raw 32-byte point from an Ed25519 or X25519 public key. */
    public static byte[] rawPublicKey(PublicKey key) {
        byte[] encoded = key.getEncoded();
        if (encoded == null || encoded.length != ED25519_SPKI_PREFIX.length + RAW_LEN) {
            throw new IllegalArgumentException("unexpected SubjectPublicKeyInfo for " + key.getAlgorithm());
        }
        byte[] raw = new byte[RAW_LEN];
        System.arraycopy(encoded, encoded.length - RAW_LEN, raw, 0, RAW_LEN);
        return raw;
    }

    public static PublicKey ed25519PublicKey(byte[] raw) throws GeneralSecurityException {
        return publicKey(ED25519, ED25519_SPKI_PREFIX, raw);
    }

    public static PublicKey x25519PublicKey(byte[] raw) throws GeneralSecurityException {
        return publicKey(X25519, X25519_SPKI_PREFIX, raw);
    }

    private static PublicKey publicKey(String algorithm, byte[] prefix, byte[] raw)
            throws GeneralSecurityException {
        if (raw.length != RAW_LEN) {
            throw new GeneralSecurityException(algorithm + " public key must be " + RAW_LEN + " bytes");
        }
        byte[] spki = new byte[prefix.length + RAW_LEN];
        System.arraycopy(prefix, 0, spki, 0, prefix.length);
        System.arraycopy(raw, 0, spki, prefix.length, RAW_LEN);
        return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(spki));
    }

    /** HKDF-SHA256 (RFC 5869). The JDK's own {@code KDF} API is too new to rely on here. */
    public static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int outputLength)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        int hashLen = mac.getMacLength();
        if (outputLength > 255 * hashLen) {
            throw new GeneralSecurityException("HKDF output length is too large");
        }

        mac.init(new SecretKeySpec(salt.length == 0 ? new byte[hashLen] : salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);

        byte[] output = new byte[outputLength];
        byte[] block = new byte[0];
        int written = 0;
        for (int counter = 1; written < outputLength; counter++) {
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(block);
            mac.update(info);
            mac.update((byte) counter);
            block = mac.doFinal();
            int take = Math.min(block.length, outputLength - written);
            System.arraycopy(block, 0, output, written, take);
            written += take;
        }
        return output;
    }

    /**
     * Short human-comparable form of an identity key, e.g. {@code 3F2A-91C7-04BE-D518}.
     * <p>
     * Players compare these out of band to detect a man-in-the-middle, so the grouping is part of
     * the contract and must stay stable across versions.
     */
    public static String fingerprint(byte[] rawIdentityKey) {
        byte[] digest;
        try {
            digest = java.security.MessageDigest.getInstance("SHA-256").digest(rawIdentityKey);
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

    private CryptoKeys() {
    }
}
