package org.francium.cybercoreMessageEncryption.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.francium.cybercoreMessageEncryption.protocol.Protocol;

/**
 * Anonymous sealed-box encryption: X25519 with a per-message ephemeral sender key, HKDF-SHA256,
 * then AES-256-GCM.
 * <p>
 * Only the recipient's long-term X25519 key is needed to encrypt, and a fresh ephemeral key per
 * message means a later compromise of the sender's identity key does not retroactively decrypt
 * traffic. Sender authenticity is <em>not</em> provided here — it comes from the Ed25519 signature
 * the sender puts over the ciphertext, which both the relay and the recipient verify.
 */
public final class SealedBox {
    private static final int AES_KEY_BITS = 256;
    private static final int GCM_TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** A message that has been sealed for exactly one recipient. */
    public record Sealed(byte[] ephemeralPublicKey, byte[] nonce, byte[] ciphertext) {
    }

    public static Sealed seal(byte[] recipientKexPublicKey, byte[] plaintext, byte[] associatedData)
            throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(CryptoKeys.X25519);
        KeyPair ephemeral = generator.generateKeyPair();
        byte[] ephemeralPublic = CryptoKeys.rawPublicKey(ephemeral.getPublic());

        byte[] shared = agree(ephemeral.getPrivate(), recipientKexPublicKey);
        byte[] key = deriveKey(shared, ephemeralPublic, recipientKexPublicKey);

        byte[] nonce = new byte[Protocol.GCM_NONCE_LEN];
        RANDOM.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
        cipher.updateAAD(associatedData);
        byte[] ciphertext = cipher.doFinal(plaintext);

        return new Sealed(ephemeralPublic, nonce, ciphertext);
    }

    public static byte[] open(PrivateKey recipientKexPrivateKey,
                              byte[] recipientKexPublicKey,
                              Sealed sealed,
                              byte[] associatedData) throws GeneralSecurityException {
        byte[] shared = agree(recipientKexPrivateKey, sealed.ephemeralPublicKey());
        byte[] key = deriveKey(shared, sealed.ephemeralPublicKey(), recipientKexPublicKey);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, sealed.nonce()));
        cipher.updateAAD(associatedData);
        return cipher.doFinal(sealed.ciphertext());
    }

    private static byte[] agree(PrivateKey privateKey, byte[] rawPeerPublicKey) throws GeneralSecurityException {
        KeyAgreement agreement = KeyAgreement.getInstance(CryptoKeys.X25519);
        agreement.init(privateKey);
        agreement.doPhase(CryptoKeys.x25519PublicKey(rawPeerPublicKey), true);
        return agreement.generateSecret();
    }

    /**
     * Binds the derived key to both public keys, so a shared secret can never be reused under a
     * different pair of endpoints.
     */
    private static byte[] deriveKey(byte[] sharedSecret, byte[] ephemeralPublic, byte[] recipientPublic)
            throws GeneralSecurityException {
        byte[] salt = new byte[ephemeralPublic.length + recipientPublic.length];
        System.arraycopy(ephemeralPublic, 0, salt, 0, ephemeralPublic.length);
        System.arraycopy(recipientPublic, 0, salt, ephemeralPublic.length, recipientPublic.length);
        return CryptoKeys.hkdfSha256(sharedSecret, salt, Protocol.MESSAGE_KEY_INFO, AES_KEY_BITS / 8);
    }

    private SealedBox() {
    }
}
