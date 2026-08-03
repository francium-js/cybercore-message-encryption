package org.francium.cybercoreMessageEncryption.protocol;

import java.io.ByteArrayOutputStream;
import java.util.UUID;

/**
 * Builds the exact byte strings that get Ed25519-signed.
 * <p>
 * Signer and verifier live in different code bases, so this file is duplicated verbatim in the
 * Folia plugin: if the two ever drift, every signature fails closed rather than silently
 * authenticating the wrong thing.
 */
public final class SignatureContext {

    /** Proves the client holds the private half of the keys it just announced, for this session. */
    public static byte[] handshake(byte[] serverNonce, UUID player, byte[] identityPublicKey, byte[] kexPublicKey) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(160);
        write(out, Protocol.HANDSHAKE_DOMAIN);
        write(out, serverNonce);
        writeUuid(out, player);
        write(out, identityPublicKey);
        write(out, kexPublicKey);
        return out.toByteArray();
    }

    /**
     * Ties an exchange key to the identity key that owns it, verifiable by anyone.
     * <p>
     * The relay publishes this alongside the exchange key, so a peer who has pinned the identity
     * key can tell that the exchange key it was handed really came from that player.
     */
    public static byte[] keyBinding(UUID owner, byte[] identityPublicKey, byte[] kexPublicKey) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(128);
        write(out, Protocol.KEY_BINDING_DOMAIN);
        writeUuid(out, owner);
        write(out, identityPublicKey);
        write(out, kexPublicKey);
        return out.toByteArray();
    }

    /**
     * Binds a ciphertext to its sender <em>and</em> its recipient, so the relay cannot re-address a
     * captured message to a third party and still have it verify.
     */
    public static byte[] message(UUID sender, UUID recipient, byte[] ephemeralPublicKey,
                                 byte[] nonce, byte[] ciphertext) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(ciphertext.length + 128);
        write(out, Protocol.MESSAGE_DOMAIN);
        writeUuid(out, sender);
        writeUuid(out, recipient);
        write(out, ephemeralPublicKey);
        write(out, nonce);
        write(out, ciphertext);
        return out.toByteArray();
    }

    /**
     * Additional authenticated data for the AEAD. Sharing the endpoint pair with the signature
     * means a ciphertext only decrypts for the conversation it was sealed for.
     */
    public static byte[] associatedData(UUID sender, UUID recipient) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(32);
        writeUuid(out, sender);
        writeUuid(out, recipient);
        return out.toByteArray();
    }

    /** Length-prefixed so no field boundary can be shifted without changing the signed bytes. */
    private static void write(ByteArrayOutputStream out, byte[] value) {
        out.write(value.length >>> 8);
        out.write(value.length & 0xFF);
        out.write(value, 0, value.length);
    }

    private static void writeUuid(ByteArrayOutputStream out, UUID value) {
        writeLong(out, value.getMostSignificantBits());
        writeLong(out, value.getLeastSignificantBits());
    }

    private static void writeLong(ByteArrayOutputStream out, long value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.write((int) (value >>> shift) & 0xFF);
        }
    }

    private SignatureContext() {
    }
}
