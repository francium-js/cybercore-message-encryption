package org.francium.cybercoreMessageEncryption.protocol;

/**
 * Wire contract shared with the {@code cybercore-server-message-encryption} Folia plugin.
 * <p>
 * Everything travels over a single plugin channel; the first byte of every frame is the opcode.
 * The frame body is encoded with {@link PacketWriter} / {@link PacketReader} rather than
 * {@code FriendlyByteBuf} so that the Bukkit side — which only ever sees a raw {@code byte[]} —
 * can decode it with the exact same primitives.
 * <p>
 * Any change to the opcodes or field order has to be mirrored in the plugin's copy of this file
 * and must bump {@link #VERSION}.
 */
public final class Protocol {
    public static final String NAMESPACE = "cybercore";
    public static final String PATH = "encrypto";
    /** Channel name as Bukkit spells it. */
    public static final String CHANNEL = NAMESPACE + ":" + PATH;

    public static final int VERSION = 3;

    // --- serverbound ---------------------------------------------------------
    public static final byte C2S_CLIENT_HELLO = 0x01;
    public static final byte C2S_KEY_REQUEST = 0x02;
    public static final byte C2S_MESSAGE = 0x03;

    // --- clientbound ---------------------------------------------------------
    public static final byte S2C_SERVER_HELLO = (byte) 0x81;
    public static final byte S2C_HANDSHAKE_RESULT = (byte) 0x82;
    public static final byte S2C_KEY_RESPONSE = (byte) 0x83;
    public static final byte S2C_MESSAGE = (byte) 0x84;
    public static final byte S2C_MESSAGE_STATUS = (byte) 0x85;

    // --- key lookup outcomes -------------------------------------------------
    public static final byte KEY_OK = 0;
    public static final byte KEY_UNKNOWN_PLAYER = 1;
    /** Player is online but has no encrypted session (vanilla client, or handshake failed). */
    public static final byte KEY_NOT_ENCRYPTED = 2;
    public static final byte KEY_SELF = 3;

    // --- delivery outcomes ---------------------------------------------------
    public static final byte SEND_OK = 0;
    public static final byte SEND_TARGET_OFFLINE = 1;
    public static final byte SEND_TARGET_NOT_ENCRYPTED = 2;
    public static final byte SEND_NOT_HANDSHAKEN = 3;
    public static final byte SEND_BAD_SIGNATURE = 4;
    public static final byte SEND_RATE_LIMITED = 5;
    /** The sender sealed to an exchange key the recipient has since rotated away from. */
    public static final byte SEND_STALE_KEY = 6;

    // --- sizes ---------------------------------------------------------------
    public static final int ED25519_PUBLIC_LEN = 32;
    public static final int X25519_PUBLIC_LEN = 32;
    public static final int ED25519_SIGNATURE_LEN = 64;
    public static final int HANDSHAKE_NONCE_LEN = 32;
    public static final int GCM_NONCE_LEN = 12;
    /** Upper bound on a decrypted private message, in UTF-8 bytes. */
    public static final int MAX_PLAINTEXT_BYTES = 1024;
    /**
     * Largest ciphertext anyone may present: the plaintext cap plus the 16-byte GCM tag.
     * <p>
     * Enforced on both sides so an oversized body is rejected at the relay rather than being
     * forwarded into a frame the recipient can no longer decode.
     */
    public static final int MAX_CIPHERTEXT_BYTES = MAX_PLAINTEXT_BYTES + 16;
    /** Upper bound on a whole frame, well under the 32 KiB custom-payload limit. */
    public static final int MAX_FRAME_BYTES = 8192;

    // --- signature domains ---------------------------------------------------
    /** Signed by the client over: domain || serverNonce || playerUuid || identityPub || kexPub. */
    public static final byte[] HANDSHAKE_DOMAIN = ascii("cybercore:encrypto:handshake:v1");
    /** Signed by the sender over: domain || senderUuid || recipientUuid || ephPub || nonce || ciphertext. */
    public static final byte[] MESSAGE_DOMAIN = ascii("cybercore:encrypto:message:v1");
    /**
     * Signed by a player over: domain || ownerUuid || identityPub || kexPub.
     * <p>
     * Unlike {@link #HANDSHAKE_DOMAIN} this carries no server nonce, so any peer can check it. It
     * ties an exchange key to the identity key peers have pinned, which is what prevents the relay
     * from handing out an exchange key of its own choosing.
     */
    public static final byte[] KEY_BINDING_DOMAIN = ascii("cybercore:encrypto:key-binding:v1");
    /** HKDF info string for the per-message AES key. */
    public static final byte[] MESSAGE_KEY_INFO = ascii("cybercore:encrypto:message-key:v1");

    private static byte[] ascii(String s) {
        return s.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }

    private Protocol() {
    }
}
