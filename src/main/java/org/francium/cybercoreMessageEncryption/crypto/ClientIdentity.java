package org.francium.cybercoreMessageEncryption.crypto;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Set;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.francium.cybercoreMessageEncryption.CybercoreMessageEncryption;

/**
 * The player's keys, which have deliberately different lifetimes.
 * <p>
 * The <b>identity</b> pair (Ed25519) is long-term and persisted. It signs messages and is what
 * peers pin, so rotating it is not a security upgrade but a change of identity. Rotating it every
 * session would show every peer a "key changed" warning every session, training them to dismiss
 * the one warning that catches a malicious relay.
 * <p>
 * The <b>exchange</b> pair (X25519) is regenerated for every server session and never written to
 * disk. Peers seal to it, and the server publishes it fresh on each join, so nothing has to be
 * invalidated when it changes. Together with the per-message ephemeral key in {@link SealedBox},
 * this leaves no long-lived secret on disk that could open captured traffic.
 * <p>
 * Private keys never leave the local machine; the server only ever learns public halves.
 */
public final class ClientIdentity {
    private static final int FORMAT_VERSION = 2;

    /** Held as a single object so a rotation can never be observed half-applied. */
    private record Exchange(KeyPair pair, byte[] publicKey) {
        static Exchange generate() throws GeneralSecurityException {
            KeyPair pair = KeyPairGenerator.getInstance(CryptoKeys.X25519).generateKeyPair();
            return new Exchange(pair, CryptoKeys.rawPublicKey(pair.getPublic()));
        }
    }

    private final KeyPair identity;
    private final byte[] rawIdentityPublicKey;
    private volatile Exchange exchange;

    private ClientIdentity(KeyPair identity, Exchange exchange) {
        this.identity = identity;
        this.rawIdentityPublicKey = CryptoKeys.rawPublicKey(identity.getPublic());
        this.exchange = exchange;
    }

    /**
     * Loads the identity from {@code file}, generating and persisting a fresh one if the file is
     * missing. A file that exists but cannot be parsed is moved aside and replaced, because a
     * corrupt key must not lock the player out of chat.
     */
    public static ClientIdentity loadOrCreate(Path file) throws IOException, GeneralSecurityException {
        if (Files.isRegularFile(file)) {
            try {
                return read(file);
            } catch (RuntimeException | GeneralSecurityException e) {
                Path backup = file.resolveSibling(file.getFileName() + ".broken");
                CybercoreMessageEncryption.LOGGER.warn(
                        "Identity file {} was unreadable; moving it to {} and generating a new key. "
                                + "Peers will see your fingerprint change.", file, backup, e);
                Files.move(file, backup, StandardCopyOption.REPLACE_EXISTING);
                ClientIdentity replacement = generate();
                replacement.write(file);
                return replacement;
            }
        }
        ClientIdentity created = generate();
        created.write(file);
        return created;
    }

    public static ClientIdentity generate() throws GeneralSecurityException {
        return new ClientIdentity(
                KeyPairGenerator.getInstance(CryptoKeys.ED25519).generateKeyPair(),
                Exchange.generate());
    }

    /**
     * Starts a new exchange key for a new server session. This must happen before the handshake
     * announces the public half, since that is the only moment the server learns it.
     */
    public void rotateExchangeKey() throws GeneralSecurityException {
        this.exchange = Exchange.generate();
    }

    private static ClientIdentity read(Path file) throws IOException, GeneralSecurityException {
        JsonObject json = JsonParser.parseString(Files.readString(file, StandardCharsets.UTF_8)).getAsJsonObject();
        int version = json.get("version").getAsInt();
        // v1 also stored a long-term exchange pair. It is ignored: only the identity half needs
        // continuity, and rewriting the file drops the stale key.
        if (version != 1 && version != FORMAT_VERSION) {
            throw new GeneralSecurityException("unsupported identity format version " + version);
        }
        ClientIdentity loaded = new ClientIdentity(readIdentityPair(json), Exchange.generate());
        if (version != FORMAT_VERSION) {
            // Rewrite once, which drops the long-term exchange key a v1 file still holds.
            loaded.write(file);
        }
        return loaded;
    }

    private static KeyPair readIdentityPair(JsonObject json) throws GeneralSecurityException {
        Base64.Decoder decoder = Base64.getDecoder();
        KeyFactory factory = KeyFactory.getInstance(CryptoKeys.ED25519);
        PrivateKey privateKey = factory.generatePrivate(
                new PKCS8EncodedKeySpec(decoder.decode(json.get("identity_private").getAsString())));
        PublicKey publicKey = factory.generatePublic(
                new X509EncodedKeySpec(decoder.decode(json.get("identity_public").getAsString())));
        return new KeyPair(publicKey, privateKey);
    }

    public void write(Path file) throws IOException {
        Base64.Encoder encoder = Base64.getEncoder();
        JsonObject json = new JsonObject();
        json.addProperty("version", FORMAT_VERSION);
        json.addProperty("identity_private", encoder.encodeToString(identity.getPrivate().getEncoded()));
        json.addProperty("identity_public", encoder.encodeToString(identity.getPublic().getEncoded()));
        json.addProperty("fingerprint", fingerprint());

        Files.createDirectories(file.getParent());
        Path temporary = file.resolveSibling(file.getFileName() + ".tmp");
        Files.writeString(temporary, json.toString(), StandardCharsets.UTF_8);
        restrictPermissions(temporary);
        Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING);
    }

    private static void restrictPermissions(Path file) {
        try {
            Set<PosixFilePermission> ownerOnly = EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(file, ownerOnly);
        } catch (IOException | UnsupportedOperationException ignored) {
            // Windows and some filesystems have no POSIX bits. The key is then protected no worse
            // than anything else in the config directory.
        }
    }

    public byte[] identityPublicKey() {
        return rawIdentityPublicKey.clone();
    }

    public byte[] exchangePublicKey() {
        return exchange.publicKey().clone();
    }

    public PrivateKey exchangePrivateKey() {
        return exchange.pair().getPrivate();
    }

    public String fingerprint() {
        return CryptoKeys.fingerprint(rawIdentityPublicKey);
    }

    public byte[] sign(byte[] message) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(CryptoKeys.ED25519);
        signature.initSign(identity.getPrivate());
        signature.update(message);
        return signature.sign();
    }
}
