package org.francium.cybercoreMessageEncryption.client;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import net.fabricmc.fabric.api.client.networking.v1.ClientPlayNetworking;
import net.minecraft.client.Minecraft;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.network.chat.Component;

import org.francium.cybercoreMessageEncryption.CybercoreMessageEncryption;
import org.francium.cybercoreMessageEncryption.crypto.ClientIdentity;
import org.francium.cybercoreMessageEncryption.crypto.CryptoKeys;
import org.francium.cybercoreMessageEncryption.crypto.SealedBox;
import org.francium.cybercoreMessageEncryption.protocol.EncryptoPayload;
import org.francium.cybercoreMessageEncryption.protocol.PacketReader;
import org.francium.cybercoreMessageEncryption.protocol.PacketWriter;
import org.francium.cybercoreMessageEncryption.protocol.Protocol;
import org.francium.cybercoreMessageEncryption.protocol.SignatureContext;

/**
 * Everything that happens between this client and one server: the handshake, the key directory
 * cache, and the encrypt/decrypt path for private messages.
 * <p>
 * All of it runs on the client thread — Fabric delivers payloads there and {@link #tick()} is
 * driven from the client tick — so nothing here needs synchronisation.
 */
public final class EncryptoSession {
    public enum State {
        /** Not in a world, or the connection just dropped. */
        DISCONNECTED,
        /** Joined; waiting for the server to open the handshake. */
        AWAITING_SERVER_HELLO,
        /** The challenge has been answered; waiting for the server to accept the announced keys. */
        AWAITING_RESULT,
        /** Encrypted messaging is available. */
        ESTABLISHED,
        /** No encryption on this server; {@code /msg} falls through to whatever the server does. */
        FAILED
    }

    private static final long HANDSHAKE_TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(8);
    private static final long KEY_REQUEST_TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(5);

    /**
     * A peer's public keys plus the trust verdict for them.
     * <p>
     * Kept only so {@code /encrypto} can show fingerprints and so a changed key can be warned
     * about. It is never used to seal, because peers rotate their exchange key on every join and a
     * cached one may already be stale.
     */
    public record Peer(UUID uuid, String name, byte[] identityPublicKey, byte[] kexPublicKey,
                       TrustStore.Verdict verdict) {
    }

    /** A message waiting for the recipient's keys to come back from the server. */
    private record Outgoing(String targetName, String text, long deadline) {
    }

    private final ClientIdentity identity;
    private final TrustStore trustStore;

    private State state = State.DISCONNECTED;
    private long deadline;
    private String serverKey = "";
    private UUID selfUuid;
    private Component failureReason = Component.empty();

    private final Map<String, Peer> peersByName = new HashMap<>();
    private final Map<Integer, List<Outgoing>> waitingForKeys = new HashMap<>();
    private final Map<String, Integer> requestIdsByName = new HashMap<>();
    private int nextRequestId = 1;

    private String lastPartnerName;

    public EncryptoSession(ClientIdentity identity, TrustStore trustStore) {
        this.identity = identity;
        this.trustStore = trustStore;
    }

    // -- lifecycle ------------------------------------------------------------

    public void onJoin() {
        reset();
        Minecraft client = Minecraft.getInstance();
        ServerData server = client.getCurrentServer();
        if (server == null || client.isLocalServer()) {
            // There is nothing to handshake with in single player, and a timeout toast on every
            // world load would be noise. /msg keeps its vanilla behaviour.
            return;
        }
        serverKey = server.ip.toLowerCase(Locale.ROOT);

        // A fresh exchange key per session, announced moments later in the handshake. The identity
        // key deliberately stays put: it is what peers pinned, and churning it would drown the
        // "key changed" warning in false alarms.
        try {
            identity.rotateExchangeKey();
        } catch (GeneralSecurityException e) {
            CybercoreMessageEncryption.LOGGER.error("Could not generate a session exchange key", e);
            fail(Component.translatable("cybercore.encrypto.toast.failed.local_key"));
            return;
        }

        state = State.AWAITING_SERVER_HELLO;
        deadline = System.nanoTime() + HANDSHAKE_TIMEOUT_NANOS;
    }

    public void onDisconnect() {
        reset();
    }

    private void reset() {
        state = State.DISCONNECTED;
        peersByName.clear();
        waitingForKeys.clear();
        requestIdsByName.clear();
        lastPartnerName = null;
        selfUuid = null;
        failureReason = Component.empty();
    }

    public void tick() {
        long now = System.nanoTime();

        if ((state == State.AWAITING_SERVER_HELLO || state == State.AWAITING_RESULT) && now - deadline >= 0) {
            fail(state == State.AWAITING_SERVER_HELLO
                    ? Component.translatable("cybercore.encrypto.toast.failed.no_server")
                    : Component.translatable("cybercore.encrypto.toast.failed.no_result"));
        }

        Iterator<Map.Entry<Integer, List<Outgoing>>> iterator = waitingForKeys.entrySet().iterator();
        while (iterator.hasNext()) {
            List<Outgoing> queued = iterator.next().getValue();
            if (!queued.isEmpty() && now - queued.getFirst().deadline() >= 0) {
                String target = queued.getFirst().targetName();
                requestIdsByName.remove(target.toLowerCase(Locale.ROOT));
                iterator.remove();
                EncryptoChat.error(Component.translatable("cybercore.encrypto.error.key_timeout", target));
            }
        }
    }

    public State state() {
        return state;
    }

    public boolean isEstablished() {
        return state == State.ESTABLISHED;
    }

    /**
     * Whether to keep warning that private messages on this server are unprotected.
     * <p>
     * True only once the handshake has actually failed: single player never starts one, and
     * warning while it is still in flight would flash red for a few seconds and then vanish.
     */
    public boolean isKnownUnencrypted() {
        return state == State.FAILED;
    }

    public Component failureReason() {
        return failureReason;
    }

    public String serverKey() {
        return serverKey;
    }

    public ClientIdentity identity() {
        return identity;
    }

    public TrustStore trustStore() {
        return trustStore;
    }

    public Optional<Peer> cachedPeer(String name) {
        return Optional.ofNullable(peersByName.get(name.toLowerCase(Locale.ROOT)));
    }

    // -- outbound -------------------------------------------------------------

    /**
     * @return {@code false} when this client cannot encrypt for the server, which is the caller's
     *         signal to let the raw command reach the server instead of swallowing it
     */
    public boolean sendPrivateMessage(String targetName, String text) {
        if (!isEstablished()) {
            return false;
        }
        if (text.isEmpty()) {
            EncryptoChat.error(Component.translatable("cybercore.encrypto.error.empty_message"));
            return true;
        }
        if (text.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > Protocol.MAX_PLAINTEXT_BYTES) {
            EncryptoChat.error(Component.translatable("cybercore.encrypto.error.too_long",
                    Protocol.MAX_PLAINTEXT_BYTES));
            return true;
        }

        requestKeysThenSend(targetName, text);
        return true;
    }

    public boolean reply(String text) {
        if (!isEstablished()) {
            return false;
        }
        if (lastPartnerName == null) {
            EncryptoChat.error(Component.translatable("cybercore.encrypto.error.no_reply_target"));
            return true;
        }
        return sendPrivateMessage(lastPartnerName, text);
    }

    private void requestKeysThenSend(String targetName, String text) {
        String key = targetName.toLowerCase(Locale.ROOT);
        peersByName.remove(key);

        Outgoing pending = new Outgoing(targetName, text, System.nanoTime() + KEY_REQUEST_TIMEOUT_NANOS);
        Integer inFlight = requestIdsByName.get(key);
        List<Outgoing> queued = inFlight == null ? null : waitingForKeys.get(inFlight);
        if (queued != null) {
            // Messages sent to the same player in quick succession share one lookup.
            queued.add(pending);
            return;
        }

        int requestId = nextRequestId++;
        requestIdsByName.put(key, requestId);
        waitingForKeys.put(requestId, new ArrayList<>(List.of(pending)));

        send(new PacketWriter(Protocol.C2S_KEY_REQUEST)
                .varInt(requestId)
                .string(targetName)
                .toByteArray());
    }

    private void deliver(Peer peer, String text) {
        if (peer.verdict() == TrustStore.Verdict.CHANGED) {
            EncryptoChat.error(Component.translatable("cybercore.encrypto.error.key_changed", peer.name()));
            EncryptoChat.error(Component.translatable("cybercore.encrypto.error.key_changed_hint", peer.name()));
            return;
        }
        try {
            byte[] plaintext = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] associatedData = SignatureContext.associatedData(selfUuid, peer.uuid());
            SealedBox.Sealed sealed = SealedBox.seal(peer.kexPublicKey(), plaintext, associatedData);
            byte[] signature = identity.sign(SignatureContext.message(
                    selfUuid, peer.uuid(), sealed.ephemeralPublicKey(), sealed.nonce(), sealed.ciphertext()));

            send(new PacketWriter(Protocol.C2S_MESSAGE)
                    .uuid(peer.uuid())
                    .bytes(peer.kexPublicKey())
                    .bytes(sealed.ephemeralPublicKey())
                    .bytes(sealed.nonce())
                    .bytes(sealed.ciphertext())
                    .bytes(signature)
                    .toByteArray());

            lastPartnerName = peer.name();
            EncryptoChat.outgoing(peer.name(), text);
        } catch (GeneralSecurityException e) {
            CybercoreMessageEncryption.LOGGER.error("Could not encrypt a message for {}", peer.name(), e);
            EncryptoChat.error(Component.translatable("cybercore.encrypto.error.encrypt_failed"));
        }
    }

    private void send(byte[] frame) {
        if (Minecraft.getInstance().getConnection() == null) {
            return;
        }
        ClientPlayNetworking.send(new EncryptoPayload(frame));
    }

    // -- inbound --------------------------------------------------------------

    public void onPayload(byte[] frame) {
        try {
            PacketReader reader = new PacketReader(frame);
            switch (reader.opcode()) {
                case Protocol.S2C_SERVER_HELLO -> onServerHello(reader);
                case Protocol.S2C_HANDSHAKE_RESULT -> onHandshakeResult(reader);
                case Protocol.S2C_KEY_RESPONSE -> onKeyResponse(reader);
                case Protocol.S2C_MESSAGE -> onMessage(reader);
                case Protocol.S2C_MESSAGE_STATUS -> onMessageStatus(reader);
                default -> CybercoreMessageEncryption.LOGGER.debug(
                        "Ignoring unknown opcode 0x{}", Integer.toHexString(reader.opcode() & 0xFF));
            }
        } catch (PacketReader.MalformedFrameException e) {
            CybercoreMessageEncryption.LOGGER.warn("Discarding a malformed frame from the server", e);
        }
    }

    private void onServerHello(PacketReader reader) {
        int version = reader.varInt();
        byte[] nonce = reader.fixedBytes(Protocol.HANDSHAKE_NONCE_LEN);
        reader.string(256); // server display name, unused for now

        // Answered from any state, not just while waiting. A server that reloads the plugin opens
        // a fresh session and greets everyone again; ignoring that would leave the client
        // believing it is encrypted against a server that has forgotten its keys.
        if (state == State.DISCONNECTED) {
            return;
        }
        if (version != Protocol.VERSION) {
            fail(Component.translatable("cybercore.encrypto.toast.failed.version", version, Protocol.VERSION));
            return;
        }
        Minecraft client = Minecraft.getInstance();
        if (client.player == null) {
            fail(Component.translatable("cybercore.encrypto.toast.failed.no_result"));
            return;
        }
        selfUuid = client.player.getUUID();

        try {
            byte[] signature = identity.sign(SignatureContext.handshake(
                    nonce, selfUuid, identity.identityPublicKey(), identity.exchangePublicKey()));
            byte[] binding = identity.sign(SignatureContext.keyBinding(
                    selfUuid, identity.identityPublicKey(), identity.exchangePublicKey()));
            send(new PacketWriter(Protocol.C2S_CLIENT_HELLO)
                    .varInt(Protocol.VERSION)
                    .bytes(identity.identityPublicKey())
                    .bytes(identity.exchangePublicKey())
                    .bytes(signature)
                    .bytes(binding)
                    .toByteArray());
        } catch (GeneralSecurityException e) {
            CybercoreMessageEncryption.LOGGER.error("Could not sign the handshake", e);
            fail(Component.translatable("cybercore.encrypto.toast.failed.local_key"));
            return;
        }

        // An already-working session is left alone until the server actually answers, so a stray
        // greeting cannot tear down encryption that is currently in effect.
        if (state != State.ESTABLISHED) {
            state = State.AWAITING_RESULT;
            deadline = System.nanoTime() + HANDSHAKE_TIMEOUT_NANOS;
        }
    }

    private void onHandshakeResult(PacketReader reader) {
        boolean accepted = reader.bool();
        String detail = reader.string(512);

        if (!accepted) {
            // Also downgrades an established session: the server decides whether it will relay,
            // and believing otherwise would swallow /msg instead of passing it through.
            if (state == State.AWAITING_RESULT || state == State.ESTABLISHED) {
                fail(detail.isEmpty()
                        ? Component.translatable("cybercore.encrypto.toast.failed.rejected")
                        : Component.literal(detail));
            }
            return;
        }
        // FAILED is accepted as well as AWAITING_RESULT. The two sides run independent timeouts,
        // so a slow round trip can have the client give up while the server still accepts the
        // keys; a late acceptance supersedes the failure toast already shown.
        if (state != State.AWAITING_RESULT && state != State.FAILED) {
            return;
        }
        if (selfUuid == null) {
            return; // never sent a hello on this connection; not ours to accept
        }
        state = State.ESTABLISHED;
        failureReason = Component.empty();
        EncryptoToasts.handshakeSucceeded(Component.translatable("cybercore.encrypto.toast.ok.body"));
    }

    private void onKeyResponse(PacketReader reader) {
        int requestId = reader.varInt();
        byte status = reader.byteValue();
        String name = reader.string(64);

        List<Outgoing> queued = waitingForKeys.remove(requestId);
        requestIdsByName.remove(name.toLowerCase(Locale.ROOT));

        if (status != Protocol.KEY_OK) {
            // The server has already explained the failure to the player, in the wording its
            // config specifies. Only the messages waiting on this lookup need dropping here.
            return;
        }

        UUID uuid = reader.uuid();
        byte[] identityKey = reader.fixedBytes(Protocol.ED25519_PUBLIC_LEN);
        byte[] kexKey = reader.fixedBytes(Protocol.X25519_PUBLIC_LEN);
        byte[] binding = reader.fixedBytes(Protocol.ED25519_SIGNATURE_LEN);

        // Without this check the relay could hand out an exchange key of its own and read
        // everything sealed to it. The binding proves the key came from the pinned identity.
        if (!verify(identityKey, SignatureContext.keyBinding(uuid, identityKey, kexKey), binding)) {
            CybercoreMessageEncryption.LOGGER.warn(
                    "Rejected an unsigned exchange key for {} from the server", name);
            EncryptoChat.error(Component.translatable("cybercore.encrypto.error.unsigned_key", name));
            return;
        }

        Peer peer = rememberPeer(uuid, name, identityKey, kexKey);
        if (peer.verdict() == TrustStore.Verdict.CHANGED) {
            warnAboutChangedKey(peer);
        }
        if (queued != null) {
            queued.forEach(outgoing -> deliver(peer, outgoing.text()));
        }
    }

    private void onMessage(PacketReader reader) {
        UUID senderUuid = reader.uuid();
        String senderName = reader.string(64);
        byte[] senderIdentityKey = reader.fixedBytes(Protocol.ED25519_PUBLIC_LEN);
        byte[] ephemeralKey = reader.fixedBytes(Protocol.X25519_PUBLIC_LEN);
        byte[] nonce = reader.fixedBytes(Protocol.GCM_NONCE_LEN);
        byte[] ciphertext = reader.bytes(Protocol.MAX_CIPHERTEXT_BYTES);
        byte[] signature = reader.fixedBytes(Protocol.ED25519_SIGNATURE_LEN);

        if (!isEstablished() || selfUuid == null) {
            return;
        }

        // The relay verifies this too, but the relay is itself part of the threat model.
        if (!verify(senderIdentityKey,
                SignatureContext.message(senderUuid, selfUuid, ephemeralKey, nonce, ciphertext), signature)) {
            EncryptoChat.error(Component.translatable("cybercore.encrypto.error.bad_signature", senderName));
            return;
        }

        String text;
        try {
            byte[] plaintext = SealedBox.open(
                    identity.exchangePrivateKey(), identity.exchangePublicKey(),
                    new SealedBox.Sealed(ephemeralKey, nonce, ciphertext),
                    SignatureContext.associatedData(senderUuid, selfUuid));
            if (plaintext.length > Protocol.MAX_PLAINTEXT_BYTES) {
                return;
            }
            text = new String(plaintext, java.nio.charset.StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            EncryptoChat.error(Component.translatable("cybercore.encrypto.error.decrypt_failed", senderName));
            return;
        }

        Peer peer = rememberPeer(senderUuid, senderName, senderIdentityKey, null);
        if (peer.verdict() == TrustStore.Verdict.CHANGED) {
            warnAboutChangedKey(peer);
        }
        lastPartnerName = senderName;
        EncryptoChat.incoming(senderName, text);
    }

    /**
     * Delivery outcome for a relayed message. The server words every one of these itself, so this
     * only logs. The frame is still the client's one signal that a send has finished.
     */
    private void onMessageStatus(PacketReader reader) {
        byte status = reader.byteValue();
        String detail = reader.string(128);
        if (status != Protocol.SEND_OK) {
            CybercoreMessageEncryption.LOGGER.debug("Relay refused a message (status {}, detail '{}')",
                    status, detail);
        }
    }

    // -- helpers --------------------------------------------------------------

    /**
     * Caches a peer and runs it past the trust store. {@code kexPublicKey} is null for peers known
     * only from an incoming message; that is harmless, because sending always fetches a fresh key
     * rather than reading one back out of this cache.
     */
    private Peer rememberPeer(UUID uuid, String name, byte[] identityKey, byte[] kexPublicKey) {
        TrustStore.Verdict verdict = trustStore.check(serverKey, uuid, identityKey);
        Peer peer = new Peer(uuid, name, identityKey, kexPublicKey, verdict);
        peersByName.put(name.toLowerCase(Locale.ROOT), peer);
        return peer;
    }

    private void warnAboutChangedKey(Peer peer) {
        EncryptoChat.error(Component.translatable("cybercore.encrypto.error.key_changed", peer.name()));
        EncryptoChat.error(Component.translatable("cybercore.encrypto.error.key_changed_detail",
                trustStore.pinnedFingerprint(serverKey, peer.uuid()),
                CryptoKeys.fingerprint(peer.identityPublicKey())));
    }

    private static boolean verify(byte[] rawPublicKey, byte[] message, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance(CryptoKeys.ED25519);
            verifier.initVerify(CryptoKeys.ed25519PublicKey(rawPublicKey));
            verifier.update(message);
            return verifier.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private void fail(Component reason) {
        state = State.FAILED;
        failureReason = reason;
        EncryptoToasts.handshakeFailed(reason);
    }
}
