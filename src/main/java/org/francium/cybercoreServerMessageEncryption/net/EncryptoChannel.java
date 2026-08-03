package org.francium.cybercoreServerMessageEncryption.net;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import net.kyori.adventure.text.minimessage.tag.resolver.TagResolver;

import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.messaging.PluginMessageListener;
import org.francium.cybercoreServerMessageEncryption.EncryptoConfig;
import org.francium.cybercoreServerMessageEncryption.crypto.SignatureVerifier;
import org.francium.cybercoreServerMessageEncryption.protocol.PacketReader;
import org.francium.cybercoreServerMessageEncryption.protocol.PacketWriter;
import org.francium.cybercoreServerMessageEncryption.protocol.Protocol;
import org.francium.cybercoreServerMessageEncryption.protocol.SignatureContext;
import org.francium.cybercoreServerMessageEncryption.session.PlayerSession;
import org.francium.cybercoreServerMessageEncryption.session.SessionRegistry;
import org.jetbrains.annotations.NotNull;

/**
 * The relay: runs the handshake, hands out public keys, and forwards ciphertext between players.
 * <p>
 * Nothing here can read a message body — the plugin holds no private key and never derives one.
 * It does verify the sender's signature, so a message cannot be relayed under another player's
 * name.
 * <p>
 * Player-facing wording for every outcome decided here comes from {@code config.yml}; the client
 * receives only a status code. The mod writes text of its own solely for what the server cannot
 * know about, such as a local decryption failure.
 */
public final class EncryptoChannel implements PluginMessageListener {
    private static final long RATE_WINDOW_NANOS = TimeUnit.MINUTES.toNanos(1);

    private final Plugin plugin;
    private final SessionRegistry sessions;
    private final EncryptoConfig config;
    private final String serverLabel;

    public EncryptoChannel(Plugin plugin, SessionRegistry sessions, EncryptoConfig config, String serverLabel) {
        this.plugin = plugin;
        this.sessions = sessions;
        this.config = config;
        this.serverLabel = serverLabel;
    }

    /** Opens the handshake. The nonce is what makes a replayed {@code CLIENT_HELLO} unusable. */
    public void sendServerHello(PlayerSession session) {
        session.send(plugin, new PacketWriter(Protocol.S2C_SERVER_HELLO)
                .varInt(Protocol.VERSION)
                .bytes(session.challenge())
                .string(serverLabel)
                .toByteArray());
    }

    @Override
    public void onPluginMessageReceived(@NotNull String channel, @NotNull Player player, byte @NotNull [] message) {
        if (!Protocol.CHANNEL.equals(channel) || message.length > Protocol.MAX_FRAME_BYTES) {
            return;
        }
        Optional<PlayerSession> session = sessions.byUuid(player.getUniqueId());
        if (session.isEmpty()) {
            return;
        }

        try {
            PacketReader reader = new PacketReader(message);
            switch (reader.opcode()) {
                case Protocol.C2S_CLIENT_HELLO -> onClientHello(session.get(), reader);
                case Protocol.C2S_KEY_REQUEST -> onKeyRequest(session.get(), reader);
                case Protocol.C2S_MESSAGE -> onMessage(session.get(), reader);
                default -> { /* unknown opcodes come from newer clients and are ignored by contract */ }
            }
        } catch (PacketReader.MalformedFrameException e) {
            plugin.getSLF4JLogger().debug("Discarding a malformed frame from {}", player.getName(), e);
        }
    }

    // -- handshake ------------------------------------------------------------

    private void onClientHello(PlayerSession session, PacketReader reader) {
        int version = reader.varInt();
        byte[] identityKey = reader.fixedBytes(Protocol.ED25519_PUBLIC_LEN);
        byte[] kexKey = reader.fixedBytes(Protocol.X25519_PUBLIC_LEN);
        byte[] signature = reader.fixedBytes(Protocol.ED25519_SIGNATURE_LEN);
        byte[] keyBinding = reader.fixedBytes(Protocol.ED25519_SIGNATURE_LEN);

        if (session.state() != PlayerSession.State.AWAITING_CLIENT_HELLO) {
            // Keys are announced once per session and rotated by reconnecting. Honouring a second
            // hello would allow an identity swap mid-session, under a fingerprint peers have
            // already verified.
            return;
        }
        if (version != Protocol.VERSION) {
            reject(session, "Server speaks protocol v" + Protocol.VERSION + ", client speaks v" + version);
            return;
        }

        byte[] expected = SignatureContext.handshake(session.challenge(), session.uuid(), identityKey, kexKey);
        if (!SignatureVerifier.verify(identityKey, expected, signature)) {
            plugin.getSLF4JLogger().warn("Rejected the handshake from {}: signature did not match the announced key",
                    session.name());
            reject(session, "Handshake signature did not verify");
            return;
        }
        // Peers verify this binding too. Checking it here keeps a key that every peer would
        // reject out of the directory in the first place.
        if (!SignatureVerifier.verify(identityKey,
                SignatureContext.keyBinding(session.uuid(), identityKey, kexKey), keyBinding)) {
            plugin.getSLF4JLogger().warn("Rejected the handshake from {}: exchange key is not bound "
                    + "to the announced identity", session.name());
            reject(session, "Exchange key binding did not verify");
            return;
        }

        if (!session.establish(identityKey, kexKey, keyBinding)) {
            // The handshake timeout won the race. Reporting it lets the client stop waiting
            // immediately instead of sitting out its own timeout.
            reject(session, "Handshake arrived after the server stopped waiting");
            return;
        }
        session.send(plugin, new PacketWriter(Protocol.S2C_HANDSHAKE_RESULT)
                .bool(true)
                .string("")
                .toByteArray());
        plugin.getSLF4JLogger().info("{} is now encrypted (fingerprint {})",
                session.name(), SignatureVerifier.fingerprint(identityKey));
    }

    /**
     * Handshake rejections are the one exception to config-driven wording: the client shows them
     * in the failure toast rather than chat, and they are installation diagnostics rather than
     * player-facing prose.
     */
    private void reject(PlayerSession session, String reason) {
        session.markUnencrypted();
        session.send(plugin, new PacketWriter(Protocol.S2C_HANDSHAKE_RESULT)
                .bool(false)
                .string(reason)
                .toByteArray());
    }

    // -- key directory --------------------------------------------------------

    private void onKeyRequest(PlayerSession session, PacketReader reader) {
        int requestId = reader.varInt();
        String targetName = reader.string(64);
        EncryptoConfig.Messages messages = config.messages();

        if (!session.consumeLookupBudget(config.maxMessagesPerMinute(), RATE_WINDOW_NANOS)) {
            chat(session, messages.rateLimited());
            session.send(plugin, keyResponse(requestId, Protocol.KEY_NOT_ENCRYPTED, targetName));
            return;
        }
        if (!session.isEstablished()) {
            chat(session, messages.senderNotHandshaken());
            session.send(plugin, keyResponse(requestId, Protocol.KEY_NOT_ENCRYPTED, targetName));
            return;
        }

        Optional<PlayerSession> target = sessions.byName(targetName);
        if (target.isEmpty()) {
            chat(session, messages.playerNotFound(), Placeholder.unparsed("target", targetName));
            session.send(plugin, keyResponse(requestId, Protocol.KEY_UNKNOWN_PLAYER, targetName));
            return;
        }
        PlayerSession peer = target.get();
        if (peer.uuid().equals(session.uuid())) {
            chat(session, messages.cannotMessageSelf());
            session.send(plugin, keyResponse(requestId, Protocol.KEY_SELF, peer.name()));
            return;
        }
        if (!peer.isEstablished()) {
            // The message is never forwarded, but the recipient is still told that someone tried
            // to reach them and why it did not arrive.
            boolean prompted = nudge(peer, session);
            chat(session, prompted ? messages.targetNotEncryptedPrompted() : messages.targetNotEncrypted(),
                    Placeholder.unparsed("target", peer.name()));
            session.send(plugin, keyResponse(requestId, Protocol.KEY_NOT_ENCRYPTED, peer.name()));
            return;
        }

        session.send(plugin, new PacketWriter(Protocol.S2C_KEY_RESPONSE)
                .varInt(requestId)
                .byteValue(Protocol.KEY_OK)
                .string(peer.name())
                .uuid(peer.uuid())
                .bytes(peer.identityPublicKey())
                .bytes(peer.kexPublicKey())
                .bytes(peer.keyBinding())
                .toByteArray());
    }

    private static byte[] keyResponse(int requestId, byte status, String name) {
        return new PacketWriter(Protocol.S2C_KEY_RESPONSE)
                .varInt(requestId)
                .byteValue(status)
                .string(name)
                .toByteArray();
    }

    /**
     * Tells {@code target} that {@code sender} cannot reach them without the mod.
     *
     * @return whether the prompt was actually shown, or suppressed by the per-sender cooldown
     */
    private boolean nudge(PlayerSession target, PlayerSession sender) {
        if (!target.shouldNudge(sender.uuid(), config.nudgeCooldown().toNanos())) {
            return false;
        }
        chat(target, config.messages().encryptionNudge(), Placeholder.unparsed("sender", sender.name()));
        return true;
    }

    // -- relay ----------------------------------------------------------------

    private void onMessage(PlayerSession session, PacketReader reader) {
        UUID targetUuid = reader.uuid();
        byte[] sealedToKey = reader.fixedBytes(Protocol.X25519_PUBLIC_LEN);
        byte[] ephemeralKey = reader.fixedBytes(Protocol.X25519_PUBLIC_LEN);
        byte[] nonce = reader.fixedBytes(Protocol.GCM_NONCE_LEN);
        byte[] ciphertext = reader.bytes(Protocol.MAX_CIPHERTEXT_BYTES);
        byte[] signature = reader.fixedBytes(Protocol.ED25519_SIGNATURE_LEN);
        EncryptoConfig.Messages messages = config.messages();

        if (!session.isEstablished()) {
            chat(session, messages.senderNotHandshaken());
            session.send(plugin, status(Protocol.SEND_NOT_HANDSHAKEN, ""));
            return;
        }
        if (!session.consumeSendBudget(config.maxMessagesPerMinute(), RATE_WINDOW_NANOS)) {
            chat(session, messages.rateLimited());
            session.send(plugin, status(Protocol.SEND_RATE_LIMITED, ""));
            return;
        }

        byte[] signed = SignatureContext.message(
                session.uuid(), targetUuid, ephemeralKey, nonce, ciphertext);
        if (!SignatureVerifier.verify(session.identityPublicKey(), signed, signature)) {
            plugin.getSLF4JLogger().warn("Refused to relay a message from {}: bad signature", session.name());
            chat(session, messages.senderBadSignature());
            session.send(plugin, status(Protocol.SEND_BAD_SIGNATURE, ""));
            return;
        }

        Optional<PlayerSession> target = sessions.byUuid(targetUuid);
        if (target.isEmpty()) {
            chat(session, messages.targetOffline());
            session.send(plugin, status(Protocol.SEND_TARGET_OFFLINE, ""));
            return;
        }
        PlayerSession recipient = target.get();
        if (!recipient.isEstablished()) {
            // Reached when the recipient reconnected without the mod while the sender still had
            // their key cached, so it needs the same prompt as the lookup path.
            boolean prompted = nudge(recipient, session);
            chat(session, prompted ? messages.targetNotEncryptedPrompted() : messages.targetNotEncrypted(),
                    Placeholder.unparsed("target", recipient.name()));
            session.send(plugin, status(Protocol.SEND_TARGET_NOT_ENCRYPTED, recipient.name()));
            return;
        }
        if (!java.util.Arrays.equals(sealedToKey, recipient.kexPublicKey())) {
            // The recipient rotated keys between the sender's lookup and this message, so the
            // ciphertext is no longer openable. It is refused instead of delivered undecryptable.
            chat(session, messages.staleKey(), Placeholder.unparsed("target", recipient.name()));
            session.send(plugin, status(Protocol.SEND_STALE_KEY, recipient.name()));
            return;
        }

        recipient.send(plugin, new PacketWriter(Protocol.S2C_MESSAGE)
                .uuid(session.uuid())
                .string(session.name())
                .bytes(session.identityPublicKey())
                .bytes(ephemeralKey)
                .bytes(nonce)
                .bytes(ciphertext)
                .bytes(signature)
                .toByteArray());
        session.send(plugin, status(Protocol.SEND_OK, recipient.name()));
    }

    private static byte[] status(byte code, String detail) {
        return new PacketWriter(Protocol.S2C_MESSAGE_STATUS)
                .byteValue(code)
                .string(detail)
                .toByteArray();
    }

    private void chat(PlayerSession recipient, String template, TagResolver... placeholders) {
        recipient.sendChat(plugin, config.messages().render(template, placeholders));
    }
}
