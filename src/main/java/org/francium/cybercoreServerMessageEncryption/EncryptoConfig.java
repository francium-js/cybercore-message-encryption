package org.francium.cybercoreServerMessageEncryption;

import java.time.Duration;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.kyori.adventure.text.minimessage.tag.resolver.TagResolver;

import org.bukkit.configuration.file.FileConfiguration;

/**
 * Typed view over {@code config.yml}, resolved once at enable so no hot path touches the
 * configuration API.
 */
public record EncryptoConfig(Duration handshakeTimeout,
                             int maxMessagesPerMinute,
                             Duration nudgeCooldown,
                             Messages messages) {

    /** MiniMessage templates. Placeholders are supplied per call site. */
    public record Messages(String encryptionRequired,
                           String playerNotFound,
                           String cannotMessageSelf,
                           String clientShouldEncrypt,
                           String encryptionNudge,
                           String targetNotEncrypted,
                           String targetNotEncryptedPrompted,
                           String targetOffline,
                           String senderNotHandshaken,
                           String senderBadSignature,
                           String rateLimited,
                           String staleKey) {

        public Component render(String template, TagResolver... placeholders) {
            return MiniMessage.miniMessage().deserialize(template, placeholders);
        }
    }

    public static EncryptoConfig from(FileConfiguration source) {
        return new EncryptoConfig(
                Duration.ofSeconds(Math.max(1, source.getInt("handshake-timeout-seconds", 10))),
                Math.max(1, source.getInt("max-messages-per-minute", 60)),
                Duration.ofSeconds(Math.max(0, source.getInt("nudge-cooldown-seconds", 300))),
                new Messages(
                        string(source, "messages.encryption-required",
                                "<red>Private messages on this server are end-to-end encrypted. Install the cybercore-message-encryption mod to use /msg."),
                        string(source, "messages.player-not-found", "<red><target> is not online."),
                        string(source, "messages.cannot-message-self", "<red>You cannot message yourself."),
                        string(source, "messages.client-should-encrypt",
                                "<red>Your client has encryption available but sent this in the clear; "
                                        + "the message was not delivered."),
                        string(source, "messages.encryption-nudge",
                                "<yellow><sender> is trying to send you a private message, but it is "
                                        + "end-to-end encrypted and your client cannot open it. Install the "
                                        + "cybercore-message-encryption mod and rejoin to receive it."),
                        string(source, "messages.target-not-encrypted",
                                "<red><target> cannot receive encrypted messages - they need the mod. "
                                        + "Your message was not sent."),
                        string(source, "messages.target-not-encrypted-prompted",
                                "<red><target> cannot receive encrypted messages yet. They have been asked "
                                        + "to install the mod; your message was not sent."),
                        string(source, "messages.target-offline",
                                "<red>They went offline before the message arrived."),
                        string(source, "messages.sender-not-handshaken",
                                "<red>Your client has not completed the encryption handshake."),
                        string(source, "messages.sender-bad-signature",
                                "<red>The server could not verify your message signature; "
                                        + "it was not delivered."),
                        string(source, "messages.rate-limited",
                                "<red>You are sending messages too quickly."),
                        string(source, "messages.stale-key",
                                "<red><target> reconnected just now and their key changed. "
                                        + "Send it again.")));
    }

    private static String string(FileConfiguration source, String path, String fallback) {
        String value = source.getString(path);
        return value == null || value.isBlank() ? fallback : value;
    }
}
