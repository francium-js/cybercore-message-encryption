package org.francium.cybercoreMessageEncryption.client;

import java.util.Locale;
import java.util.Optional;
import java.util.Set;

import net.minecraft.ChatFormatting;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.Style;

import org.francium.cybercoreMessageEncryption.crypto.CryptoKeys;

/**
 * Takes over {@code /msg} and {@code /r}, but only while the handshake is up.
 * <p>
 * Without an established session the mod adds nothing to private messaging: the command travels to
 * the server exactly as it would with no mod installed, so the server's own {@code /msg} and
 * {@code /r} keep working. That is also why interception lives in
 * {@code ClientPacketListenerMixin} rather than in a registered client-side command — a registered
 * command would shadow the server's version even for commands this class declines to handle.
 * <p>
 * The join notification already states which mode is in effect, so nothing here announces the
 * fallback a second time.
 */
public final class EncryptoCommands {
    private static final Set<String> PRIVATE_MESSAGE_LABELS = Set.of("msg", "tell", "w", "whisper", "m");
    private static final Set<String> REPLY_LABELS = Set.of("r", "reply");
    private static final String CONTROL_LABEL = "encrypto";

    /**
     * @return {@code true} if the command was handled locally and must not reach the server
     */
    public static boolean intercept(String rawCommand) {
        EncryptoSession session = EncryptoClientState.session();
        if (session == null) {
            return false;
        }

        String command = rawCommand.trim();
        int space = command.indexOf(' ');
        String label = (space < 0 ? command : command.substring(0, space)).toLowerCase(Locale.ROOT);
        String rest = space < 0 ? "" : command.substring(space + 1).trim();

        if (label.equals(CONTROL_LABEL)) {
            return control(session, rest);
        }
        if (!session.isEstablished()) {
            // No plugin on this server, or the handshake failed; leave the command untouched.
            return false;
        }
        if (PRIVATE_MESSAGE_LABELS.contains(label)) {
            return privateMessage(session, rest);
        }
        if (REPLY_LABELS.contains(label)) {
            return session.reply(rest);
        }
        return false;
    }

    private static boolean privateMessage(EncryptoSession session, String arguments) {
        int space = arguments.indexOf(' ');
        if (space < 0) {
            EncryptoChat.error(Component.translatable("cybercore.encrypto.error.usage_msg"));
            return true;
        }
        return session.sendPrivateMessage(arguments.substring(0, space), arguments.substring(space + 1).trim());
    }

    // -- /encrypto ------------------------------------------------------------

    /**
     * @return {@code false} for an unrecognised subcommand, so the plugin's own {@code /encrypto}
     *         and its admin subcommands stay reachable
     */
    private static boolean control(EncryptoSession session, String arguments) {
        int space = arguments.indexOf(' ');
        String subcommand = (space < 0 ? arguments : arguments.substring(0, space)).toLowerCase(Locale.ROOT);
        String rest = space < 0 ? "" : arguments.substring(space + 1).trim();

        switch (subcommand) {
            case "", "status" -> status(session);
            case "fingerprint" -> fingerprint(session, rest);
            case "trust" -> trust(session, rest);
            case "forget" -> forget(session, rest);
            default -> {
                return false;
            }
        }
        return true;
    }

    private static void status(EncryptoSession session) {
        Component state = switch (session.state()) {
            case ESTABLISHED -> Component.translatable("cybercore.encrypto.status.established")
                    .withStyle(Style.EMPTY.withColor(ChatFormatting.GREEN));
            case AWAITING_SERVER_HELLO, AWAITING_RESULT ->
                    Component.translatable("cybercore.encrypto.status.handshaking")
                            .withStyle(Style.EMPTY.withColor(ChatFormatting.YELLOW));
            case FAILED -> Component.translatable("cybercore.encrypto.status.failed")
                    .withStyle(Style.EMPTY.withColor(ChatFormatting.RED));
            case DISCONNECTED -> Component.translatable("cybercore.encrypto.status.disconnected")
                    .withStyle(Style.EMPTY.withColor(ChatFormatting.GRAY));
        };
        EncryptoChat.info(Component.translatable("cybercore.encrypto.status.line", state));
        if (session.state() == EncryptoSession.State.FAILED) {
            EncryptoChat.info(session.failureReason());
        }
        EncryptoChat.info(Component.translatable("cybercore.encrypto.status.fingerprint",
                session.identity().fingerprint()));
    }

    private static void fingerprint(EncryptoSession session, String playerName) {
        if (playerName.isEmpty()) {
            EncryptoChat.info(Component.translatable("cybercore.encrypto.status.fingerprint",
                    session.identity().fingerprint()));
            return;
        }
        Optional<EncryptoSession.Peer> peer = session.cachedPeer(playerName);
        if (peer.isEmpty()) {
            EncryptoChat.error(Component.translatable("cybercore.encrypto.error.no_cached_key", playerName));
            return;
        }
        EncryptoChat.info(Component.translatable("cybercore.encrypto.status.peer_fingerprint",
                peer.get().name(), CryptoKeys.fingerprint(peer.get().identityPublicKey())));
    }

    private static void trust(EncryptoSession session, String playerName) {
        if (playerName.isEmpty()) {
            EncryptoChat.error(Component.translatable("cybercore.encrypto.error.usage_trust"));
            return;
        }
        Optional<EncryptoSession.Peer> peer = session.cachedPeer(playerName);
        if (peer.isEmpty()) {
            EncryptoChat.error(Component.translatable("cybercore.encrypto.error.no_cached_key", playerName));
            return;
        }
        session.trustStore().pin(session.serverKey(), peer.get().uuid(), peer.get().identityPublicKey());
        EncryptoChat.info(Component.translatable("cybercore.encrypto.trust.pinned",
                peer.get().name(), CryptoKeys.fingerprint(peer.get().identityPublicKey())));
    }

    private static void forget(EncryptoSession session, String playerName) {
        Optional<EncryptoSession.Peer> peer = session.cachedPeer(playerName);
        if (peer.isEmpty()) {
            EncryptoChat.error(Component.translatable("cybercore.encrypto.error.no_cached_key", playerName));
            return;
        }
        session.trustStore().forget(session.serverKey(), peer.get().uuid());
        EncryptoChat.info(Component.translatable("cybercore.encrypto.trust.forgotten", peer.get().name()));
    }

    private EncryptoCommands() {
    }
}
