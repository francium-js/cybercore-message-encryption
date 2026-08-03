package org.francium.cybercoreServerMessageEncryption.command;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

import com.mojang.brigadier.Command;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.context.CommandContext;
import com.mojang.brigadier.suggestion.SuggestionProvider;
import com.mojang.brigadier.tree.LiteralCommandNode;

import io.papermc.paper.command.brigadier.CommandSourceStack;
import io.papermc.paper.command.brigadier.Commands;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import org.francium.cybercoreServerMessageEncryption.EncryptoConfig;
import org.francium.cybercoreServerMessageEncryption.crypto.SignatureVerifier;
import org.francium.cybercoreServerMessageEncryption.session.PlayerSession;
import org.francium.cybercoreServerMessageEncryption.session.SessionRegistry;

/**
 * Server-side {@code /msg} and {@code /r}, registered as main labels so they take over the vanilla
 * commands.
 * <p>
 * A client running the mod never reaches this code: it intercepts the command and sends ciphertext
 * instead. Everything else — vanilla clients, failed handshakes, the console — lands here and is
 * refused. Registering these labels is what prevents the vanilla commands from carrying plaintext
 * through the server.
 */
public final class MessageCommands {
    /** Private-message labels; each is registered as a main label so it overrides vanilla. */
    public static final List<String> MESSAGE_LABELS = List.of("msg", "tell", "w", "whisper", "m");
    public static final List<String> REPLY_LABELS = List.of("r", "reply");

    public static final String ADMIN_PERMISSION = "cybercore.encrypto.admin";

    private final Plugin plugin;
    private final SessionRegistry sessions;
    private final EncryptoConfig config;

    public MessageCommands(Plugin plugin, SessionRegistry sessions, EncryptoConfig config) {
        this.plugin = plugin;
        this.sessions = sessions;
        this.config = config;
    }

    public LiteralCommandNode<CommandSourceStack> privateMessageNode(String label) {
        return Commands.literal(label)
                .then(Commands.argument("player", StringArgumentType.word())
                        .suggests(onlinePlayers())
                        .then(Commands.argument("message", StringArgumentType.greedyString())
                                .executes(this::refuse)))
                .build();
    }

    public LiteralCommandNode<CommandSourceStack> replyNode(String label) {
        return Commands.literal(label)
                .then(Commands.argument("message", StringArgumentType.greedyString())
                        .executes(this::refuse))
                .build();
    }

    public LiteralCommandNode<CommandSourceStack> controlNode() {
        return Commands.literal("encrypto")
                .executes(this::executeStatus)
                .then(Commands.literal("status").executes(this::executeStatus))
                .then(Commands.literal("list")
                        .requires(source -> source.getSender().hasPermission(ADMIN_PERMISSION))
                        .executes(this::executeList))
                .build();
    }

    private SuggestionProvider<CommandSourceStack> onlinePlayers() {
        return (context, builder) -> {
            String prefix = builder.getRemaining().toLowerCase(Locale.ROOT);
            sessions.all().stream()
                    .map(PlayerSession::name)
                    .filter(name -> name.toLowerCase(Locale.ROOT).startsWith(prefix))
                    .forEach(builder::suggest);
            return builder.buildFuture();
        };
    }

    // -- /msg and /r ----------------------------------------------------------

    /**
     * Both commands refuse unconditionally. There is no unencrypted path through this plugin, and
     * silently downgrading to plaintext would leave both players believing they were protected.
     */
    private int refuse(CommandContext<CommandSourceStack> context) {
        CommandSender sender = context.getSource().getSender();
        EncryptoConfig.Messages messages = config.messages();

        if (sender instanceof Player player) {
            Optional<PlayerSession> session = sessions.byUuid(player.getUniqueId());
            if (session.isPresent() && session.get().isEstablished()) {
                // The client can encrypt but sent plaintext, so the mod is installed and something
                // else failed. That warrants different wording from "install the mod".
                sender.sendMessage(messages.render(messages.clientShouldEncrypt()));
                return 0;
            }
        }
        sender.sendMessage(messages.render(messages.encryptionRequired()));
        return 0;
    }

    // -- /encrypto ------------------------------------------------------------

    private int executeStatus(CommandContext<CommandSourceStack> context) {
        CommandSender sender = context.getSource().getSender();
        if (!(sender instanceof Player player)) {
            sender.sendMessage(Component.text("Encrypted sessions: " + sessions.establishedCount()
                    + "/" + sessions.all().size(), NamedTextColor.GRAY));
            return Command.SINGLE_SUCCESS;
        }

        Optional<PlayerSession> session = sessions.byUuid(player.getUniqueId());
        if (session.isEmpty() || !session.get().isEstablished()) {
            sender.sendMessage(Component.text("Your private messages are NOT encrypted on this server.",
                    NamedTextColor.RED));
            sender.sendMessage(Component.text(
                    "Install cybercore-message-encryption and rejoin.", NamedTextColor.GRAY));
            return Command.SINGLE_SUCCESS;
        }
        sender.sendMessage(Component.text("Your private messages are end-to-end encrypted.",
                NamedTextColor.GREEN));
        sender.sendMessage(Component.text("Key the server has for you: "
                + SignatureVerifier.fingerprint(session.get().identityPublicKey()), NamedTextColor.GRAY));
        return Command.SINGLE_SUCCESS;
    }

    private int executeList(CommandContext<CommandSourceStack> context) {
        CommandSender sender = context.getSource().getSender();
        sender.sendMessage(Component.text("Encrypted sessions: " + sessions.establishedCount()
                + "/" + sessions.all().size(), NamedTextColor.GRAY));
        sessions.all().stream()
                .sorted(java.util.Comparator.comparing(PlayerSession::name, String.CASE_INSENSITIVE_ORDER))
                .forEach(session -> {
                    byte[] key = session.identityPublicKey();
                    sender.sendMessage(Component.text("  " + session.name() + " — "
                                    + (key == null ? "no key" : SignatureVerifier.fingerprint(key)),
                            key == null ? NamedTextColor.RED : NamedTextColor.GREEN));
                });
        return Command.SINGLE_SUCCESS;
    }
}
