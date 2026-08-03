package org.francium.cybercoreServerMessageEncryption;

import io.papermc.paper.plugin.lifecycle.event.types.LifecycleEvents;

import org.bukkit.Bukkit;
import org.bukkit.plugin.java.JavaPlugin;
import org.francium.cybercoreServerMessageEncryption.command.MessageCommands;
import org.francium.cybercoreServerMessageEncryption.listener.ConnectionListener;
import org.francium.cybercoreServerMessageEncryption.net.EncryptoChannel;
import org.francium.cybercoreServerMessageEncryption.protocol.Protocol;
import org.francium.cybercoreServerMessageEncryption.session.SessionRegistry;

/**
 * Server half of end-to-end encrypted private messaging.
 * <p>
 * The plugin is a relay and a public-key directory: it holds no private key, cannot decrypt a
 * message body, and keeps state only while a player is online. It also takes over {@code /msg}
 * and {@code /r}, which are refused for clients that cannot encrypt rather than being carried in
 * the clear.
 */
public final class CybercoreServerMessageEncryption extends JavaPlugin {
    private final SessionRegistry sessions = new SessionRegistry();

    @Override
    public void onEnable() {
        saveDefaultConfig();
        EncryptoConfig config = EncryptoConfig.from(getConfig());

        EncryptoChannel channel = new EncryptoChannel(this, sessions, config, Bukkit.getServer().getName());

        Bukkit.getMessenger().registerOutgoingPluginChannel(this, Protocol.CHANNEL);
        Bukkit.getMessenger().registerIncomingPluginChannel(this, Protocol.CHANNEL, channel);

        getServer().getPluginManager().registerEvents(
                new ConnectionListener(this, sessions, channel, config), this);

        MessageCommands commands = new MessageCommands(this, sessions, config);
        getLifecycleManager().registerEventHandler(LifecycleEvents.COMMANDS, event -> {
            var registrar = event.registrar();
            // One label at a time: Paper only lets a main label override an existing command,
            // so declaring these as aliases would leave vanilla /msg in place.
            for (String label : MessageCommands.MESSAGE_LABELS) {
                registrar.register(commands.privateMessageNode(label),
                        "Send an end-to-end encrypted private message");
            }
            for (String label : MessageCommands.REPLY_LABELS) {
                registrar.register(commands.replyNode(label), "Reply to the last private message");
            }
            registrar.register(commands.controlNode(), "Show encrypted messaging status");
        });

        // Players stay connected across a plugin reload, so greet whoever is already online.
        Bukkit.getOnlinePlayers().forEach(player -> channel.sendServerHello(sessions.open(player)));

        getSLF4JLogger().info("Encrypted private messaging is active on channel {}", Protocol.CHANNEL);
    }

    @Override
    public void onDisable() {
        Bukkit.getMessenger().unregisterIncomingPluginChannel(this, Protocol.CHANNEL);
        Bukkit.getMessenger().unregisterOutgoingPluginChannel(this, Protocol.CHANNEL);
        sessions.clear();
    }
}
