package org.francium.cybercoreServerMessageEncryption.listener;

import java.util.concurrent.TimeUnit;

import org.bukkit.Bukkit;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PlayerRegisterChannelEvent;
import org.bukkit.plugin.Plugin;
import org.francium.cybercoreServerMessageEncryption.EncryptoConfig;
import org.francium.cybercoreServerMessageEncryption.net.EncryptoChannel;
import org.francium.cybercoreServerMessageEncryption.protocol.Protocol;
import org.francium.cybercoreServerMessageEncryption.session.PlayerSession;
import org.francium.cybercoreServerMessageEncryption.session.SessionRegistry;

/** Opens a session and the handshake on join; tears it down on quit. */
public final class ConnectionListener implements Listener {
    private final Plugin plugin;
    private final SessionRegistry sessions;
    private final EncryptoChannel channel;
    private final EncryptoConfig config;

    public ConnectionListener(Plugin plugin, SessionRegistry sessions, EncryptoChannel channel,
                              EncryptoConfig config) {
        this.plugin = plugin;
        this.sessions = sessions;
        this.channel = channel;
        this.config = config;
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onJoin(PlayerJoinEvent event) {
        PlayerSession session = sessions.open(event.getPlayer());

        // Bukkit silently discards a plugin message when the client has not yet announced the
        // channel, and that announcement usually lands after this event. Greeting here works only
        // if it already arrived; otherwise onChannelRegistered handles it.
        if (event.getPlayer().getListeningPluginChannels().contains(Protocol.CHANNEL)) {
            channel.sendServerHello(session);
        }

        // Nothing is sent on timeout: the client raises its own notification when no handshake
        // completes. This side only stops waiting and stays unencrypted for the session.
        Bukkit.getAsyncScheduler().runDelayed(plugin, task -> {
            if (session.markUnencrypted()) {
                plugin.getSLF4JLogger().debug("{} did not complete the handshake; treating as unencrypted",
                        session.name());
            }
        }, config.handshakeTimeout().toMillis(), TimeUnit.MILLISECONDS);
    }

    /** Channel registration is the first point at which the client is known to be listening. */
    @EventHandler(priority = EventPriority.MONITOR)
    public void onChannelRegistered(PlayerRegisterChannelEvent event) {
        if (!Protocol.CHANNEL.equals(event.getChannel())) {
            return;
        }
        sessions.byUuid(event.getPlayer().getUniqueId())
                .filter(session -> session.state() == PlayerSession.State.AWAITING_CLIENT_HELLO)
                .ifPresent(channel::sendServerHello);
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onQuit(PlayerQuitEvent event) {
        sessions.close(event.getPlayer().getUniqueId());
    }
}
