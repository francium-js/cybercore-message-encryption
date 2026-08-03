package org.francium.cybercoreServerMessageEncryption.session;

import java.util.Collection;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.bukkit.entity.Player;

/**
 * The public-key directory, held only for players who are currently online.
 * <p>
 * Nothing is persisted. A fresh handshake on every join means a rotated client key takes effect
 * immediately, and no long-term record of which players talk to each other accumulates.
 * <p>
 * The name index exists so a lookup never has to walk Bukkit's player list from a region thread.
 */
public final class SessionRegistry {
    private final Map<UUID, PlayerSession> byUuid = new ConcurrentHashMap<>();
    private final Map<String, UUID> byLowercaseName = new ConcurrentHashMap<>();

    public PlayerSession open(Player player) {
        PlayerSession session = new PlayerSession(player);
        byUuid.put(session.uuid(), session);
        byLowercaseName.put(session.name().toLowerCase(Locale.ROOT), session.uuid());
        return session;
    }

    public void close(UUID uuid) {
        PlayerSession removed = byUuid.remove(uuid);
        if (removed != null) {
            // Drop the name only while it still maps to this session; a reconnect may have
            // re-bound it to a newer one.
            byLowercaseName.remove(removed.name().toLowerCase(Locale.ROOT), uuid);
        }
    }

    public Optional<PlayerSession> byUuid(UUID uuid) {
        return Optional.ofNullable(byUuid.get(uuid));
    }

    public Optional<PlayerSession> byName(String name) {
        UUID uuid = byLowercaseName.get(name.toLowerCase(Locale.ROOT));
        return uuid == null ? Optional.empty() : byUuid(uuid);
    }

    public Collection<PlayerSession> all() {
        return byUuid.values();
    }

    public long establishedCount() {
        return byUuid.values().stream().filter(PlayerSession::isEstablished).count();
    }

    public void clear() {
        byUuid.clear();
        byLowercaseName.clear();
    }
}
