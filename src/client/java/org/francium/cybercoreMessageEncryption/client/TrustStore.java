package org.francium.cybercoreMessageEncryption.client;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.francium.cybercoreMessageEncryption.CybercoreMessageEncryption;
import org.francium.cybercoreMessageEncryption.crypto.CryptoKeys;

/**
 * Trust-on-first-use pinning of other players' identity keys.
 * <p>
 * This is the only defence against the relay lying about who owns which key: the server hands out
 * public keys, so a hostile server could substitute its own and read everything. What it cannot do
 * is substitute one silently — the previously pinned fingerprint would change, which is what this
 * class detects.
 * <p>
 * Pins are scoped per server address, since a different server is a different key directory.
 */
public final class TrustStore {
    public enum Verdict {
        /** Fingerprint matches the existing pin. */
        TRUSTED,
        /** No pin existed for this player on this server; the key has just been pinned. */
        FIRST_SEEN,
        /** Pinned fingerprint differs — either a key rotation or an active attack. */
        CHANGED
    }

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private final Path file;
    /** server address -> player uuid -> pinned fingerprint. */
    private final Map<String, Map<UUID, String>> pins = new ConcurrentHashMap<>();

    public TrustStore(Path file) {
        this.file = file;
        load();
    }

    /** Checks {@code identityPublicKey} against the pin, pinning it if this player is new here. */
    public Verdict check(String server, UUID player, byte[] identityPublicKey) {
        String fingerprint = CryptoKeys.fingerprint(identityPublicKey);
        Map<UUID, String> forServer = pins.computeIfAbsent(server, unused -> new ConcurrentHashMap<>());
        String pinned = forServer.putIfAbsent(player, fingerprint);
        if (pinned == null) {
            save();
            return Verdict.FIRST_SEEN;
        }
        return pinned.equals(fingerprint) ? Verdict.TRUSTED : Verdict.CHANGED;
    }

    /** Replaces the pin, once the new fingerprint has been confirmed out of band. */
    public void pin(String server, UUID player, byte[] identityPublicKey) {
        pins.computeIfAbsent(server, unused -> new ConcurrentHashMap<>())
                .put(player, CryptoKeys.fingerprint(identityPublicKey));
        save();
    }

    public String pinnedFingerprint(String server, UUID player) {
        Map<UUID, String> forServer = pins.get(server);
        return forServer == null ? null : forServer.get(player);
    }

    public void forget(String server, UUID player) {
        Map<UUID, String> forServer = pins.get(server);
        if (forServer != null && forServer.remove(player) != null) {
            save();
        }
    }

    private void load() {
        if (!Files.isRegularFile(file)) {
            return;
        }
        try {
            JsonObject root = JsonParser.parseString(Files.readString(file, StandardCharsets.UTF_8))
                    .getAsJsonObject();
            for (String server : root.keySet()) {
                Map<UUID, String> forServer = new ConcurrentHashMap<>();
                JsonObject players = root.getAsJsonObject(server);
                for (String uuid : players.keySet()) {
                    forServer.put(UUID.fromString(uuid), players.get(uuid).getAsString());
                }
                pins.put(server, forServer);
            }
        } catch (IOException | RuntimeException e) {
            // Losing pins downgrades every peer to FIRST_SEEN, which is noisy but not unsafe.
            CybercoreMessageEncryption.LOGGER.warn("Could not read the trust store at {}", file, e);
        }
    }

    private synchronized void save() {
        JsonObject root = new JsonObject();
        pins.forEach((server, players) -> {
            JsonObject entry = new JsonObject();
            players.forEach((uuid, fingerprint) -> entry.addProperty(uuid.toString(), fingerprint));
            root.add(server, entry);
        });
        try {
            Files.createDirectories(file.getParent());
            Path temporary = file.resolveSibling(file.getFileName() + ".tmp");
            Files.writeString(temporary, GSON.toJson(root), StandardCharsets.UTF_8);
            Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            CybercoreMessageEncryption.LOGGER.warn("Could not write the trust store at {}", file, e);
        }
    }
}
