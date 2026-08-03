package org.francium.cybercoreServerMessageEncryption.session;

import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import net.kyori.adventure.text.Component;

import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import org.francium.cybercoreServerMessageEncryption.protocol.Protocol;
import org.jetbrains.annotations.Nullable;

/**
 * One connected player's view of the protocol: the challenge issued to them, the public keys they
 * answered with, and their rate-limit budget.
 * <p>
 * The handshake is driven from the player's region thread while its timeout fires on the async
 * scheduler, so the state is an atomic the two contend for and the key fields are volatile.
 */
public final class PlayerSession {
    private static final SecureRandom RANDOM = new SecureRandom();

    public enum State {
        /** {@code SERVER_HELLO} has been sent; the client has not answered yet. */
        AWAITING_CLIENT_HELLO,
        /** Keys accepted; this player can send and receive ciphertext. */
        ESTABLISHED,
        /** No mod, or a failed handshake; private messages from this player are refused. */
        UNENCRYPTED
    }

    private final Player player;
    private final UUID uuid;
    private final String name;
    private final byte[] challenge = new byte[Protocol.HANDSHAKE_NONCE_LEN];

    // Atomic rather than volatile: the handshake resolves on the player's region thread while the
    // timeout fires on the async scheduler, and a plain read-then-write would let a late timeout
    // overwrite a handshake that has just succeeded.
    private final AtomicReference<State> state = new AtomicReference<>(State.AWAITING_CLIENT_HELLO);
    private volatile byte[] identityPublicKey;
    private volatile byte[] kexPublicKey;
    private volatile byte[] keyBinding;


    private final Budget sendBudget = new Budget();
    private final Budget lookupBudget = new Budget();

    /** When each sender was last told this player needs the mod; backs the nudge cooldown. */
    private final Map<UUID, Long> nudgedBy = new ConcurrentHashMap<>();

    public PlayerSession(Player player) {
        this.player = player;
        this.uuid = player.getUniqueId();
        this.name = player.getName();
        RANDOM.nextBytes(challenge);
    }

    public Player player() {
        return player;
    }

    public UUID uuid() {
        return uuid;
    }

    public String name() {
        return name;
    }

    public byte[] challenge() {
        return challenge.clone();
    }

    public State state() {
        return state.get();
    }

    public boolean isEstablished() {
        return state.get() == State.ESTABLISHED;
    }

    public byte @Nullable [] identityPublicKey() {
        byte[] key = identityPublicKey;
        return key == null ? null : key.clone();
    }

    public byte @Nullable [] kexPublicKey() {
        byte[] key = kexPublicKey;
        return key == null ? null : key.clone();
    }

    /** The owner's signature tying {@link #kexPublicKey()} to {@link #identityPublicKey()}. */
    public byte @Nullable [] keyBinding() {
        byte[] value = keyBinding;
        return value == null ? null : value.clone();
    }

    /**
     * @return whether the handshake was still open; a late hello loses to an already-decided state
     */
    public boolean establish(byte[] identityPublicKey, byte[] kexPublicKey, byte[] keyBinding) {
        this.identityPublicKey = identityPublicKey.clone();
        this.kexPublicKey = kexPublicKey.clone();
        this.keyBinding = keyBinding.clone();
        if (state.compareAndSet(State.AWAITING_CLIENT_HELLO, State.ESTABLISHED)) {
            return true;
        }
        this.identityPublicKey = null;
        this.kexPublicKey = null;
        this.keyBinding = null;
        return false;
    }

    /** Marks the handshake as never going to happen; never downgrades a success. */
    public boolean markUnencrypted() {
        return state.compareAndSet(State.AWAITING_CLIENT_HELLO, State.UNENCRYPTED);
    }


    /**
     * Fixed-window budget bounding how much a scripted client can push through the relay. The
     * configured default sits far above human typing speed.
     */
    public boolean consumeSendBudget(int maxPerWindow, long windowNanos) {
        return sendBudget.consume(maxPerWindow, windowNanos);
    }

    /** Separate ceiling for key lookups, which a client can otherwise issue without ever sending. */
    public boolean consumeLookupBudget(int maxPerWindow, long windowNanos) {
        return lookupBudget.consume(maxPerWindow, windowNanos);
    }

    /** Fixed window; a lost increment during a concurrent reset is acceptable for a limit this loose. */
    private static final class Budget {
        private final AtomicLong windowStart = new AtomicLong(System.nanoTime());
        private final AtomicLong count = new AtomicLong();

        boolean consume(int maxPerWindow, long windowNanos) {
            long now = System.nanoTime();
            long start = windowStart.get();
            if (now - start >= windowNanos && windowStart.compareAndSet(start, now)) {
                count.set(0);
            }
            return count.incrementAndGet() <= maxPerWindow;
        }
    }

    /**
     * Whether {@code sender} may prompt this player to install the mod right now.
     * <p>
     * Every {@code /msg} attempt against a player without the mod reaches the server, so without a
     * per-sender cooldown the prompt could be driven as a spam channel. The check and the update
     * share one {@code compute} call so two senders on different region threads cannot both pass
     * for the same slot.
     */
    public boolean shouldNudge(UUID sender, long cooldownNanos) {
        long now = System.nanoTime();
        boolean[] allowed = {false};
        nudgedBy.compute(sender, (key, previous) -> {
            if (previous != null && now - previous < cooldownNanos) {
                return previous;
            }
            allowed[0] = true;
            return now;
        });
        return allowed[0];
    }

    /** Delivers a frame on the player's own region thread, as Folia requires. */
    public void send(Plugin plugin, byte[] frame) {
        player.getScheduler().run(plugin, task -> {
            if (!player.isOnline()) {
                return;
            }
            if (!player.getListeningPluginChannels().contains(Protocol.CHANNEL)) {
                // Bukkit would drop the frame silently, so record it in the log instead.
                plugin.getSLF4JLogger().debug("{} is not listening on {}, dropping a frame",
                        name, Protocol.CHANNEL);
                return;
            }
            player.sendPluginMessage(plugin, Protocol.CHANNEL, frame);
        }, null);
    }

    /** Same threading rule as {@link #send}, for chat addressed to this player. */
    public void sendChat(Plugin plugin, Component message) {
        player.getScheduler().run(plugin, task -> {
            if (player.isOnline()) {
                player.sendMessage(message);
            }
        }, null);
    }
}
