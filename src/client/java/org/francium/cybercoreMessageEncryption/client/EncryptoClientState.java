package org.francium.cybercoreMessageEncryption.client;

import org.jetbrains.annotations.Nullable;

/**
 * Holds the one live {@link EncryptoSession}.
 * <p>
 * A separate holder rather than a field on the entrypoint, so the command mixin can reach the
 * session without pulling the whole initializer onto the mixin's classpath. It stays {@code null}
 * when key setup failed, a case every caller must handle.
 */
public final class EncryptoClientState {
    private static volatile EncryptoSession session;

    static void install(EncryptoSession session) {
        EncryptoClientState.session = session;
    }

    public static @Nullable EncryptoSession session() {
        return session;
    }

    private EncryptoClientState() {
    }
}
