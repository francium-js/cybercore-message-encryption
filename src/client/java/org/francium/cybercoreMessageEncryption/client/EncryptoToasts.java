package org.francium.cybercoreMessageEncryption.client;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.components.toasts.SystemToast;
import net.minecraft.network.chat.Component;

/**
 * The handshake result notification.
 * <p>
 * Success is deliberately brief and failure lingers, since learning that private messages are not
 * protected takes longer to read and act on. {@code SystemToastId} carries the display time, so
 * the two outcomes need separate ids rather than one shared id.
 */
public final class EncryptoToasts {
    private static final long SUCCESS_MILLIS = 3_000L;
    private static final long FAILURE_MILLIS = 10_000L;

    private static final SystemToast.SystemToastId SUCCESS_ID = new SystemToast.SystemToastId(SUCCESS_MILLIS);
    private static final SystemToast.SystemToastId FAILURE_ID = new SystemToast.SystemToastId(FAILURE_MILLIS);

    public static void handshakeSucceeded(Component description) {
        show(SUCCESS_ID, Component.translatable("cybercore.encrypto.toast.ok.title"), description);
    }

    public static void handshakeFailed(Component description) {
        show(FAILURE_ID, Component.translatable("cybercore.encrypto.toast.failed.title"), description);
    }

    private static void show(SystemToast.SystemToastId id, Component title, Component description) {
        Minecraft client = Minecraft.getInstance();
        // A reconnect can land a second result while the first toast is still on screen. Dropping
        // the stale one avoids showing "encrypted" and "not encrypted" stacked together.
        SystemToast.forceHide(client.getToastManager(), SUCCESS_ID);
        SystemToast.forceHide(client.getToastManager(), FAILURE_ID);
        // Fixed-width toast rather than the multiline variant, which grows to fit its text and
        // squeezes out the icon. Both lines must stay short enough for the standard width.
        client.getToastManager().addToast(new SystemToast(id, title, description));
    }

    private EncryptoToasts() {
    }
}
