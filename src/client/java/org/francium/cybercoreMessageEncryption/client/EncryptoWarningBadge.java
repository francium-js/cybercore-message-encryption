package org.francium.cybercoreMessageEncryption.client;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.Font;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.network.chat.Component;

/**
 * A red badge sitting just above the chat input while the current server offers no encryption.
 * <p>
 * The join toast is easy to miss, and the warning matters most at the moment of typing, so it is
 * placed next to the input. It is drawn only for the unencrypted case: a permanent "all good"
 * badge would blend into the interface and stop being read.
 */
public final class EncryptoWarningBadge {
    private static final int BACKDROP = 0xC0000000;
    private static final int ACCENT = 0xFFFF5555;
    private static final int LABEL = 0xFFFF5555;

    private static final int ACCENT_WIDTH = 2;
    private static final int PADDING_X = 4;
    private static final int PADDING_Y = 2;
    /** Gap between the badge and the input box below it. */
    private static final int GAP = 2;

    /**
     * @param inputX      left edge of the chat input
     * @param inputY      top edge of the chat input; the badge sits above this
     * @param inputWidth  width of the chat input, used to right-align the badge
     */
    public static void renderAbove(GuiGraphicsExtractor extractor, int inputX, int inputY, int inputWidth) {
        EncryptoSession session = EncryptoClientState.session();
        if (session == null || !session.isKnownUnencrypted()) {
            return;
        }

        Font font = Minecraft.getInstance().font;
        Component label = Component.translatable("cybercore.encrypto.hud.unencrypted");

        int width = ACCENT_WIDTH + PADDING_X + font.width(label) + PADDING_X;
        int height = font.lineHeight + PADDING_Y * 2;

        // Flush with the left edge of the input. The command suggestion popup shares this strip
        // and is anchored near the word being completed, so the two can overlap while a command is
        // being typed; the badge is drawn last and stays on top.
        int left = inputX;
        int bottom = inputY - GAP;
        int top = bottom - height;

        extractor.fill(left, top, left + width, bottom, BACKDROP);
        extractor.fill(left, top, left + ACCENT_WIDTH, bottom, ACCENT);
        extractor.text(font, label, left + ACCENT_WIDTH + PADDING_X, top + PADDING_Y, LABEL);
    }

    private EncryptoWarningBadge() {
    }
}
