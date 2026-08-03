package org.francium.cybercoreMessageEncryption.mixin.client;

import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.screens.ChatScreen;

import org.francium.cybercoreMessageEncryption.client.EncryptoWarningBadge;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Draws the "not encrypted" badge over the open chat screen.
 * <p>
 * Injected at the tail so it lands on top of the chat screen's own contents, including the command
 * suggestion popup that shares this corner of the screen.
 */
@Mixin(ChatScreen.class)
public class ChatScreenMixin {
    @Shadow
    protected EditBox input;

    @Inject(method = "extractRenderState", at = @At("TAIL"))
    private void cybercore$warnWhenUnencrypted(GuiGraphicsExtractor extractor, int mouseX, int mouseY,
                                               float partialTick, CallbackInfo callback) {
        if (input != null) {
            EncryptoWarningBadge.renderAbove(extractor, input.getX(), input.getY(), input.getWidth());
        }
    }
}
