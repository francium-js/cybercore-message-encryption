package org.francium.cybercoreMessageEncryption.mixin.client;

import net.minecraft.client.multiplayer.ClientPacketListener;

import org.francium.cybercoreMessageEncryption.client.EncryptoCommands;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Diverts {@code /msg} and {@code /r} into the encrypted path before they are serialised.
 * <p>
 * Cancelling here, rather than registering a client-side command, is what lets an unhandled
 * command continue to the server untouched. That is the entire fallback path for servers without
 * the plugin.
 */
@Mixin(ClientPacketListener.class)
public class ClientPacketListenerMixin {

    @Inject(method = "sendCommand", at = @At("HEAD"), cancellable = true)
    private void cybercore$encryptPrivateMessages(String command, CallbackInfo callback) {
        if (EncryptoCommands.intercept(command)) {
            callback.cancel();
        }
    }
}
