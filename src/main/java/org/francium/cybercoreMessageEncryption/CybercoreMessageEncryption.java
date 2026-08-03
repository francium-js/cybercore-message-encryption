package org.francium.cybercoreMessageEncryption;

import net.fabricmc.api.ModInitializer;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;

import org.francium.cybercoreMessageEncryption.protocol.EncryptoPayload;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Registers the wire format. Everything else lives in the client entrypoint: this mod has no
 * server side of its own, and its counterpart is the {@code cybercore-server-message-encryption}
 * Folia plugin, which speaks the same channel through Bukkit's plugin messenger.
 */
public class CybercoreMessageEncryption implements ModInitializer {
    public static final String MOD_ID = "cybercore-message-encryption";
    public static final Logger LOGGER = LoggerFactory.getLogger(MOD_ID);

    @Override
    public void onInitialize() {
        PayloadTypeRegistry.serverboundPlay().register(EncryptoPayload.TYPE, EncryptoPayload.CODEC);
        PayloadTypeRegistry.clientboundPlay().register(EncryptoPayload.TYPE, EncryptoPayload.CODEC);
    }
}
