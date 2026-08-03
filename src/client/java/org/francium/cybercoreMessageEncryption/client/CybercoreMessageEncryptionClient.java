package org.francium.cybercoreMessageEncryption.client;

import java.nio.file.Path;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientTickEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayNetworking;
import net.fabricmc.loader.api.FabricLoader;

import org.francium.cybercoreMessageEncryption.CybercoreMessageEncryption;
import org.francium.cybercoreMessageEncryption.crypto.ClientIdentity;
import org.francium.cybercoreMessageEncryption.protocol.EncryptoPayload;

/**
 * Wires the session into the client: loads the identity, then hooks join/leave, the payload
 * receiver and the tick that drives handshake timeouts.
 */
public class CybercoreMessageEncryptionClient implements ClientModInitializer {

    @Override
    public void onInitializeClient() {
        Path configDirectory = FabricLoader.getInstance().getConfigDir().resolve("cybercore-encrypto");

        EncryptoSession session;
        try {
            ClientIdentity identity = ClientIdentity.loadOrCreate(configDirectory.resolve("identity.json"));
            session = new EncryptoSession(identity, new TrustStore(configDirectory.resolve("trusted.json")));
        } catch (Exception e) {
            // Without keys there is nothing to hook up. Leaving the session null keeps /msg on its
            // ordinary path to the server instead of silently dropping messages.
            CybercoreMessageEncryption.LOGGER.error(
                    "Could not set up encryption keys in {}; private messages will not be encrypted",
                    configDirectory, e);
            return;
        }

        EncryptoClientState.install(session);

        ClientPlayConnectionEvents.JOIN.register((handler, sender, client) -> session.onJoin());
        ClientPlayConnectionEvents.DISCONNECT.register((handler, client) -> session.onDisconnect());
        ClientTickEvents.END_CLIENT_TICK.register(client -> session.tick());

        ClientPlayNetworking.registerGlobalReceiver(EncryptoPayload.TYPE,
                (payload, context) -> session.onPayload(payload.data()));

        CybercoreMessageEncryption.LOGGER.info("Encrypted private messaging ready (fingerprint {})",
                session.identity().fingerprint());
    }
}
