package org.francium.cybercoreMessageEncryption.protocol;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;

/**
 * The single custom payload used by the whole protocol.
 * <p>
 * The body is deliberately opaque to Minecraft's codec layer: it is written and read as raw bytes,
 * so the Folia plugin — which receives a plain {@code byte[]} from Bukkit's messenger — sees
 * exactly what {@link PacketWriter} produced. Framing lives in {@link Protocol}.
 */
public record EncryptoPayload(byte[] data) implements CustomPacketPayload {
    public static final Identifier ID = Identifier.fromNamespaceAndPath(Protocol.NAMESPACE, Protocol.PATH);
    public static final CustomPacketPayload.Type<EncryptoPayload> TYPE = new CustomPacketPayload.Type<>(ID);

    public static final StreamCodec<FriendlyByteBuf, EncryptoPayload> CODEC = StreamCodec.of(
            (buf, payload) -> buf.writeBytes(payload.data()),
            buf -> {
                int length = buf.readableBytes();
                if (length > Protocol.MAX_FRAME_BYTES) {
                    throw new PacketReader.MalformedFrameException("frame of " + length + " bytes is too large");
                }
                byte[] data = new byte[length];
                buf.readBytes(data);
                return new EncryptoPayload(data);
            });

    @Override
    public CustomPacketPayload.Type<? extends CustomPacketPayload> type() {
        return TYPE;
    }
}
