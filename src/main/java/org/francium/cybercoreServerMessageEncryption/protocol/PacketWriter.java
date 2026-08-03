package org.francium.cybercoreServerMessageEncryption.protocol;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/** Minimal big-endian/VarInt writer; the mirror of {@link PacketReader}. */
public final class PacketWriter {
    private final ByteArrayOutputStream out = new ByteArrayOutputStream(64);

    public PacketWriter(byte opcode) {
        this.out.write(opcode);
    }

    public PacketWriter byteValue(int value) {
        out.write(value & 0xFF);
        return this;
    }

    public PacketWriter bool(boolean value) {
        return byteValue(value ? 1 : 0);
    }

    public PacketWriter varInt(int value) {
        int remaining = value;
        while ((remaining & ~0x7F) != 0) {
            out.write((remaining & 0x7F) | 0x80);
            remaining >>>= 7;
        }
        out.write(remaining);
        return this;
    }

    public PacketWriter bytes(byte[] value) {
        varInt(value.length);
        out.write(value, 0, value.length);
        return this;
    }

    public PacketWriter string(String value) {
        return bytes(value.getBytes(StandardCharsets.UTF_8));
    }

    public PacketWriter uuid(UUID value) {
        writeLong(value.getMostSignificantBits());
        writeLong(value.getLeastSignificantBits());
        return this;
    }

    private void writeLong(long value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.write((int) (value >>> shift) & 0xFF);
        }
    }

    public byte[] toByteArray() {
        return out.toByteArray();
    }
}
