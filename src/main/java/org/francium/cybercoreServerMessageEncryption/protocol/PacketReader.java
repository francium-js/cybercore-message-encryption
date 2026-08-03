package org.francium.cybercoreServerMessageEncryption.protocol;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * Minimal reader for {@link PacketWriter} frames.
 * <p>
 * Every accessor is bounds-checked and throws {@link MalformedFrameException} instead of
 * {@link ArrayIndexOutOfBoundsException}: these bytes arrive from an untrusted peer, so decoding
 * failures surface as a single exception type that callers can discard.
 */
public final class PacketReader {
    /** Thrown for any frame that cannot be decoded; never propagate it to the network thread. */
    public static final class MalformedFrameException extends RuntimeException {
        public MalformedFrameException(String message) {
            super(message);
        }
    }

    private final byte[] data;
    private int cursor;

    public PacketReader(byte[] data) {
        if (data.length == 0) {
            throw new MalformedFrameException("empty frame");
        }
        this.data = data;
        this.cursor = 1; // opcode
    }

    public byte opcode() {
        return data[0];
    }

    public byte byteValue() {
        require(1);
        return data[cursor++];
    }

    public boolean bool() {
        return byteValue() != 0;
    }

    public int varInt() {
        int result = 0;
        for (int shift = 0; shift <= 28; shift += 7) {
            require(1);
            byte b = data[cursor++];
            result |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                return result;
            }
        }
        throw new MalformedFrameException("VarInt is too wide");
    }

    /**
     * @param maxLength largest array the caller is willing to allocate; bounds the allocation a
     *                  hostile length prefix can request
     */
    public byte[] bytes(int maxLength) {
        int length = varInt();
        if (length < 0 || length > maxLength) {
            throw new MalformedFrameException("byte array length " + length + " exceeds " + maxLength);
        }
        require(length);
        byte[] result = new byte[length];
        System.arraycopy(data, cursor, result, 0, length);
        cursor += length;
        return result;
    }

    /** Reads a byte array of an exact length — used for keys, nonces and signatures. */
    public byte[] fixedBytes(int exactLength) {
        byte[] result = bytes(exactLength);
        if (result.length != exactLength) {
            throw new MalformedFrameException("expected " + exactLength + " bytes, got " + result.length);
        }
        return result;
    }

    public String string(int maxBytes) {
        return new String(bytes(maxBytes), StandardCharsets.UTF_8);
    }

    public UUID uuid() {
        return new UUID(readLong(), readLong());
    }

    private long readLong() {
        require(8);
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (data[cursor++] & 0xFFL);
        }
        return value;
    }

    private void require(int count) {
        if (cursor + count > data.length) {
            throw new MalformedFrameException("frame truncated");
        }
    }
}
