package org.francium.cybercoreMessageEncryption.client;

import net.minecraft.ChatFormatting;
import net.minecraft.client.Minecraft;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.Style;

/**
 * Renders private messages into the client's own chat. The server relays only ciphertext and never
 * sends any of this text, so every line here is built locally.
 * <p>
 * Direction is carried by colour alone: incoming lines are brighter than outgoing ones, so a
 * conversation reads as alternating shades with no prefix to scan past.
 */
public final class EncryptoChat {
    /** Incoming: arrow and colon in gray, the rest in light purple. */
    private static final Style INCOMING_PUNCTUATION = Style.EMPTY.withColor(ChatFormatting.GRAY);
    private static final Style INCOMING_TEXT = Style.EMPTY.withColor(ChatFormatting.LIGHT_PURPLE);

    /** Outgoing: the same shape one step darker. */
    private static final Style OUTGOING_PUNCTUATION = Style.EMPTY.withColor(ChatFormatting.DARK_GRAY);
    private static final Style OUTGOING_TEXT = Style.EMPTY.withColor(ChatFormatting.DARK_PURPLE);

    /** Marks the mod's own status lines so they are not mistaken for server chat. */
    private static final Style PREFIX = Style.EMPTY.withColor(ChatFormatting.DARK_GRAY);

    public static void outgoing(String targetName, String text) {
        addLine(Component.empty()
                .append(Component.translatable("cybercore.encrypto.chat.you").withStyle(OUTGOING_TEXT))
                .append(Component.literal(" → ").withStyle(OUTGOING_PUNCTUATION))
                .append(Component.literal(targetName).withStyle(OUTGOING_TEXT))
                .append(Component.literal(": ").withStyle(OUTGOING_PUNCTUATION))
                .append(Component.literal(text).withStyle(OUTGOING_TEXT)));
    }

    public static void incoming(String senderName, String text) {
        addLine(Component.empty()
                .append(Component.literal(senderName).withStyle(INCOMING_TEXT))
                .append(Component.literal(" → ").withStyle(INCOMING_PUNCTUATION))
                .append(Component.translatable("cybercore.encrypto.chat.you").withStyle(INCOMING_TEXT))
                .append(Component.literal(": ").withStyle(INCOMING_PUNCTUATION))
                .append(Component.literal(text).withStyle(INCOMING_TEXT)));
    }

    public static void info(Component message) {
        addLine(Component.empty()
                .append(Component.literal("[E] ").withStyle(PREFIX))
                .append(message.copy().withStyle(Style.EMPTY.withColor(ChatFormatting.GRAY))));
    }

    public static void error(Component message) {
        addLine(Component.empty()
                .append(Component.literal("[E] ").withStyle(PREFIX))
                .append(message.copy().withStyle(Style.EMPTY.withColor(ChatFormatting.RED))));
    }

    private static void addLine(Component line) {
        Minecraft.getInstance().gui.getChat().addClientSystemMessage(line);
    }

    private EncryptoChat() {
    }
}
