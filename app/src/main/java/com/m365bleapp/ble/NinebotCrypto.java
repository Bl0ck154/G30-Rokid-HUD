package com.m365bleapp.ble;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * ScooterHacking Utility 2.7 compatible Ninebot transport crypto.
 * Ported from the known-good Ninebot-scooter-blocker implementation.
 */
public final class NinebotCrypto {
    private static final byte[] FW_DATA = hex("97CFB802844143DE56002B3B34780A5D");

    private final byte[] fwData = Arrays.copyOf(FW_DATA, 16);
    private final byte[] bleData = new byte[16];
    private final byte[] appData = new byte[16];
    private final byte[] shaKey = new byte[16];
    private final byte[] name;
    private int counter;

    public NinebotCrypto(String deviceName) {
        String n = (deviceName == null || deviceName.isBlank()) ? "NBScooter2020" : deviceName;
        name = n.getBytes(StandardCharsets.UTF_8);
        deriveKey(name, fwData);
    }

    public byte[] encrypt(byte[] plainPacket) {
        if (plainPacket == null || plainPacket.length < 7) {
            throw new IllegalArgumentException("Invalid Ninebot plaintext packet");
        }

        byte[] payload = Arrays.copyOfRange(plainPacket, 3, plainPacket.length);
        byte[] temp = new byte[plainPacket.length + 6];
        System.arraycopy(plainPacket, 0, temp, 0, 3);

        if (counter == 0) {
            byte[] crc = crcFirst(payload);
            byte[] encrypted = cryptoFirst(payload);
            System.arraycopy(encrypted, 0, temp, 3, encrypted.length);

            int end = plainPacket.length;
            temp[end] = 0;
            temp[end + 1] = 0;
            temp[end + 2] = crc[0];
            temp[end + 3] = crc[1];
            temp[end + 4] = 0;
            temp[end + 5] = 0;
            counter = counter + 1;
        } else {
            counter = counter + 1;
            byte[] crc = crcNext(plainPacket, counter);
            byte[] encrypted = cryptoNext(payload, counter);
            System.arraycopy(encrypted, 0, temp, 3, encrypted.length);

            int end = plainPacket.length;
            System.arraycopy(crc, 0, temp, end, 4);
            temp[end + 4] = (byte) ((counter & 0xFF00) >>> 8);
            temp[end + 5] = (byte) (counter & 0xFF);
        }

        byte[] out = Arrays.copyOf(temp, plainPacket.length + 6);

        if (plainPacket.length >= 23
                && (plainPacket[0] & 0xFF) == 0x5A
                && (plainPacket[1] & 0xFF) == 0xA5
                && (plainPacket[2] & 0xFF) == 0x10
                && (plainPacket[3] & 0xFF) == 0x3E
                && (plainPacket[4] & 0xFF) == 0x21
                && (plainPacket[5] & 0xFF) == 0x5C
                && (plainPacket[6] & 0xFF) == 0x00) {
            System.arraycopy(plainPacket, 7, appData, 0, 16);
        }

        return out;
    }

    public byte[] decrypt(byte[] encryptedPacket) {
        if (encryptedPacket == null || encryptedPacket.length < 13) {
            throw new IllegalArgumentException("Encrypted Ninebot packet too short");
        }

        byte[] result = new byte[encryptedPacket.length - 6];
        System.arraycopy(encryptedPacket, 0, result, 0, 3);

        int receivedCounter = (counter & 0xFFFF0000)
                + (((encryptedPacket[encryptedPacket.length - 2] & 0xFF) << 8)
                | (encryptedPacket[encryptedPacket.length - 1] & 0xFF));

        int payloadLength = encryptedPacket.length - 9;
        byte[] encryptedPayload = new byte[payloadLength];
        System.arraycopy(encryptedPacket, 3, encryptedPayload, 0, payloadLength);

        byte[] decrypted = receivedCounter == 0
                ? cryptoFirst(encryptedPayload)
                : cryptoNext(encryptedPayload, receivedCounter);
        System.arraycopy(decrypted, 0, result, 3, decrypted.length);

        if (startsWith(result, new int[]{0x5A, 0xA5, 0x1E, 0x21, 0x3E, 0x5B})
                && result.length >= 23) {
            System.arraycopy(result, 7, bleData, 0, 16);
            deriveKey(name, bleData);
            return result;
        }

        if (startsWith(result, new int[]{0x5A, 0xA5, 0x00, 0x21, 0x3E, 0x5C, 0x01})) {
            deriveKey(appData, bleData);
        }

        if (Integer.compare(counter, receivedCounter) > 0) {
            counter = receivedCounter;
        } else {
            counter = counter + 1;
        }

        return result;
    }

    private byte[] cryptoFirst(byte[] data) {
        byte[] out = new byte[data.length];
        byte[] keyStream = aesEcbFirstBlock(fwData, shaKey);
        for (int offset = 0; offset < data.length; offset += 16) {
            int n = Math.min(16, data.length - offset);
            for (int i = 0; i < n; i++) out[offset + i] = (byte) (data[offset + i] ^ keyStream[i]);
        }
        return out;
    }

    private byte[] cryptoNext(byte[] data, int messageCounter) {
        byte[] out = new byte[data.length];
        byte[] ctr = counterBlock(messageCounter);
        ctr[15] = 0;
        int remaining = data.length;
        int offset = 0;
        while (remaining > 0) {
            ctr[15] = (byte) (ctr[15] + 1);
            int n = Math.min(16, remaining);
            byte[] keyStream = aesEcbFirstBlock(ctr, shaKey);
            for (int i = 0; i < n; i++) out[offset + i] = (byte) (data[offset + i] ^ keyStream[i]);
            remaining -= n;
            offset += n;
        }
        return out;
    }

    private static byte[] crcFirst(byte[] data) {
        long sum = 0;
        for (byte b : data) sum += b;
        long crc = ~sum;
        return new byte[]{(byte) (crc & 0xFF), (byte) ((crc >> 8) & 0xFF)};
    }

    private byte[] crcNext(byte[] plainPacket, int messageCounter) {
        byte[] state = counterBlock(messageCounter);
        int remaining = plainPacket.length - 3;
        state[0] = 0x59;
        state[15] = (byte) remaining;
        byte[] chain = aesEcbFirstBlock(state, shaKey);

        byte[] block = new byte[16];
        System.arraycopy(plainPacket, 0, block, 0, Math.min(3, plainPacket.length));
        chain = aesEcbFirstBlock(xor16(block, chain), shaKey);

        int offset = 3;
        while (remaining > 0) {
            int n = Math.min(16, remaining);
            block = new byte[16];
            System.arraycopy(plainPacket, offset, block, 0, n);
            chain = aesEcbFirstBlock(xor16(block, chain), shaKey);
            remaining -= n;
            offset += n;
        }

        state[0] = 0x01;
        state[15] = 0;
        byte[] tail = aesEcbFirstBlock(state, shaKey);
        return new byte[]{
                (byte) (tail[0] ^ chain[0]),
                (byte) (tail[1] ^ chain[1]),
                (byte) (tail[2] ^ chain[2]),
                (byte) (tail[3] ^ chain[3])
        };
    }

    private byte[] counterBlock(int messageCounter) {
        byte[] block = new byte[16];
        block[0] = 0x01;
        block[1] = (byte) ((messageCounter >>> 24) & 0xFF);
        block[2] = (byte) ((messageCounter >>> 16) & 0xFF);
        block[3] = (byte) ((messageCounter >>> 8) & 0xFF);
        block[4] = (byte) (messageCounter & 0xFF);
        System.arraycopy(bleData, 0, block, 5, 8);
        return block;
    }

    private void deriveKey(byte[] first, byte[] second) {
        try {
            byte[] input = new byte[32];
            if (first != null) System.arraycopy(first, 0, input, 0, Math.min(first.length, input.length));
            if (second != null) System.arraycopy(second, 0, input, 16, Math.min(16, second.length));
            byte[] digest = MessageDigest.getInstance("SHA-1").digest(input);
            System.arraycopy(digest, 0, shaKey, 0, 16);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-1 unavailable", e);
        }
    }

    private static byte[] aesEcbFirstBlock(byte[] block, byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            return cipher.doFinal(Arrays.copyOf(block, 16));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES unavailable", e);
        }
    }

    private static byte[] xor16(byte[] a, byte[] b) {
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) out[i] = (byte) (a[i] ^ b[i]);
        return out;
    }

    private static boolean startsWith(byte[] data, int[] prefix) {
        if (data == null || data.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) if ((data[i] & 0xFF) != prefix[i]) return false;
        return true;
    }

    private static byte[] hex(String value) {
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
}
