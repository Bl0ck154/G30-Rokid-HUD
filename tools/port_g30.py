from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if old not in text:
        raise RuntimeError(f"Patch anchor not found for {label}: {path}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def write_if_changed(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return
    path.write_text(content, encoding="utf-8")


NINEBOT_CRYPTO = r'''package com.m365bleapp.ble;

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
'''


SHU_PROTOCOL = r'''package com.m365bleapp.ble;

import java.util.Arrays;

/** Packet shapes used by ScooterHacking Utility 2.7 for classic Ninebot G30 BLE. */
public final class ShuNinebotProtocol {
    private ShuNinebotProtocol() {}

    public static final int SOURCE_PHONE = 0x3E;
    public static final int TARGET_ESC = 0x20;
    public static final int TARGET_BLE = 0x21;

    public static final int CMD_READ_REGISTER = 0x01;
    public static final int CMD_WRITE_REGISTER = 0x02;
    public static final int CMD_INIT = 0x5B;
    public static final int CMD_PING = 0x5C;
    public static final int CMD_PAIR = 0x5D;

    public static final byte[] SHU_APP_KEY = hex("4AEEBD73E2161C112D065A49CC6E8BB7");

    public static byte[] initPacket() {
        return wrapCryptoPlain(new byte[]{(byte) SOURCE_PHONE, (byte) TARGET_BLE, (byte) CMD_INIT, 0x00});
    }

    public static byte[] pingPacket() {
        byte[] command = new byte[20];
        command[0] = (byte) SOURCE_PHONE;
        command[1] = (byte) TARGET_BLE;
        command[2] = (byte) CMD_PING;
        command[3] = 0x00;
        System.arraycopy(SHU_APP_KEY, 0, command, 4, 16);
        return wrapCryptoPlain(command);
    }

    public static byte[] pairPacket(byte[] serial) {
        if (serial == null || serial.length < 14) throw new IllegalArgumentException("Pairing requires 14-byte serial");
        byte[] command = new byte[18];
        command[0] = (byte) SOURCE_PHONE;
        command[1] = (byte) TARGET_BLE;
        command[2] = (byte) CMD_PAIR;
        command[3] = 0x00;
        System.arraycopy(serial, 0, command, 4, 14);
        return wrapCryptoPlain(command);
    }

    public static byte[] readRegisterPacket(int register, int length) {
        return wrapCryptoPlain(new byte[]{
                (byte) SOURCE_PHONE, (byte) TARGET_ESC, (byte) CMD_READ_REGISTER,
                (byte) register, (byte) length
        });
    }

    public static byte[] writeRegisterPacket(int register, byte[] payload) {
        byte[] data = payload == null ? new byte[0] : payload;
        byte[] command = new byte[4 + data.length];
        command[0] = (byte) SOURCE_PHONE;
        command[1] = (byte) TARGET_ESC;
        command[2] = (byte) CMD_WRITE_REGISTER;
        command[3] = (byte) register;
        System.arraycopy(data, 0, command, 4, data.length);
        return wrapCryptoPlain(command);
    }

    public static byte[] wrapCryptoPlain(byte[] command) {
        if (command == null || command.length < 4) throw new IllegalArgumentException("Ninebot command too short");
        byte[] out = new byte[command.length + 3];
        out[0] = 0x5A;
        out[1] = (byte) 0xA5;
        out[2] = (byte) (command.length - 4);
        System.arraycopy(command, 0, out, 3, command.length);
        return out;
    }

    public static boolean isPacket(byte[] packet) {
        if (packet == null || packet.length < 7) return false;
        if ((packet[0] & 0xFF) != 0x5A || (packet[1] & 0xFF) != 0xA5) return false;
        int dataLength = packet[2] & 0xFF;
        return packet.length >= 7 + dataLength;
    }

    public static int command(byte[] packet) { return isPacket(packet) ? packet[5] & 0xFF : -1; }
    public static int index(byte[] packet) { return isPacket(packet) ? packet[6] & 0xFF : -1; }

    public static byte[] payload(byte[] packet) {
        if (!isPacket(packet)) return new byte[0];
        int len = packet[2] & 0xFF;
        return Arrays.copyOfRange(packet, 7, 7 + len);
    }

    public static int encryptedPacketLengthFromHeader(byte[] data) {
        if (data == null || data.length < 3) return -1;
        return (data[2] & 0xFF) + 13;
    }

    private static byte[] hex(String value) {
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
}
'''


G30_SESSION = r'''package com.m365bleapp.ble

import android.bluetooth.BluetoothGatt
import android.os.SystemClock
import android.util.Log
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import java.io.ByteArrayOutputStream
import java.util.UUID

/**
 * Classic Ninebot G30 BLE session using the SHU 2.7 handshake/crypto path.
 * This intentionally avoids Xiaomi FE95 registration/token auth.
 */
class G30ShuSession(
    private val bleManager: BleManager,
    private val gatt: BluetoothGatt,
    private val uartService: UUID,
    private val uartWrite: UUID,
    private val incoming: Channel<ByteArray>,
    deviceName: String?
) {
    private val crypto = NinebotCrypto(deviceName)
    private val commandMutex = Mutex()
    @Volatile var authenticated: Boolean = false
        private set

    suspend fun authenticate(onPowerButtonRequired: () -> Unit) = commandMutex.withLock {
        drainIncoming()

        var initResponse: ByteArray? = null
        repeat(15) {
            if (initResponse != null) return@repeat
            sendPlain(ShuNinebotProtocol.initPacket())
            val packet = readPlainFrame(900)
            if (packet != null && ShuNinebotProtocol.command(packet) == ShuNinebotProtocol.CMD_INIT) {
                initResponse = packet
            }
        }

        val init = initResponse ?: throw IllegalStateException("Ninebot G30 authentication: INIT timeout")
        val initPayload = ShuNinebotProtocol.payload(init)
        if (initPayload.size < 30) throw IllegalStateException("Ninebot G30 authentication: invalid INIT response")
        val serial = initPayload.copyOfRange(16, 30)

        var pingAccepted = false
        var paired = false
        var firstPairTriggerSent = false
        var powerPromptShown = false

        repeat(55) {
            if (paired) return@repeat

            if (!pingAccepted) {
                sendPlain(ShuNinebotProtocol.pingPacket())
                if (!firstPairTriggerSent) {
                    firstPairTriggerSent = true
                    delay(500)
                    sendPlain(ShuNinebotProtocol.pairPacket(serial))
                }
            } else {
                sendPlain(ShuNinebotProtocol.pairPacket(serial))
            }

            repeat(3) { responseIndex ->
                if (paired) return@repeat
                val packet = readPlainFrame(if (responseIndex == 0) 550 else 120) ?: return@repeat
                when (ShuNinebotProtocol.command(packet)) {
                    ShuNinebotProtocol.CMD_PING -> {
                        when (ShuNinebotProtocol.index(packet)) {
                            0 -> if (!powerPromptShown) {
                                powerPromptShown = true
                                onPowerButtonRequired()
                            }
                            1 -> pingAccepted = true
                        }
                    }
                    ShuNinebotProtocol.CMD_PAIR -> {
                        if (ShuNinebotProtocol.index(packet) == 1) paired = true
                    }
                }
            }
        }

        if (!paired) throw IllegalStateException("Ninebot G30 authentication timeout. Press POWER once when requested.")
        authenticated = true
        Log.i("G30ShuSession", "SHU authentication complete")
    }

    suspend fun readRegister(register: Int, length: Int, timeoutMs: Long = 1800): ByteArray? = commandMutex.withLock {
        if (!authenticated) return@withLock null
        sendPlain(ShuNinebotProtocol.readRegisterPacket(register, length))
        awaitRegister(register, timeoutMs)
    }

    suspend fun writeRegister(register: Int, payload: ByteArray): ByteArray? = commandMutex.withLock {
        if (!authenticated) return@withLock null
        sendPlain(ShuNinebotProtocol.writeRegisterPacket(register, payload))
        awaitRegister(register, 800)
    }

    private suspend fun awaitRegister(register: Int, timeoutMs: Long): ByteArray? {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        while (true) {
            val remaining = deadline - SystemClock.elapsedRealtime()
            if (remaining <= 0) return null
            val packet = readPlainFrame(remaining) ?: return null
            if (ShuNinebotProtocol.isPacket(packet) && ShuNinebotProtocol.index(packet) == register) return packet
        }
    }

    private suspend fun sendPlain(plain: ByteArray) {
        val encrypted = crypto.encrypt(plain)
        for (offset in encrypted.indices step 20) {
            val end = (offset + 20).coerceAtMost(encrypted.size)
            val chunk = encrypted.copyOfRange(offset, end)
            val ok = bleManager.write(gatt, uartService, uartWrite, chunk, true)
            if (!ok) throw IllegalStateException("Ninebot G30 Bluetooth write failed")
            delay(5)
        }
    }

    private suspend fun readPlainFrame(timeoutMs: Long): ByteArray? = withTimeoutOrNull(timeoutMs) {
        while (true) {
            val first = incoming.receive()
            if (first.size < 3 || (first[0].toInt() and 0xFF) != 0x5A || (first[1].toInt() and 0xFF) != 0xA5) {
                continue
            }

            val expected = ShuNinebotProtocol.encryptedPacketLengthFromHeader(first)
            if (expected < 13) continue

            val buffer = ByteArrayOutputStream()
            buffer.write(first, 0, first.size)
            while (buffer.size() < expected) {
                val next = incoming.receive()
                buffer.write(next, 0, next.size)
            }

            val raw = buffer.toByteArray().copyOfRange(0, expected)
            try {
                return@withTimeoutOrNull crypto.decrypt(raw)
            } catch (e: Exception) {
                Log.w("G30ShuSession", "Failed to decrypt frame: ${e.message}")
            }
        }
        @Suppress("UNREACHABLE_CODE")
        null
    }

    private fun drainIncoming() {
        while (incoming.tryReceive().isSuccess) { }
    }
}
'''


write_if_changed(ROOT / "app/src/main/java/com/m365bleapp/ble/NinebotCrypto.java", NINEBOT_CRYPTO)
write_if_changed(ROOT / "app/src/main/java/com/m365bleapp/ble/ShuNinebotProtocol.java", SHU_PROTOCOL)
write_if_changed(ROOT / "app/src/main/java/com/m365bleapp/ble/G30ShuSession.kt", G30_SESSION)

# G30 writes need the same Write With Response behavior as the known-good blocker.
ble = ROOT / "app/src/main/java/com/m365bleapp/ble/BleManager.kt"
replace_once(
    ble,
    '        char.writeType = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE\n',
    '        char.writeType = if (waitForResponse) {\n            BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT\n        } else {\n            BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE\n        }\n',
    "BLE write type"
)

# Recognize classic Ninebot/Segway G30 advertising in addition to Xiaomi MIScooter/FE95.
scan = ROOT / "app/src/main/java/com/m365bleapp/ui/ScanScreen.kt"
replace_once(
    scan,
    '        private const val XIAOMI_SCOOTER_NAME_PREFIX = "MIScooter"\n',
    '        private const val XIAOMI_SCOOTER_NAME_PREFIX = "MIScooter"\n        private val NINEBOT_UART_SERVICE_UUID = android.os.ParcelUuid.fromString("6e400001-b5a3-f393-e0a9-e50e24dcca9e")\n',
    "G30 scan UUID"
)
replace_once(
    scan,
    '''            // Check if name starts with MIScooter\n            if (name?.startsWith(XIAOMI_SCOOTER_NAME_PREFIX) == true) return true\n            // Check if device advertises Xiaomi service UUID\n            val serviceUuids = scanResult.scanRecord?.serviceUuids\n            return serviceUuids?.contains(XIAOMI_SERVICE_UUID) == true\n''',
    '''            // Xiaomi M365 naming\n            if (name?.startsWith(XIAOMI_SCOOTER_NAME_PREFIX) == true) return true\n\n            // Classic Ninebot/Segway naming used by G30 BLE firmware.\n            val normalizedName = name?.lowercase().orEmpty()\n            if (normalizedName.contains("nbscooter") ||\n                normalizedName.contains("ninebot") ||\n                normalizedName.contains("segway")) return true\n\n            // Service UUID fallback: Xiaomi FE95 or Nordic UART used by Ninebot G30.\n            val serviceUuids = scanResult.scanRecord?.serviceUuids\n            return serviceUuids?.contains(XIAOMI_SERVICE_UUID) == true ||\n                serviceUuids?.contains(NINEBOT_UART_SERVICE_UUID) == true\n''',
    "G30 scan classification"
)
replace_once(
    scan,
    '                    repository.connect(deviceToConnect.scanResult.device.address, register)\n',
    '                    repository.connect(deviceToConnect.scanResult.device.address, register, deviceToConnect.name)\n',
    "pass advertised G30 name"
)

repo = ROOT / "app/src/main/java/com/m365bleapp/repository/ScooterRepository.kt"
replace_once(
    repo,
    'import com.m365bleapp.ble.BleManager\n',
    'import com.m365bleapp.ble.BleManager\nimport com.m365bleapp.ble.G30ShuSession\nimport com.m365bleapp.ble.ShuNinebotProtocol\n',
    "G30 imports"
)
replace_once(
    repo,
    '    private var sessionPtr: Long = 0\n',
    '    private var sessionPtr: Long = 0\n    private var g30Session: G30ShuSession? = null\n',
    "G30 session field"
)
replace_once(
    repo,
    '    fun connect(mac: String, register: Boolean = false) {\n',
    '    fun connect(mac: String, register: Boolean = false, preferredDeviceName: String? = null) {\n',
    "connect signature"
)
replace_once(
    repo,
    '                // Clear old data from channels\n                while(controlChannel.tryReceive().isSuccess) {}\n',
    '                // Clear old transport/session state and buffered data.\n                g30Session = null\n                while(controlChannel.tryReceive().isSuccess) {}\n',
    "reset G30 transport"
)
replace_once(
    repo,
    '''                gatt.requestMtu(512)\n                delay(200)\n\n                // Enable Notifications on Handshake chars\n''',
    '''                gatt.requestMtu(512)\n                delay(200)\n\n                // Classic G30 uses Ninebot UART + SHU crypto, not Xiaomi FE95 token auth.\n                val resolvedDeviceName = preferredDeviceName ?: runCatching { gatt.device.name }.getOrNull()\n                val normalizedDeviceName = resolvedDeviceName?.lowercase().orEmpty()\n                val hasUart = gatt.getService(UART_SERVICE) != null\n                val hasMiAuth = gatt.getService(AUTH_SERVICE) != null\n                val looksLikeG30 = normalizedDeviceName.contains("nbscooter") ||\n                    normalizedDeviceName.contains("ninebot") ||\n                    normalizedDeviceName.contains("segway")\n                val useG30Shu = hasUart && (looksLikeG30 || !hasMiAuth)\n\n                if (useG30Shu) {\n                    Log.i("ScooterRepo", "Using Ninebot G30 SHU authentication for $resolvedDeviceName")\n                    _connectionState.value = ConnectionState.Handshaking("Authenticating Ninebot G30…")\n                    val uartOk = bleManager.enableNotifications(gatt, UART_SERVICE, UART_RX) { }\n                    if (!uartOk) throw Exception("Could not enable Ninebot G30 UART notifications")\n\n                    val session = G30ShuSession(\n                        bleManager = bleManager,\n                        gatt = gatt,\n                        uartService = UART_SERVICE,\n                        uartWrite = UART_TX,\n                        incoming = uartRxChannel,\n                        deviceName = resolvedDeviceName\n                    )\n                    g30Session = session\n                    session.authenticate {\n                        _connectionState.value = ConnectionState.Handshaking(getString(R.string.state_press_power_button))\n                    }\n\n                    _connectionState.value = ConnectionState.Ready\n                    delay(300)\n                    readInitialStates()\n                    startTelemetryLoop()\n                    return@launch\n                }\n\n                // Xiaomi/M365 FE95 authentication path.\n                // Enable Notifications on Handshake chars\n''',
    "G30 connect/auth branch"
)
replace_once(
    repo,
    '    private suspend fun startTelemetryLoop() {\n        logger.startSession()\n',
    '    private suspend fun startTelemetryLoop() {\n        val activeG30 = g30Session\n        if (activeG30 != null) {\n            startG30TelemetryLoop(activeG30)\n            return\n        }\n\n        logger.startSession()\n',
    "G30 telemetry branch"
)

G30_TELEMETRY = r'''    private suspend fun startG30TelemetryLoop(session: G30ShuSession) {
        logger.startSession()
        Log.i("ScooterRepo", "Starting G30 SHU telemetry loop")
        var tick = 0
        var lastTripQueryTick = 0
        var lastRangeQueryTick = 0
        var lastSpeed = 0.0
        var consecutiveFailures = 0

        while (currentCoroutineContext().isActive && activeGatt != null && g30Session === session) {
            try {
                val (attribute, length) = when {
                    tick - lastTripQueryTick >= TRIP_QUERY_INTERVAL_TICKS -> {
                        lastTripQueryTick = tick
                        0x3A to 0x04
                    }
                    tick - lastRangeQueryTick >= RANGE_QUERY_INTERVAL_TICKS -> {
                        lastRangeQueryTick = tick
                        0x25 to 0x02
                    }
                    else -> 0xB0 to 0x20
                }

                val response = session.readRegister(attribute, length)
                if (response != null) {
                    parseG30Packet(response)
                    consecutiveFailures = 0
                    _motorInfo.value?.let { lastSpeed = it.speed }
                } else {
                    consecutiveFailures++
                    Log.w("ScooterRepo", "G30 query 0x${attribute.toString(16)} timed out ($consecutiveFailures)")
                }

                if (consecutiveFailures >= 10) {
                    _connectionState.value = ConnectionState.Error(getString(R.string.connection_lost))
                    break
                }
                tick++
            } catch (e: Exception) {
                consecutiveFailures++
                Log.w("ScooterRepo", "G30 telemetry error: ${e.message}")
                if (consecutiveFailures >= 10) {
                    _connectionState.value = ConnectionState.Error(getString(R.string.connection_lost))
                    break
                }
            }

            delay(if (lastSpeed > SPEED_THRESHOLD_KMH) POLL_INTERVAL_MOVING_MS else POLL_INTERVAL_IDLE_MS)
        }
    }

    private fun parseG30Packet(packet: ByteArray) {
        if (!ShuNinebotProtocol.isPacket(packet)) return
        val attr = ShuNinebotProtocol.index(packet)
        val data = ShuNinebotProtocol.payload(packet)
        Log.d("ScooterRepo", "G30 response attr=0x${attr.toString(16)} data=${data.toHex()}")
        when (attr) {
            0xB0 -> parseMotorInfoFromData(data)
            0x3A -> parseTripInfo(data)
            0x25 -> parseRemainingKm(data)
            0xB5 -> parseSpeedFromData(data)
            0x7D -> parseTailLightState(data)
            0x7C -> parseCruiseState(data)
        }
    }

'''
replace_once(
    repo,
    '    private fun buildPacket(dest: Byte, rw: Byte, attr: Byte, payload: ByteArray): ByteArray {\n',
    G30_TELEMETRY + '    private fun buildPacket(dest: Byte, rw: Byte, attr: Byte, payload: ByteArray): ByteArray {\n',
    "G30 telemetry implementation"
)

# Existing public controls already construct register/attribute packets. Keep that API and
# translate those compact packets into SHU frames when the G30 transport is active.
replace_once(
    repo,
    '''    private suspend fun sendCommand(packet: ByteArray, commandName: String = "Command") {\n        val counter = 0L  // Always use counter=0 (scooter doesn't track)\n        val encrypted = native.encrypt(sessionPtr, packet, counter)\n        Log.d("ScooterRepo", "Command Encrypted (${encrypted.size} bytes): ${encrypted.toHex()}")\n        \n        // Log the command to CSV\n        logger.logCommand(commandName, packet)\n        logger.logUartTx(encrypted, "$commandName (encrypted)")\n        \n        writeUartEncrypted(encrypted)\n    }\n''',
    '''    private suspend fun sendCommand(packet: ByteArray, commandName: String = "Command") {\n        logger.logCommand(commandName, packet)\n\n        val g30 = g30Session\n        if (g30 != null) {\n            if (packet.size < 4) throw IllegalArgumentException("Invalid G30 command packet")\n            val rw = packet[2].toInt() and 0xFF\n            val attr = packet[3].toInt() and 0xFF\n            val payload = if (packet.size > 4) packet.copyOfRange(4, packet.size) else ByteArray(0)\n\n            if (rw == 0x01) {\n                val length = payload.firstOrNull()?.toInt()?.and(0xFF) ?: 1\n                val response = g30.readRegister(attr, length)\n                if (response != null) parseG30Packet(response)\n            } else {\n                // SHU's G30 lock/unlock registers use a single 0x01 value.\n                val g30Payload = if ((attr == 0x70 || attr == 0x71) && payload.isNotEmpty()) {\n                    byteArrayOf(payload[0])\n                } else payload\n                g30.writeRegister(attr, g30Payload)\n            }\n            return\n        }\n\n        val counter = 0L  // Xiaomi/M365 session transport\n        val encrypted = native.encrypt(sessionPtr, packet, counter)\n        Log.d("ScooterRepo", "Command Encrypted (${encrypted.size} bytes): ${encrypted.toHex()}")\n        logger.logUartTx(encrypted, "$commandName (encrypted)")\n        writeUartEncrypted(encrypted)\n    }\n''',
    "G30 command translation"
)

# All existing controls consider either the Mi session pointer OR the G30 SHU session valid.
text = repo.read_text(encoding="utf-8")
text = text.replace('if (sessionPtr == 0L) {', 'if (sessionPtr == 0L && g30Session == null) {')
repo.write_text(text, encoding="utf-8")

replace_once(
    repo,
    '                activeGatt = null\n                if (sessionPtr != 0L) {\n',
    '                activeGatt = null\n                g30Session = null\n                if (sessionPtr != 0L) {\n',
    "G30 unexpected disconnect cleanup"
)
replace_once(
    repo,
    '        activeGatt = null\n        _connectionState.value = ConnectionState.Disconnected\n',
    '        activeGatt = null\n        g30Session = null\n        _connectionState.value = ConnectionState.Disconnected\n',
    "G30 disconnect cleanup"
)

# Fork versioning: upstream 1.3 + first G30 compatibility patch.
gradle = ROOT / "app/build.gradle.kts"
replace_once(gradle, '        versionCode = 5\n', '        versionCode = 6\n', "versionCode")
replace_once(gradle, '        versionName = "1.3"\n', '        versionName = "1.3.1-g30.1"\n', "versionName")

print("G30 SHU compatibility patch applied")
