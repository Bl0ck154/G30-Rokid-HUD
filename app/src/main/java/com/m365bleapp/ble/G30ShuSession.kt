package com.m365bleapp.ble

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
