package network.columba.app.rns.backend.kt

import java.io.FilterInputStream
import java.io.InputStream
import java.util.concurrent.ConcurrentHashMap

// KISS framing + the battery status command, mirroring upstream firmware
// values (markqvist RNode_Firmware Framing.h: CMD_STAT_BAT).
private const val FEND = 0xC0
private const val FESC = 0xDB
private const val TFEND = 0xDC
private const val TFESC = 0xDD
private const val CMD_STAT_BAT = 0x27

/** Longest payload we are willing to buffer for a sniffed frame. */
private const val MAX_SNIFF_PAYLOAD = 16

/**
 * RNode battery readings sniffed from the KISS RX stream, keyed by interface
 * name (the configured [network.columba.app.rns.api.model.InterfaceConfig.RNode.name],
 * same key the UI's per-interface battery maps use).
 *
 * reticulum-kt's RNodeInterface consumes CMD_STAT_BAT control frames
 * internally (or ignores them, depending on version) — they never surface
 * through `onPacketReceived`. The only in-repo observation point is the raw
 * serial stream handed to the interface, so [tap] wraps that stream with a
 * non-owning tee that feeds a tiny frame sniffer and otherwise delegates
 * byte-for-byte unchanged.
 *
 * Wire format (markqvist RNode_Firmware, Utilities.h kiss_indicate_battery):
 * a CMD_STAT_BAT payload starts with `[state, percent]` where state is
 * 0=unknown/1=discharging/2=charging/3=charged and percent is 0-100. Firmware
 * builds may append extra payload bytes (e.g. voltage); the sniffer reads the
 * conventional second byte and ignores the rest.
 */
internal object RNodeBatteryStore {
    private val readings = ConcurrentHashMap<String, Int>()

    /** Last reported percent for [name], or null when no frame arrived yet. */
    fun get(name: String): Int? = readings[name]

    /** Drop the cached reading (interface stopped or went offline). */
    fun clear(name: String) {
        readings.remove(name)
    }

    /** Drop all cached readings (backend shutdown). */
    fun clearAll() {
        readings.clear()
    }

    /**
     * Wrap [input] with a tee that sniffs CMD_STAT_BAT frames destined for
     * the interface named [name]. Reads delegate unchanged; only the battery
     * percent is captured as a side effect.
     */
    fun tap(
        name: String,
        input: InputStream,
    ): InputStream {
        val sniffer = BatteryFrameSniffer { percent -> readings[name] = percent }
        return object : FilterInputStream(input) {
            override fun read(): Int {
                val b = super.read()
                if (b >= 0) sniffer.offer(b)
                return b
            }

            override fun read(
                b: ByteArray,
                off: Int,
                len: Int,
            ): Int {
                val n = super.read(b, off, len)
                if (n > 0) {
                    for (i in 0 until n) {
                        sniffer.offer(b[off + i].toInt() and 0xFF)
                    }
                }
                return n
            }
        }
    }
}

/**
 * Byte-at-a-time KISS frame watcher for one stream. Feeds only battery
 * frames to [onPercent]; every other frame (including oversized or
 * malformed ones) is discarded silently so the wrapped consumer is never
 * affected.
 */
private class BatteryFrameSniffer(private val onPercent: (Int) -> Unit) {
    private var inFrame = false
    private var escape = false
    private var command = -1
    private var payload = ByteArray(0)
    private var overflow = false

    fun offer(b: Int) {
        when {
            b == FEND -> { // frame boundary
                if (inFrame && !overflow) deliver()
                inFrame = true
                escape = false
                command = -1
                payload = ByteArray(0)
                overflow = false
            }
            !inFrame -> Unit // noise between frames
            else -> offerPayloadByte(b)
        }
    }

    private fun offerPayloadByte(b: Int) {
        when {
            escape -> {
                escape = false
                when (b) {
                    TFEND -> push(FEND)
                    TFESC -> push(FESC)
                    else -> push(b) // invalid escape; pass through like stock parsers
                }
            }
            b == FESC -> escape = true
            command < 0 -> command = b
            else -> push(b)
        }
    }

    private fun push(byte: Int) {
        if (payload.size >= MAX_SNIFF_PAYLOAD) {
            overflow = true
            return
        }
        payload += byte.toByte()
    }

    private fun deliver() {
        if (command != CMD_STAT_BAT || payload.isEmpty()) return
        // [state, percent, ...]: the percent sits at index 1; a lone byte is
        // read as percent-only (older firmware convention).
        val percent = if (payload.size >= 2) payload[1].toInt() and 0xFF else payload[0].toInt() and 0xFF
        if (percent in 0..100) {
            onPercent(percent)
        }
    }
}
