package network.columba.app.rns.backend.kt

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.InputStream

/**
 * Wire-format conformance for the KISS battery sniffer behind
 * [RNodeBatteryStore.tap].
 *
 * markqvist RNode firmware pushes CMD_STAT_BAT (0x27) unsolicited with a
 * payload starting `[state, percent]` (Utilities.h kiss_indicate_battery);
 * firmware builds may append extra bytes after the percent — RNode_HaLow
 * sends `[state, percent, V_hi, V_lo, percent]` with the voltage in 10 mV
 * units. Payload bytes equal to FEND/FESC must be KISS-escaped on the wire.
 *
 * The vectors below encode both shapes (escaped and plain) plus the
 * single-byte percent-only convention; if a test fails, re-derive against
 * the firmware sender before touching the sniffer.
 */
class RNodeBatteryStoreTest {
    private companion object {
        private const val FEND = 0xC0
        private const val FESC = 0xDB
        private const val TFESC = 0xDD
        private const val CMD_STAT_BAT = 0x27
        private const val CMD_DATA = 0x00
        private const val CMD_FW_VERSION = 0x50
    }

    /** Frame builder from Int bytes so vectors read like wire dumps. */
    private fun wire(vararg bytes: Int): ByteArray = ByteArray(bytes.size) { bytes[it].toByte() }

    @Before
    fun resetStore() {
        RNodeBatteryStore.clearAll()
    }

    private fun readAll(input: InputStream): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(3) // small on purpose: exercise chunked read()
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    @Test
    fun stockFirmwarePayloadYieldsPercent() {
        val bytes = wire(FEND, CMD_STAT_BAT, 0x01, 72, FEND)
        RNodeBatteryStore.tap("rnode", ByteArrayInputStream(bytes)).use { readAll(it) }
        assertEquals(72, RNodeBatteryStore.get("rnode"))
    }

    @Test
    fun extendedPayloadWithVoltageYieldsPercent() {
        // [state=1, percent=84, V=4.02 V as 0x01 0x8A (10 mV units), percent=84]
        val bytes = wire(FEND, CMD_STAT_BAT, 0x01, 84, 0x01, 0x8A, 84, FEND)
        RNodeBatteryStore.tap("rnode", ByteArrayInputStream(bytes)).use { readAll(it) }
        assertEquals(84, RNodeBatteryStore.get("rnode"))
    }

    @Test
    fun escapedPayloadByteIsUnescapedBeforeParsing() {
        // percent 0x64 (100), voltage dv=475=0x01DB: the 0xDB must arrive
        // escaped as FESC TFESC (0xDB 0xDD).
        val bytes = wire(FEND, CMD_STAT_BAT, 0x02, 0x64, 0x01, FESC, TFESC, 0x64, FEND)
        RNodeBatteryStore.tap("rnode", ByteArrayInputStream(bytes)).use { readAll(it) }
        assertEquals(100, RNodeBatteryStore.get("rnode"))
    }

    @Test
    fun loneBytePayloadIsPercentOnly() {
        val bytes = wire(FEND, CMD_STAT_BAT, 53, FEND)
        RNodeBatteryStore.tap("rnode", ByteArrayInputStream(bytes)).use { readAll(it) }
        assertEquals(53, RNodeBatteryStore.get("rnode"))
    }

    @Test
    fun outOfRangePercentIsIgnored() {
        val bytes = wire(FEND, CMD_STAT_BAT, 0x01, 150, FEND)
        RNodeBatteryStore.tap("rnode", ByteArrayInputStream(bytes)).use { readAll(it) }
        assertNull(RNodeBatteryStore.get("rnode"))
    }

    @Test
    fun dataAndOtherCommandsDoNotTouchReadings() {
        val bytes =
            wire(
                FEND, CMD_DATA, 0xDE, 0xAD, FEND,
                FEND, CMD_FW_VERSION, 0x01, 0x59, FEND,
            )
        RNodeBatteryStore.tap("rnode", ByteArrayInputStream(bytes)).use { readAll(it) }
        assertNull(RNodeBatteryStore.get("rnode"))
    }

    @Test
    fun garbageBetweenFramesResynchronizesOnFend() {
        val noise = wire(0x12, 0x34, 0x56)
        val frame = wire(FEND, CMD_STAT_BAT, 0x01, 47, FEND)
        RNodeBatteryStore.tap("rnode", ByteArrayInputStream(noise + frame)).use { readAll(it) }
        assertEquals(47, RNodeBatteryStore.get("rnode"))
    }

    @Test
    fun interfacesAreKeyedIndependently() {
        val frame = wire(FEND, CMD_STAT_BAT, 0x01, 61, FEND)
        RNodeBatteryStore.tap("a", ByteArrayInputStream(frame)).use { readAll(it) }
        RNodeBatteryStore.tap("b", ByteArrayInputStream(frame)).use { readAll(it) }
        RNodeBatteryStore.clear("a")
        assertNull(RNodeBatteryStore.get("a"))
        assertEquals(61, RNodeBatteryStore.get("b"))
    }

    @Test
    fun tapIsTransparentToTheWrappedStream() {
        val bytes =
            wire(
                FEND, CMD_STAT_BAT, 0x01, 72, 0x01, 0x8A, 72, FEND,
                FEND, CMD_DATA, 0x01, 0x02, 0x03, FEND,
                0x00, 0xFF, // trailing inter-frame noise
            )
        val viaTap = RNodeBatteryStore.tap("rnode", ByteArrayInputStream(bytes)).use { readAll(it) }
        assertArrayEquals(bytes, viaTap)
    }

    @Test
    fun singleByteReadsAlsoFeedTheSniffer() {
        val bytes = wire(FEND, CMD_STAT_BAT, 0x01, 39, FEND)
        RNodeBatteryStore.tap("rnode", ByteArrayInputStream(bytes)).use { input ->
            while (input.read() >= 0) {
                // drain byte-at-a-time
            }
        }
        assertEquals(39, RNodeBatteryStore.get("rnode"))
    }
}
