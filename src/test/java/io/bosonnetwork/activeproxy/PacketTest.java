package io.bosonnetwork.activeproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;

import io.vertx.core.buffer.Buffer;

import org.junit.jupiter.api.Test;

import io.bosonnetwork.CryptoContext;
import io.bosonnetwork.Id;
import io.bosonnetwork.crypto.CryptoBox;

/**
 * Unit tests for {@link Packet} framing/codec — header parsing, encode/decode round-trips, and the
 * malformed-input hardening (truncated/corrupted packets must surface {@link MalformedPacketException}
 * rather than an unchecked exception).
 */
class PacketTest {
	/**
	 * Builds a matched pair of {@link CryptoContext} so that {@code pair[0].encrypt(x)} can be
	 * decrypted by {@code pair[1].decrypt(...)} (and vice-versa), emulating the client/server session
	 * contexts.
	 */
	private static CryptoContext[] contextPair() {
		CryptoBox.KeyPair a = CryptoBox.KeyPair.random();
		CryptoBox.KeyPair b = CryptoBox.KeyPair.random();
		Id id = Id.random();
		CryptoContext ca = new CryptoContext(id, b.publicKey(), a.privateKey());
		CryptoContext cb = new CryptoContext(id, a.publicKey(), b.privateKey());
		return new CryptoContext[] { ca, cb };
	}

	@Test
	void getTypeRejectsTooShortPacket() {
		Buffer b = Buffer.buffer().appendByte((byte) 0x01); // 1 byte < HEADER_BYTES
		MalformedPacketException ex = assertThrows(MalformedPacketException.class, () -> Packet.getType(b));
		assertTrue(ex.getMessage().contains("too short"));
	}

	@Test
	void getTypeRejectsSizeMismatch() {
		Buffer b = Buffer.buffer();
		b.appendUnsignedShort(99);                 // declares 99 ...
		b.appendByte(PacketType.PING.value());
		b.appendByte((byte) 0);                    // ... but the actual length is 4
		MalformedPacketException ex = assertThrows(MalformedPacketException.class, () -> Packet.getType(b));
		assertTrue(ex.getMessage().contains("size mismatch"));
	}

	@Test
	void getTypeRejectsZeroDeclaredSize() {
		Buffer b = Buffer.buffer();
		b.appendUnsignedShort(0);                  // declared size 0 (the A3 framing hazard)
		b.appendByte((byte) 0);
		assertThrows(MalformedPacketException.class, () -> Packet.getType(b));
	}

	@Test
	void connectRoundTrip() throws Exception {
		CryptoContext[] ctx = contextPair();
		InetAddress addr = InetAddress.getByName("8.8.8.8");
		Buffer pkt = new Packet.Connect(addr, 443).encode(ctx[0]);

		assertEquals(PacketType.CONNECT, Packet.getType(pkt));
		Packet.Connect decoded = Packet.Connect.decode(pkt, ctx[1]);
		assertEquals(addr, decoded.address());
		assertEquals(443, decoded.port());
	}

	@Test
	void dataRoundTrip() throws Exception {
		CryptoContext[] ctx = contextPair();
		byte[] payload = "hello upstream".getBytes(StandardCharsets.UTF_8);
		Buffer pkt = new Packet.Data(payload).encode(ctx[0]);

		assertEquals(PacketType.DATA, Packet.getType(pkt));
		Packet.Data decoded = Packet.Data.decode(pkt, ctx[1]);
		assertArrayEquals(payload, decoded.data());
	}

	@Test
	void errorRoundTrip() throws Exception {
		CryptoContext[] ctx = contextPair();
		Buffer pkt = new Packet.Error((short) 42, "boom").encode(ctx[0]);

		assertEquals(PacketType.ERROR, Packet.getType(pkt));
		Packet.Error decoded = Packet.Error.decode(pkt, ctx[1]);
		assertEquals((short) 42, decoded.code());
		assertEquals("boom", decoded.message());
	}

	@Test
	void connectAckRoundTrip() throws Exception {
		assertTrue(Packet.ConnectAck.decode(Packet.ConnectAck.of(true).encode()).succeeded());
		assertFalse(Packet.ConnectAck.decode(Packet.ConnectAck.of(false).encode()).succeeded());
	}

	@Test
	void challengeRoundTrip() throws Exception {
		byte[] challenge = new byte[32];
		for (int i = 0; i < challenge.length; i++)
			challenge[i] = (byte) (i + 1);

		Packet.Challenge decoded = Packet.Challenge.decode(new Packet.Challenge(challenge).encode());
		assertArrayEquals(challenge, decoded.challenge());
	}

	@Test
	void truncatedConnectThrowsMalformed() throws Exception {
		CryptoContext[] ctx = contextPair();
		Buffer pkt = new Packet.Connect(InetAddress.getByName("1.1.1.1"), 53).encode(ctx[0]);
		Buffer truncated = pkt.slice(0, 4); // far shorter than the fixed Connect size

		assertThrows(MalformedPacketException.class, () -> Packet.Connect.decode(truncated, ctx[1]));
	}

	@Test
	void corruptedDataThrowsMalformed() {
		CryptoContext[] ctx = contextPair();
		byte[] raw = new Packet.Data("payload".getBytes(StandardCharsets.UTF_8)).encode(ctx[0]).getBytes();
		raw[raw.length - 1] ^= 0xFF; // corrupt the ciphertext so the MAC check fails

		assertThrows(MalformedPacketException.class, () -> Packet.Data.decode(Buffer.buffer(raw), ctx[1]));
	}
}