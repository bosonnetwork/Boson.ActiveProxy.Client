/*
 * Copyright (c) 2023 -      bosonnetwork.io
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package io.bosonnetwork.activeproxy;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import io.vertx.core.buffer.Buffer;

import io.bosonnetwork.CryptoContext;
import io.bosonnetwork.Id;
import io.bosonnetwork.Identity;
import io.bosonnetwork.crypto.CryptoBox;
import io.bosonnetwork.crypto.CryptoException;
import io.bosonnetwork.crypto.Random;
import io.bosonnetwork.crypto.Signature;

// This class is copied from the Active-Proxy service implementation.
// Keep it synchronized with the original source to avoid divergence.
@SuppressWarnings("unused")
public class Packet {
	public static final int VERSION = 1;
	public static final int HEADER_BYTES = Short.BYTES + Byte.BYTES;

	public static PacketType getType(Buffer packet) throws MalformedPacketException {
		if (packet.length() < HEADER_BYTES)
			throw new MalformedPacketException("packet too short");

		int size = packet.getUnsignedShort(0);
		if (size != packet.length())
			throw new MalformedPacketException("package size mismatch");

		try {
			return PacketType.valueOf(packet.getByte(Short.BYTES));
		} catch (IllegalArgumentException e) {
			throw new MalformedPacketException("invalid packet type", e);
		}
	}

	public record Challenge(byte[] challenge) {
		public static final int MIN_BYTES = Short.BYTES + 32;

		public Buffer encode() {
			int size = MIN_BYTES + challenge.length - 32;
			Buffer packet = Buffer.buffer(size);
			packet.appendUnsignedShort(size);
			packet.appendBytes(challenge);
			return packet;
		}

		public static Challenge decode(Buffer packet) throws MalformedPacketException {
			if (packet.length() < MIN_BYTES)
				throw new MalformedPacketException("packet too short");

			int size = packet.getUnsignedShort(0);
			if (size != packet.length())
				throw new MalformedPacketException("package size mismatch");

			byte[] challenge = packet.getBytes(Short.BYTES, packet.length());
			return new Challenge(challenge);
		}
	}

	/*/
	 * AUTH packet payload:
	 *   - plain
	 *     - deviceId
	 *   - encrypted
	 *     - version(short)
	 *     - userId
	 *     - clientSessionPk
	 *     - nameAccess
	 *     # - userSig[challenge]
	 *     - deviceSig[challenge]
	 *     - padding
	 */
	public record Auth(int version, Id userId, Id deviceId, CryptoBox.PublicKey clientSessionPk,
					   boolean nameAccess, byte[] deviceSig) {
		private static final int SECRET_BYTES = Short.BYTES + Id.BYTES + CryptoBox.PublicKey.BYTES +
				Byte.BYTES + Signature.BYTES;
		public static int BYTES = HEADER_BYTES +  // package header
				Id.BYTES +  // plain device id
				CryptoBox.Nonce.BYTES + CryptoBox.MAC_BYTES + // encryption header
				SECRET_BYTES;

		public Buffer encode(CryptoContext cryptoContext) {
			byte[] padding = randomPadding(BYTES);
			byte[] secret = new byte[SECRET_BYTES + padding.length];

			int pos = 0;
			shortToNetwork(version, secret, pos);
			pos += Short.BYTES;

			System.arraycopy(userId.bytes(), 0, secret, pos, Id.BYTES);
			pos += Id.BYTES;

			System.arraycopy(clientSessionPk.bytes(), 0, secret, pos, CryptoBox.PublicKey.BYTES);
			pos += CryptoBox.PublicKey.BYTES;

			secret[pos++] = (byte)(nameAccess ? 1 : 0);

			System.arraycopy(deviceSig, 0, secret, pos, deviceSig.length);
			pos += deviceSig.length;

			System.arraycopy(padding, 0, secret, pos, padding.length);

			byte[] cipher = cryptoContext.encrypt(secret);

			int size = BYTES + padding.length;
			Buffer packet = Buffer.buffer(size);
			packet.appendUnsignedShort(size);
			packet.appendByte(PacketType.AUTH.value());
			packet.appendBytes(deviceId.bytes());
			packet.appendBytes(cipher);

			return packet;
		}

		public boolean verify(byte[] challenge) {
			return Signature.verify(challenge, deviceSig, deviceId.toSignatureKey());
		}

		public static Auth decode(Buffer packet, Identity identity) throws MalformedPacketException {
			if (packet.length() < BYTES)
				throw new MalformedPacketException("packet too short");

			int pos = HEADER_BYTES;
			Id deviceId = Id.of(packet.getBytes(pos, pos + Id.BYTES));
			pos += Id.BYTES;

			byte[] cipher = packet.getBytes(pos, packet.length());
			byte[] secret;
			try {
				secret = identity.decrypt(deviceId, cipher);
			} catch (CryptoException e) {
				throw new MalformedPacketException("failed to decrypt packet", e);
			}

			pos = 0;
			int version = networkToShort(secret, pos);
			pos += Short.BYTES;

			Id userId = Id.of(Arrays.copyOfRange(secret, pos, pos + Id.BYTES));
			pos += Id.BYTES;

			CryptoBox.PublicKey clientSessionPk = CryptoBox.PublicKey.fromBytes(
					Arrays.copyOfRange(secret, pos, pos + CryptoBox.PublicKey.BYTES));
			pos += CryptoBox.PublicKey.BYTES;

			boolean nameAccess = Byte.toUnsignedInt(secret[pos++]) == 1;

			byte[] deviceSig = Arrays.copyOfRange(secret, pos, pos + Signature.BYTES);

			return new Auth(version, userId, deviceId, clientSessionPk, nameAccess, deviceSig);
		}
	}

	/*/
	 * AUTH_ACK packet payload:
	 * - encrypted
	 *   - serverSessionPk[server]
	 *   - maxConnections[uint16]
	 *   - nameAccess
	 *   - endpoint[null terminated string - IP:PORT]
	 *   - namedEndpoint[null terminated string - URL]
	 *   - padding
	 */
	public record AuthAck(CryptoBox.PublicKey serverSessionPk, int maxConnections, boolean nameAccess,
						  String endpoint, String namedEndpoint) {
		private static final int MIN_SECRET_BYTES = CryptoBox.PublicKey.BYTES + Short.BYTES + Byte.BYTES + 2;
		public static final int MIN_BYTES = HEADER_BYTES + // packet header
				CryptoBox.Nonce.BYTES + CryptoBox.MAC_BYTES + // encryption header
				MIN_SECRET_BYTES;

		public Buffer encode(CryptoContext cryptoContext) {
			int endpointsSize = (endpoint != null ? endpoint.length() : 0) +
					(namedEndpoint != null ? namedEndpoint.length() : 0);

			byte[] padding = randomPadding(MIN_BYTES + endpointsSize);
			byte[] secret = new byte[MIN_SECRET_BYTES + endpointsSize + padding.length];

			int pos = 0;
			System.arraycopy(serverSessionPk.bytes(), 0, secret, pos, CryptoBox.PublicKey.BYTES);
			pos += CryptoBox.PublicKey.BYTES;

			shortToNetwork(maxConnections, secret, pos);
			pos += Short.BYTES;

			secret[pos++] = (byte)(nameAccess ? 1 : 0);

			if (endpoint != null) {
				byte[] bytes = endpoint.getBytes(StandardCharsets.UTF_8);
				System.arraycopy(bytes, 0, secret, pos, bytes.length);
				pos += bytes.length;
			}
			secret[pos++] = (byte)0;

			if (namedEndpoint != null) {
				byte[] bytes = namedEndpoint.getBytes(StandardCharsets.UTF_8);
				System.arraycopy(bytes, 0, secret, pos, bytes.length);
				pos += bytes.length;
			}
			secret[pos++] = (byte)0;

			System.arraycopy(padding, 0, secret, pos, padding.length);

			byte[] cipher = cryptoContext.encrypt(secret);

			int size = HEADER_BYTES + cipher.length;
			Buffer packet = Buffer.buffer(size);
			packet.appendUnsignedShort(size);
			packet.appendByte(PacketType.AUTH_ACK.value());
			packet.appendBytes(cipher);

			return packet;
		}

		public static AuthAck decode(Buffer packet, CryptoContext cryptoContext) throws MalformedPacketException {
			if (packet.length() < MIN_BYTES)
				throw new MalformedPacketException("packet too short");

			int pos = HEADER_BYTES;

			byte[] cipher = packet.getBytes(pos, packet.length());
			byte[] secret;
			try {
				secret = cryptoContext.decrypt(cipher);
			} catch (CryptoException e) {
				throw new MalformedPacketException("failed to decrypt packet", e);
			}

			pos = 0;
			CryptoBox.PublicKey serverSessionPk = CryptoBox.PublicKey.fromBytes(
					Arrays.copyOfRange(secret, pos, pos + CryptoBox.PublicKey.BYTES));
			pos += CryptoBox.PublicKey.BYTES;

			int maxConnections = networkToShort(secret, pos);
			pos += Short.BYTES;

			boolean nameAccess = Byte.toUnsignedInt(secret[pos++]) == 1;

			String endpoint = null;
			if (secret[pos] != 0) {
				int end = pos;
				while (end < secret.length && secret[end] != 0) end++;
				if (end >= secret.length)
					throw new MalformedPacketException("missing null terminator for the endpoint");

				endpoint = new String(secret, pos, end - pos, StandardCharsets.UTF_8);
				pos = end + 1;
			}

			if (endpoint == null)
				throw new MalformedPacketException("missing endpoint");

			String namedEndpoint = null;
			if (secret[pos] != 0) {
				int end = pos;
				while (end < secret.length && secret[end] != 0) end++;
				if (end >= secret.length)
					throw new MalformedPacketException("missing null terminator for the named endpoint");

				namedEndpoint = new String(secret, pos, end - pos, StandardCharsets.UTF_8);
			}

			if (nameAccess && namedEndpoint == null)
				throw new MalformedPacketException("missing named endpoint");

			return new AuthAck(serverSessionPk, maxConnections, nameAccess, endpoint, namedEndpoint);
		}
	}

	/*/
	 * ATTACH packet payload:
	 *   - plain
	 *     - deviceId
	 *   - encrypted
	 *     - clientSessionPk
	 *     - deviceSig[challenge]
	 *     - padding
	 */
	public record Attach(Id deviceId, CryptoBox.PublicKey clientSessionPk, byte[] deviceSig) {
		private static final int SECRET_BYTES = CryptoBox.PublicKey.BYTES + Signature.BYTES;
		public static final int BYTES = HEADER_BYTES + // packet header
				Id.BYTES + // plain device id
				CryptoBox.Nonce.BYTES + CryptoBox.MAC_BYTES + // encryption header
				SECRET_BYTES;

		public Buffer encode(CryptoContext cryptoContext) {
			byte[] padding = randomPadding(BYTES);
			byte[] secret = new byte[SECRET_BYTES + padding.length];

			int pos = 0;
			System.arraycopy(clientSessionPk.bytes(), 0, secret, pos, CryptoBox.PublicKey.BYTES);
			pos += CryptoBox.PublicKey.BYTES;

			System.arraycopy(deviceSig, 0, secret, pos, deviceSig.length);
			pos += deviceSig.length;

			System.arraycopy(padding, 0, secret, pos, padding.length);

			byte[] cipher = cryptoContext.encrypt(secret);

			int size = BYTES + padding.length;
			Buffer packet = Buffer.buffer(size);
			packet.appendUnsignedShort(size);
			packet.appendByte(PacketType.ATTACH.value());
			packet.appendBytes(deviceId.bytes());
			packet.appendBytes(cipher);

			return packet;
		}

		public boolean verify(byte[] challenge) {
			return Signature.verify(challenge, deviceSig, deviceId.toSignatureKey());
		}

		public static Attach decode(Buffer packet, Identity identity) throws MalformedPacketException {
			if (packet.length() < BYTES)
				throw new MalformedPacketException("packet too short");

			int pos = HEADER_BYTES;
			Id deviceId = Id.of(packet.getBytes(pos, pos + Id.BYTES));
			pos += Id.BYTES;

			byte[] cipher = packet.getBytes(pos, packet.length());
			byte[] secret;
			try {
				secret = identity.decrypt(deviceId, cipher);
			} catch (CryptoException e) {
				throw new MalformedPacketException("failed to decrypt packet", e);
			}

			pos = 0;
			CryptoBox.PublicKey clientSessionPk = CryptoBox.PublicKey.fromBytes(
					Arrays.copyOfRange(secret, pos, pos + CryptoBox.PublicKey.BYTES));
			pos += CryptoBox.PublicKey.BYTES;

			byte[] deviceSig = Arrays.copyOfRange(secret, pos, pos + Signature.BYTES);
			return new Attach(deviceId, clientSessionPk, deviceSig);
		}
	}

	public record AttachAck() {
		public static final int BYTES = HEADER_BYTES;
		public static final AttachAck INSTANCE = new AttachAck();

		public static Buffer encode() {
			return encodeWithEmptyPayload(PacketType.ATTACH_ACK);
		}

		public static AttachAck decode(@SuppressWarnings("unused") Buffer packet) {
			return INSTANCE;
		}
	}

	public record Ping() {
		public static final int BYTES = HEADER_BYTES;
		public static final Ping INSTANCE = new Ping();

		public static Buffer encode() {
			return encodeWithEmptyPayload(PacketType.PING);
		}

		public static Ping decode(@SuppressWarnings("unused") Buffer packet) {
			return INSTANCE;
		}
	}

	public record PingAck() {
		public static final int BYTES = HEADER_BYTES;
		public static final PingAck INSTANCE = new PingAck();

		public static Buffer encode() {
			return encodeWithEmptyPayload(PacketType.PING_ACK);
		}

		public static PingAck decode(@SuppressWarnings("unused") Buffer packet) {
			return INSTANCE;
		}
	}

	/*
	 * CONNECT packet payload:
	 * - encrypted
	 *   - port[uint16]
	 *   - addrlen[uint8]
	 *   - addr[16 bytes both for IPv4 or IPv6]
	 *   - padding
	 */
	public record Connect(InetAddress address, int port) {
		private static final int SECRET_BYTES = Short.BYTES + Byte.BYTES + 16;
		public static final int BYTES = HEADER_BYTES + // packet header
				CryptoBox.Nonce.BYTES + CryptoBox.MAC_BYTES + // encryption header
				SECRET_BYTES;

		public Buffer encode(CryptoContext cryptoContext) {
			byte[] padding = randomPadding(BYTES);
			byte[] secret = new byte[SECRET_BYTES + padding.length];

			int pos = 0;
			shortToNetwork(port, secret, pos);
			pos += Short.BYTES;

			byte[] addr = address.getAddress();
			secret[pos++] = (byte)addr.length;
			System.arraycopy(addr, 0, secret, pos, addr.length);

			byte[] cipher = cryptoContext.encrypt(secret);

			int size = BYTES + padding.length;
			Buffer packet = Buffer.buffer(size);
			packet.appendUnsignedShort(size);
			packet.appendByte(PacketType.CONNECT.value());
			packet.appendBytes(cipher);

			return packet;
		}

		public static Connect decode(Buffer packet, CryptoContext cryptoContext) throws MalformedPacketException {
			if (packet.length() < BYTES)
				throw new MalformedPacketException("packet too short");

			byte[] cipher = packet.getBytes(HEADER_BYTES, packet.length());
			byte[] secret;
			try {
				secret = cryptoContext.decrypt(cipher);
			} catch (CryptoException e) {
				throw new MalformedPacketException("failed to decrypt packet", e);
			}

			int pos = 0;
			int port = networkToShort(secret, pos);
			pos += Short.BYTES;
			int addrLen = Byte.toUnsignedInt(secret[pos++]);
			byte[] addr = new byte[addrLen];
			System.arraycopy(secret, pos, addr, 0, addrLen);

			try {
				return new Connect(InetAddress.getByAddress(addr), port);
			} catch (UnknownHostException e) {
				throw new MalformedPacketException("Invalid address", e);
			}
		}
	}

	/*/
	 * CONNECT_ACK packet payload:
	 * - plain
	 *   - succeeded[boolean]
	 *   - padding
	 */
	public record ConnectAck(boolean succeeded) {
		public static final int BYTES = HEADER_BYTES + Byte.BYTES;
		public static final ConnectAck SUCCEEDED = new ConnectAck(true);
		public static final ConnectAck FAILED = new ConnectAck(false);

		public static ConnectAck of(boolean succeeded) {
			return succeeded ? SUCCEEDED : FAILED;
		}

		public Buffer encode() {
			byte[] padding = randomPadding(BYTES);
			int size = BYTES + padding.length;
			Buffer packet = Buffer.buffer(size);
			packet.appendUnsignedShort(size);
			packet.appendByte(PacketType.CONNECT_ACK.value());
			int r = Random.secureRandom().nextInt(0, 255);
			byte b = (byte)(succeeded ? r | 0x01 : r & 0xFE);
			packet.appendByte(b);
			packet.appendBytes(padding);
			return packet;
		}

		public static ConnectAck decode(Buffer packet) throws MalformedPacketException {
			if (packet.length() < BYTES)
				throw new MalformedPacketException("packet too short");

			byte b = packet.getByte(HEADER_BYTES);
			boolean succeeded = (b & 0x01) != 0;
			return succeeded ? SUCCEEDED : FAILED;
		}

	}

	public record Disconnect() {
		public static final int BYTES = HEADER_BYTES;
		public static final Disconnect INSTANCE = new Disconnect();

		public static Buffer encode() {
			return encodeWithEmptyPayload(PacketType.DISCONNECT);
		}

		public static Disconnect decode(@SuppressWarnings("unused") Buffer packet) {
			return INSTANCE;
		}
	}

	public record DisconnectAck() {
		public static final int BYTES = HEADER_BYTES;
		public static final DisconnectAck INSTANCE = new DisconnectAck();

		public static Buffer encode() {
			return encodeWithEmptyPayload(PacketType.DISCONNECT_ACK);
		}

		public static DisconnectAck decode(@SuppressWarnings("unused") Buffer packet) {
			return INSTANCE;
		}
	}

	/*/
	 * DATA packet payload:
	 * - encrypted
	 *   - data
	 */
	public record Data(byte[] data) {
		public static final int MIN_BYTES = HEADER_BYTES + // packet header
			CryptoBox.Nonce.BYTES + CryptoBox.MAC_BYTES;

		public Buffer encode(CryptoContext cryptoContext) {
			byte[] cipher = cryptoContext.encrypt(data);
			int size = HEADER_BYTES + cipher.length;
			Buffer packet = Buffer.buffer(size);
			packet.appendUnsignedShort(size);
			packet.appendByte(PacketType.DATA.value());
			packet.appendBytes(cipher);
			return packet;
		}

		public static Data decode(Buffer packet, CryptoContext cryptoContext) throws MalformedPacketException {
			if (packet.length() < MIN_BYTES)
				throw new MalformedPacketException("packet too short");

			byte[] cipher = packet.getBytes(HEADER_BYTES, packet.length());
			byte[] payload;
			try {
				payload = cryptoContext.decrypt(cipher);
			} catch (CryptoException e) {
				throw new MalformedPacketException("failed to decrypt packet", e);
			}

			return new Data(payload);
		}
	}

	public record Error(short code, String message) {
		private static final int MIN_SECRET_BYTES = Short.BYTES + 1;
		public static final int MIN_BYTES = HEADER_BYTES +
				CryptoBox.Nonce.BYTES + CryptoBox.MAC_BYTES + // encryption header
				MIN_SECRET_BYTES;

		public Buffer encode(CryptoContext cryptoContext) {
			int messageLen = message != null ? message.length() : 0;
			byte[] padding = randomPadding(MIN_BYTES + messageLen);
			byte[] secret = new byte[MIN_SECRET_BYTES + messageLen + padding.length];

			int pos = 0;
			shortToNetwork(code, secret, pos);
			pos += Short.BYTES;

			if (message != null) {
				byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
				System.arraycopy(bytes, 0, secret, pos, bytes.length);
				pos += bytes.length;
			}
			secret[pos++] = (byte)0;

			System.arraycopy(padding, 0, secret, pos, padding.length);

			byte[] cipher = cryptoContext.encrypt(secret);

			int size = HEADER_BYTES + cipher.length;
			Buffer packet = Buffer.buffer(size);
			packet.appendUnsignedShort(size);
			packet.appendByte(PacketType.ERROR.value());
			packet.appendBytes(cipher);

			return packet;
		}

		public static Error decode(Buffer packet, CryptoContext cryptoContext) throws MalformedPacketException {
			if (packet.length() < MIN_BYTES)
				throw new MalformedPacketException("packet too short");

			byte[] cipher = packet.getBytes(HEADER_BYTES, packet.length());
			byte[] secret;
			try {
				secret = cryptoContext.decrypt(cipher);
			} catch (CryptoException e) {
				throw new MalformedPacketException("failed to decrypt packet", e);
			}

			int pos = 0;
			short code = (short) networkToShort(secret, pos);
			pos += Short.BYTES;

			String message = null;
			if (secret[pos] != 0) {
				int end = pos;
				while (end < secret.length && secret[end] != 0) end++;
				if (end >= secret.length)
					throw new MalformedPacketException("missing null terminator for the message");

				message = new String(secret, pos, end - pos, StandardCharsets.UTF_8);
			}

			return new Error(code, message);
		}
	}

	private static Buffer encodeWithEmptyPayload(PacketType type) {
		byte[] padding = randomPadding(HEADER_BYTES);
		int size = HEADER_BYTES + padding.length;

		Buffer packet = Buffer.buffer(size);
		packet.appendUnsignedShort(size);
		packet.appendByte(type.value());
		packet.appendBytes(padding);
		return packet;
	}

	protected static int paddingSize(int size) {
		// round up to the nearest multiple of 256
		int bound = ((size + 255) & ~255);
		return Random.secureRandom().nextInt(bound - size + 1);
	}

	protected static byte[] randomPadding(int size) {
		byte[] padding = new byte[paddingSize(size)];
		if (padding.length > 0)
			Random.secureRandom().nextBytes(padding);
		return padding;
	}

	private static void shortToNetwork(int num, byte[] dest, int pos) {
		ByteBuffer.wrap(dest, pos, Short.BYTES).putShort((short)num);
	}

	private static int networkToShort(byte[] dest, int pos) {
		return ByteBuffer.wrap(dest, pos, Short.BYTES).getShort() & 0xFFFF;
	}
}