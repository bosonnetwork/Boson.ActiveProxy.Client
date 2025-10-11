/*
 * Copyright (c) 2022 - 2023 trinity-tech.io
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

import io.bosonnetwork.crypto.Random;

// This class is copied from the Active-Proxy service implementation.
// Keep it synchronized with the original source to avoid divergence.
public enum PacketType {
	CHALLENGE(0x00, 0x00),	// abstract type, no real value and type header
	AUTH(0x00, 0x07),
	AUTH_ACK(AUTH),
	ATTACH(0x08, 0x0F),
	ATTACH_ACK(ATTACH),
	PING(0x10, 0x1F),
	PING_ACK(PING),
	CONNECT(0x20, 0x2F),
	CONNECT_ACK(CONNECT),
	DISCONNECT(0x30, 0x3F),
	DISCONNECT_ACK(DISCONNECT),
	DATA(0x40, 0x6F),
	ERROR(0x70, 0x7F);

	private static final byte ACK_MASK = (byte) 0x80;
	private static final byte TYPE_MASK = 0x7F;

	private final byte min;
	private final byte max;
	private final boolean ack;

	PacketType(int min, int max) {
		this.min = (byte)min;
		this.max = (byte)max;
		this.ack = false;
	}

	// ACK
	PacketType(PacketType flag) {
		this.min = flag.min;
		this.max = flag.max;
		this.ack = true;
	}

	public byte value() {
		byte value = (byte)Random.random().nextInt(min, max + 1);
		return ack ? (byte)(value | (ACK_MASK & 0x00ff)) : value;
	}

	public boolean isAck() {
		return ack;
	}

	public static PacketType valueOf(byte flag) {
		boolean ack = (flag & ACK_MASK) != 0;
		byte type = (byte) (flag & TYPE_MASK);
		return switch (type >> 4) {
			case 0 -> {
				if (type <= AUTH.max)
					yield ack ? AUTH_ACK : AUTH;
				else
					yield ack ? ATTACH_ACK : ATTACH;
			}
			case 1 -> ack ? PING_ACK : PING;
			case 2 -> ack ? CONNECT_ACK : CONNECT;
			case 3 -> ack ? DISCONNECT_ACK : DISCONNECT;
			case 4, 5, 6 -> {
				if (ack)
					throw new IllegalArgumentException("Invalid ACK flag for DATA packet");
				else
					yield DATA;
			}
			case 7 -> {
				if (ack)
					throw new IllegalArgumentException("Invalid ACK flag for ERROR packet");
				else
					yield ERROR;
			}
			default -> throw new IllegalArgumentException("Should never happen: invalid flag");
		};
	}
}