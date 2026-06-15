package io.bosonnetwork.activeproxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.InetAddress;
import java.util.concurrent.atomic.AtomicInteger;

import io.vertx.core.Context;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.net.NetClient;
import io.vertx.core.net.NetServer;
import io.vertx.core.net.NetSocket;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;

import io.bosonnetwork.CryptoContext;
import io.bosonnetwork.crypto.CryptoBox;

/**
 * Tests {@link ProxyConnection#proxyHandler(io.vertx.core.buffer.Buffer)} framing over a real
 * loopback socket: a Vert.x {@link NetServer} pushes precisely-crafted bytes to a client-side
 * {@code ProxyConnection}, exercising TCP segmentation, packet coalescing, and malformed-size
 * handling (the A3 fix).
 */
@ExtendWith(VertxExtension.class)
class ProxyConnectionFramingTest {

	/** A {@link ProxyConnectionHandler} with no-op defaults; tests override what they need. */
	@NullMarked
	private abstract static class TestHandler implements ProxyConnectionHandler {
		@Override public void challenge(ProxyConnection c, byte[] challenge) { }
		@Override public CryptoContext authenticated(ProxyConnection c, CryptoBox.PublicKey serverSessionPk,
				int maxConnections, boolean nameAccess, String endpoint, @Nullable String namedEndpoint) { return null; }
		@Override public void open(ProxyConnection c) { }
		@Override public void close(ProxyConnection c) { }
		@Override public void idle(ProxyConnection c) { }
		@Override public void busy(ProxyConnection c) { }
		@Override public boolean allow(InetAddress clientAddress, int clientPort) { return true; }
		@Override public Future<NetSocket> connectUpstream() { return Future.failedFuture("no upstream"); }
	}

	private static Buffer challengePacket(byte[] challenge) {
		return new Packet.Challenge(challenge).encode();
	}

	/**
	 * Stands up a server that runs {@code serverSend} for each incoming connection and a client that
	 * wraps its socket in a {@link ProxyConnection} driven by {@code handler}.
	 */
	private void withConnection(Vertx vertx, VertxTestContext ctx, Handler<NetSocket> serverSend,
			ProxyConnectionHandler handler) {
		NetServer server = vertx.createNetServer();
		server.connectHandler(serverSend);
		server.listen(0, "127.0.0.1").onComplete(ctx.succeeding(srv -> {
			NetClient client = vertx.createNetClient();
			client.connect(srv.actualPort(), "127.0.0.1").onComplete(ctx.succeeding(sock -> {
				Context c = vertx.getOrCreateContext();
				// Construction wires the proxy-socket handlers; nothing else to hold onto.
				new ProxyConnection(1, c, null, null, sock, handler);
			}));
		}));
	}

	@Test
	void reassemblesPacketSplitAcrossWrites(Vertx vertx, VertxTestContext ctx) {
		byte[] challenge = new byte[32];
		for (int i = 0; i < challenge.length; i++)
			challenge[i] = (byte) (i + 1);
		Buffer pkt = challengePacket(challenge);

		withConnection(vertx, ctx,
				serverSock -> {
					// Split the 2-byte size header itself across two TCP segments.
					serverSock.write(pkt.slice(0, 1));
					vertx.setTimer(30, t -> serverSock.write(pkt.slice(1, pkt.length())));
				},
				new TestHandler() {
					@Override
					public void challenge(@NonNull ProxyConnection c, byte @NonNull [] ch) {
						ctx.verify(() -> assertArrayEquals(challenge, ch)).completeNow();
					}
				});
	}

	@Test
	void deliversTwoCoalescedPackets(Vertx vertx, VertxTestContext ctx) {
		byte[] challenge = new byte[32];
		Buffer two = Buffer.buffer()
				.appendBuffer(challengePacket(challenge))
				.appendBuffer(challengePacket(challenge));
		AtomicInteger count = new AtomicInteger();

		withConnection(vertx, ctx,
				serverSock -> serverSock.write(two),
				new TestHandler() {
					@Override
					public void challenge(@NonNull ProxyConnection c, byte @NonNull [] ch) {
						if (count.incrementAndGet() == 2)
							ctx.completeNow();
					}
				});
	}

	@Test
	void malformedZeroSizeClosesConnection(Vertx vertx, VertxTestContext ctx) {
		AtomicInteger challenges = new AtomicInteger();

		withConnection(vertx, ctx,
				// declared size 0 (0x00 0x00) + a type byte: must be rejected, not looped on
				serverSock -> serverSock.write(Buffer.buffer(new byte[] { 0, 0, 0 })),
				new TestHandler() {
					@Override
					public void challenge(@Nullable ProxyConnection c, byte @Nullable [] ch) {
						challenges.incrementAndGet();
					}

					@Override
					public void close(@Nullable ProxyConnection c) {
						ctx.verify(() -> assertEquals(0, challenges.get())).completeNow();
					}
				});
	}
}