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

import java.util.Objects;

import io.vertx.core.Context;
import io.vertx.core.Future;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.net.NetSocket;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.bosonnetwork.CryptoContext;
import io.bosonnetwork.Id;
import io.bosonnetwork.crypto.CryptoBox;
import io.bosonnetwork.crypto.Random;

/**
 * A single multiplexing connection between this client and the Active Proxy super node.
 * <p>
 * Each {@code ProxyConnection} owns one TCP socket to the super node (the <em>proxy socket</em>) and,
 * while relaying, one TCP socket to the local upstream service (the <em>upstream socket</em>). The
 * proxy socket carries a length-prefixed, encrypted packet stream; {@link #proxyHandler(Buffer)}
 * de-frames it (handling TCP segmentation via {@link #stickyBuffer}) and dispatches each complete
 * packet through {@link #packetHandler(Buffer)} according to the current {@link State}.
 * <p>
 * <b>Lifecycle / handshake:</b> a connection starts in {@link State#Initializing}, receives a
 * {@code CHALLENGE}, and authenticates (first connection of a session) or attaches (subsequent
 * connections) to reach {@link State#Idling}. From there the super node drives it through
 * {@code CONNECT → Relaying → DISCONNECT} cycles to bridge external connections to the upstream;
 * {@code PING}/{@code PING_ACK} keep the link alive.
 * <p>
 * <b>Threading:</b> all methods run on the owning session's Vert.x event loop, so no field is
 * accessed from another thread and no synchronization is required here.
 *
 * @implNote The disconnect path uses a small three-way handshake - see {@link #disconnectUpstream()}.
 */
@SuppressWarnings("UnusedReturnValue")
class ProxyConnection {
	private static final int KEEP_ALIVE_INTERVAL = 60000;
	private static final int MAX_KEEP_ALIVE_RETRY = 3;
	// A relayed connection is fully torn down only after three disconnect confirmations:
	// the local upstream end, the server DISCONNECT, and the matching DISCONNECT_ACK.
	private static final int DISCONNECT_CONFIRMS = 3;

	private final long id;
	private final Context vertxContext;
	private final CryptoContext peerContext;
	private @Nullable CryptoContext sessionContext;
	private final ProxyConnectionHandler handler;

	private final NetSocket proxySocket;
	private @Nullable NetSocket upstreamSocket;

	private State state = State.Initializing;
	private @Nullable Buffer stickyBuffer;

	private long lastReceiveTimestamp;
	private int disconnectConfirms;

	private static final Logger log = LoggerFactory.getLogger(ProxyConnection.class);

	// @formatter:off
	/**
	 * Represents the lifecycle of a proxy connection.
	 * <p>
	 * The state machine enforces protocol correctness by declaring which {@link PacketType}s
	 * are valid in each state via {@link #accept(PacketType)}. Reception of an unexpected packet
	 * is treated as a protocol violation and results in immediate connection closure.
	 * <p>
	 * <b>Lifecycle Flow:</b>
	 * <ol>
	 *   <li><b>Establishment:</b> {@code Initializing} &rarr; {@code Authenticating} | {@code Attaching} &rarr; {@code Idling}</li>
	 *   <li><b>Operation:</b> {@code Idling} &rarr; {@code Connecting} &rarr; {@code Relaying}</li>
	 *   <li><b>Teardown:</b> {@code Relaying} &rarr; {@code Disconnecting} &rarr; {@code Idling}</li>
	 * </ol>
	 * <pre>
	 *  [ Initializing ] --(CHALLENGE)--> [ Authenticating / Attaching ]
	 *                                                |
	 *                                           (AUTH_ACK / ATTACH_ACK)
	 *                                                v
	 *  [ Relaying ] <---(upstream ok)--- [ Connecting ] <---(CONNECT)--- [ Idling ]
	 *       |                                                               ^
	 *  (DISCONNECT / upstream end)                                          |
	 *       |                                                               |
	 *       v                                                               |
	 *  [ Disconnecting ] ------------------(3-way handshake)----------------/
	 * </pre>
	 * {@link #Closed} is the terminal state for the underlying socket.
	 */
	// @formatter:on
	private enum State {
		/** Freshly opened; awaiting the server {@code CHALLENGE}. */
		Initializing {
			@Override
			public boolean accept(PacketType type) {
				return type == PacketType.CHALLENGE;
			}
		},
		/** First connection of a session: {@code AUTH} sent, awaiting {@code AUTH_ACK}. */
		Authenticating {
			@Override
			public boolean accept(PacketType type) {
				return type == PacketType.AUTH_ACK;
			}
		},
		/** Additional connection of an authenticated session: {@code ATTACH} sent, awaiting {@code ATTACH_ACK}. */
		Attaching {
			@Override
			public boolean accept(PacketType type) {
				return type == PacketType.ATTACH_ACK;
			}
		},
		/** Authenticated and idle; awaiting a {@code CONNECT} request (or keep-alive {@code PING_ACK}). */
		Idling {
			@Override
			public boolean accept(PacketType type) {
				return type == PacketType.PING_ACK || type == PacketType.CONNECT;
			}
		},
		/** {@code CONNECT} received; dialing the upstream service. */
		Connecting {
			@Override
			public boolean accept(PacketType type) {
				return type == PacketType.PING_ACK || type == PacketType.DISCONNECT;
			}
		},
		/** Upstream connected; relaying {@code DATA} in both directions. */
		Relaying {
			@Override
			public boolean accept(PacketType type) {
				return type == PacketType.DATA || type == PacketType.DISCONNECT || type == PacketType.PING_ACK;
			}
		},
		/** Tearing down the relayed connection via the disconnect handshake before returning to {@link #Idling}. */
		Disconnecting {
			@Override
			public boolean accept(PacketType type) {
				return type == PacketType.DISCONNECT || type == PacketType.DISCONNECT_ACK ||
						type == PacketType.DATA || type == PacketType.PING_ACK;
			}
		},
		/** Terminal: the connection (and its sockets) have been closed. */
		Closed {
			@Override
			public boolean accept(PacketType type) {
				return false;
			}
		};

		/**
		 * @param type an inbound packet type
		 * @return {@code true} if this state may process {@code type}
		 */
		public abstract boolean accept(PacketType type);
	}

	protected ProxyConnection(long id, Context vertxContext, CryptoContext peerContext, @Nullable CryptoContext sessionContext,
							  NetSocket proxySocket, ProxyConnectionHandler handler) {
		this.id = id;
		this.vertxContext = vertxContext;
		this.peerContext = peerContext;
		this.sessionContext = sessionContext;
		this.handler = handler;

		this.lastReceiveTimestamp = System.currentTimeMillis();
		this.proxySocket = proxySocket;
		proxySocket.endHandler(v -> {
			log.debug("Connection {} closed by proxy socket", id);
			close();
		});
		proxySocket.exceptionHandler(e -> {
			log.error("Connection {} got exception from proxy socket", id, e);
			close();
		});
		proxySocket.handler(this::proxyHandler);
	}

	@SuppressWarnings("unused")
	public long getId() {
		return id;
	}

	private Future<Void> sendPacket(PacketType type, Buffer buffer) {
		return proxySocket.write(buffer).andThen(ar -> {
			if (ar.succeeded()) {
				log.trace("Connection {} sent {} packet to proxy socket", id, type);
			} else {
				if (log.isDebugEnabled())
					log.error("Connection {} failed to send {} packet to proxy socket", id, type, ar.cause());
				else
					log.error("Connection {} failed to send {} packet to proxy socket: {}", id, type, ar.cause().getMessage());

				close();
			}
		});
	}

	protected Future<Void> sendAuth(Id userId, Id deviceId, CryptoBox.PublicKey clientSessionPk,
									boolean nameAccess, byte[] deviceSig, CryptoContext peerContext) {
		state = State.Authenticating;
		Packet.Auth auth = new Packet.Auth(Packet.VERSION, userId, deviceId, clientSessionPk, nameAccess, deviceSig);
		return sendPacket(PacketType.AUTH, auth.encode(peerContext));
	}

	protected Future<Void> sendAttach(Id deviceId, CryptoBox.PublicKey clientSessionPk, byte[] deviceSig, CryptoContext peerContext) {
		state = State.Attaching;
		Packet.Attach attach = new Packet.Attach(deviceId, clientSessionPk, deviceSig);
		return sendPacket(PacketType.ATTACH, attach.encode(peerContext));
	}

	private Future<Void> sendPing() {
		return sendPacket(PacketType.PING, Packet.Ping.encode());
	}

	private Future<Void> sendConnectAck(boolean succeeded) {
		return sendPacket(PacketType.CONNECT_ACK, Packet.ConnectAck.of(succeeded).encode());
	}

	private Future<Void> sendDisconnect() {
		return sendPacket(PacketType.DISCONNECT, Packet.Disconnect.encode());
	}

	private Future<Void> sendDisconnectAck() {
		return sendPacket(PacketType.DISCONNECT_ACK, Packet.DisconnectAck.encode());
	}

	private Future<Void> sendData(byte[] data) {
		CryptoContext sessionContext = requireInitialized(this.sessionContext, "sessionContext");
		Packet.Data dat = new Packet.Data(data);
		Future<Void> future = sendPacket(PacketType.DATA, dat.encode(sessionContext));

		// Flow control for the upstream to the proxy
		if (proxySocket.writeQueueFull()) {
			log.trace("Proxy socket write queue full, pause upstream reading");
			if (upstreamSocket != null)
				upstreamSocket.pause();

			proxySocket.drainHandler(v -> {
				if (upstreamSocket != null) {
					log.trace("Proxy socket write queue drain, resume upstream reading");
					upstreamSocket.resume();
				}
			});
		}

		return future;
	}

	private void proxyHandler(Buffer buffer) {
		log.trace("Connection {} got {} bytes data from proxy socket {}",
				id, buffer.length(), proxySocket.remoteAddress());

		lastReceiveTimestamp = System.currentTimeMillis();

		int pos = 0;
		int remaining = buffer.length();

		if (stickyBuffer != null) {
			if (stickyBuffer.length() < Packet.HEADER_BYTES) {
				int rs = Packet.HEADER_BYTES - stickyBuffer.length();
				if (remaining < rs) {
					stickyBuffer.appendBuffer(buffer, pos, remaining);
					return;
				}

				stickyBuffer.appendBuffer(buffer, pos, rs);
				pos += rs;
				remaining -= rs;
			}

			int packetSize = stickyBuffer.getUnsignedShort(0);
			if (packetSize < Packet.HEADER_BYTES) {
				// noinspection LoggingSimilarMessage
				log.error("Connection {} got malformed packet (declared size {}) from proxy socket {}",
						id, packetSize, proxySocket.remoteAddress());
				close();
				return;
			}

			int rs = packetSize - stickyBuffer.length();
			if (remaining < rs) {
				stickyBuffer.appendBuffer(buffer, pos, remaining);
				return;
			}

			stickyBuffer.appendBuffer(buffer, pos, rs);
			pos += rs;
			remaining -= rs;

			packetHandler(stickyBuffer);
			stickyBuffer = null;

			if (state == State.Closed)
				return;
		}

		while (remaining > 0) {
			if (remaining < Packet.HEADER_BYTES) {
				stickyBuffer = Buffer.buffer();
				stickyBuffer.appendBuffer(buffer, pos, remaining);
				return;
			}

			int packetSize = buffer.getUnsignedShort(pos);
			if (packetSize < Packet.HEADER_BYTES) {
				// noinspection LoggingSimilarMessage
				log.error("Connection {} got malformed packet (declared size {}) from proxy socket {}",
						id, packetSize, proxySocket.remoteAddress());
				close();
				return;
			}

			if (remaining < packetSize) {
				stickyBuffer = Buffer.buffer(packetSize);
				stickyBuffer.appendBuffer(buffer, pos, remaining);
				return;
			}

			packetHandler(buffer.slice(pos, pos + packetSize));
			pos += packetSize;
			remaining -= packetSize;

			if (state == State.Closed)
				return;
		}
	}

	private void packetHandler(Buffer packet) {
		PacketType type;

		if (state == State.Initializing) {
			type = PacketType.CHALLENGE;
		} else {
			try {
				type = Packet.getType(packet);
			} catch (MalformedPacketException e) {
				if (log.isDebugEnabled())
					log.error("Connection {} got malformed packet from proxy socket {}: {}",
							id, proxySocket.remoteAddress(), e.getMessage(), e);
				else
					log.error("Connection {} got malformed packet from proxy socket {}: {}",
							id, proxySocket.remoteAddress(), e.getMessage());

				close();
				return;
			}
		}

		log.trace("Connection {} got {} packet({} bytes) from proxy socket {}",
				id, type, packet.length(), proxySocket.remoteAddress());

		if (!state.accept(type)) {
			log.error("Connection {} cannot accept {} packet in {} state", id, type, state);
			close();
			return;
		}

		try {
			switch (type) {
				case CHALLENGE -> handleChallenge(Packet.Challenge.decode(packet));
				case AUTH_ACK -> handleAuthAck(Packet.AuthAck.decode(packet, peerContext));
				case ATTACH_ACK -> handleAttachAck(Packet.AttachAck.decode(packet));
				case PING_ACK -> handlePingAck(Packet.PingAck.decode(packet));
				case CONNECT -> handleConnect(Packet.Connect.decode(packet, requireInitialized(sessionContext, "sessionContext")));
				case DATA -> handleData(Packet.Data.decode(packet, requireInitialized(sessionContext, "sessionContext")));
				case DISCONNECT -> handleDisconnect(Packet.Disconnect.decode(packet));
				case DISCONNECT_ACK -> handleDisconnectAck(Packet.DisconnectAck.decode(packet));
				default -> log.error("INTERNAL ERROR: Connection {} got wrong {} packet in {} state", id, type, state);
			}
		} catch (MalformedPacketException e) {
			if (log.isDebugEnabled())
				log.error("Connection {} got invalid {} packet from proxy socket {}", id, type, proxySocket.remoteAddress(), e);
			else
				log.error("Connection {} got invalid {} packet from proxy socket {}", id, type, proxySocket.remoteAddress());

			close();
		}
	}

	private void handleChallenge(Packet.Challenge packet) {
		handler.challenge(this, packet.challenge());
	}

	private void handleAuthAck(Packet.AuthAck packet) {
		this.sessionContext = handler.authenticated(this, packet.serverSessionPk(), packet.maxConnections(),
				packet.nameAccess(), packet.endpoint(), packet.namedEndpoint());
		state = State.Idling;
		handler.open(this);
	}

	private void handleAttachAck(@SuppressWarnings("unused") Packet.AttachAck packet) {
		state = State.Idling;
		handler.open(this);
	}

	private void handlePingAck(@SuppressWarnings("unused")Packet.PingAck packet) {
	}

	private void handleConnect(Packet.Connect packet) {
		if (!handler.allow(packet.address(), packet.port())) {
			sendConnectAck(false);
			return;
		}

		state = State.Connecting;
		// Reset the disconnect handshake count at the start of a new relay cycle. Doing this here
		// (rather than in the async callback below) ensures a DISCONNECT that races the upstream
		// CONNECT keeps its confirmation instead of having it wiped by a late callback.
		disconnectConfirms = 0;
		vertxContext.runOnContext(v -> handler.busy(this));
		log.debug("Connection {} connecting to the upstream...", id);
		handler.connectUpstream().andThen(ar -> {
			if (ar.succeeded()) {
				NetSocket socket = ar.result();
				log.debug("Connection {} connected to the upstream: {}", id, socket.remoteAddress());
				connectUpstream(socket);
			} else {
				state = State.Idling;
				vertxContext.runOnContext(v -> handler.idle(this));
				log.error("Connection {} failed to connect to upstream: {}", id, ar.cause().getMessage());
			}
			sendConnectAck(ar.succeeded());
		});
	}

	private void handleData(Packet.Data packet) {
		if (state != State.Relaying) {
			log.trace("Connection {} dropping DATA packet from proxy socket because the connection is not in the relaying state", id);
			return;
		}

		final NetSocket upstreamSocket = requireInitialized(this.upstreamSocket, "upstreamSocket");
		upstreamSocket.write(Buffer.buffer(packet.data())).andThen(ar -> {
			if (ar.succeeded()) {
				log.trace("Connection {} sent {} bytes data to upstream", id, packet.data().length);
			} else {
				log.error("Connection {} failed to write data to upstream: {}", id, ar.cause().getMessage());
				upstreamSocket.close();
			}
		});

		// Flow control for the proxy to the upstream
		if (upstreamSocket.writeQueueFull()) {
			log.trace("Upstream write queue full, pause proxy reading");
			proxySocket.pause();
			upstreamSocket.drainHandler(v-> proxySocket.resume());
		}
	}

	private void handleDisconnect(@SuppressWarnings("unused") Packet.Disconnect packet) {
		// disconnected from the client side before connected to the upstream.
		// - assume the upstream is disconnected
		//   - increment the disconnectConfirms
		//   - send disconnect
		// - change the state to disconnecting
		if (state == State.Connecting && upstreamSocket == null) {
			confirmDisconnect();
			sendDisconnect();
		}

		state = State.Disconnecting;
		disconnectUpstream();
		sendDisconnectAck();
	}

	private void handleDisconnectAck(@SuppressWarnings("unused") Packet.DisconnectAck packet) {
		disconnectUpstream();
	}

	private void upstreamSocketEndHandler(Void unused) {
		log.debug("Connection {} upstream ended.", id);
		sendDisconnect().onComplete(ar -> {
			state = State.Disconnecting;

			proxySocket.drainHandler(null);
			proxySocket.resume();

			disconnectUpstream();
		});
	}

	private void upstreamSocketExceptionHandler(Throwable t) {
		if (log.isDebugEnabled())
			log.error("Connection {} upstream socket error", id, t);
		else
			log.error("Connection {} upstream socket error: {}", id, t.getMessage());

		if (upstreamSocket != null) {
			upstreamSocket.close();
			upstreamSocket = null;
		}
	}

	private void upstreamDataHandler(Buffer data) {
		if (state != State.Relaying) {
			log.trace("Connection {} dropping data from upstream because the connection is not in the relaying state", id);
			return;
		}

		sendData(data.getBytes());
	}

	private void connectUpstream(NetSocket upstreamSocket) {
		if (state == State.Connecting) {
			state = State.Relaying;

			this.upstreamSocket = upstreamSocket;

			upstreamSocket.endHandler(this::upstreamSocketEndHandler);
			upstreamSocket.exceptionHandler(this::upstreamSocketExceptionHandler);
			upstreamSocket.handler(this::upstreamDataHandler);
		} else {
			// disconnected from the client side before connected to the upstream.
			// close and drop the upstream socket, keep the status no change
			log.debug("Connection {} dropped the upstream socket in {} state", id, state);
			upstreamSocket.close();
		}
	}

	/**
	 * Closes the upstream socket (if still open) and records one step of the disconnect handshake via
	 * {@link #confirmDisconnect()}.
	 */
	private void disconnectUpstream() {
		if (upstreamSocket != null) {
			upstreamSocket.close();
			upstreamSocket = null;
		}

		confirmDisconnect();
	}

	/**
	 * Records one disconnect confirmation and, once {@link #DISCONNECT_CONFIRMS} have been observed,
	 * returns the connection to {@link State#Idling} so it can be reused for the next {@code CONNECT}.
	 *
	 * @implNote A relayed connection is fully torn down only after three confirmations are observed:
	 *           the local upstream end, the {@code DISCONNECT} from the super node, and the matching
	 *           {@code DISCONNECT_ACK}. Every contributing path funnels through this single method;
	 *           reaching {@link #DISCONNECT_CONFIRMS} transitions back to {@link State#Idling}. The
	 *           counter is reset to {@code 0} when a new {@code CONNECT} cycle starts (see
	 *           {@link #handleConnect}), so an aborted CONNECT cannot leak a stale count into the next
	 *           cycle.
	 */
	private void confirmDisconnect() {
		if (++disconnectConfirms == DISCONNECT_CONFIRMS) {
			log.trace("Connection {} disconnect confirmed, changing state to idle", id);
			state = State.Idling;
			disconnectConfirms = 0;
			vertxContext.runOnContext(v -> handler.idle(this));
		}
	}

	protected void healthCheck() {
		long now = System.currentTimeMillis();
		if (now - lastReceiveTimestamp >= MAX_KEEP_ALIVE_RETRY * KEEP_ALIVE_INTERVAL) {
			log.warn("Connection {} keep alive timeout, close now", id);
			close();
			return;
		}

		int randomShift = Random.random().nextInt(10000); // max 10 seconds
		if ((now - lastReceiveTimestamp) >= (KEEP_ALIVE_INTERVAL - randomShift))
			sendPing();
	}

	public Future<Void> close(boolean silent) {
		if (state == State.Closed)
			return Future.succeededFuture();

		state = State.Closed;

		// just close the sockets without handle close futures
		if (upstreamSocket != null) {
			upstreamSocket.handler(null);
			upstreamSocket.endHandler(null);
			upstreamSocket.exceptionHandler(null);
			upstreamSocket.close().onComplete(ar -> {
				if (ar.succeeded())
					log.debug("Connection {} upstream socket closed", id);
				else
					log.error("Connection {} upstream socket close failed", id, ar.cause());
			});
			upstreamSocket = null;
		}

		proxySocket.handler(null);
		proxySocket.endHandler(null);
		proxySocket.exceptionHandler(null);
		proxySocket.close().onComplete(ar -> {
			if (ar.succeeded())
				log.debug("Connection {} proxy socket closed", id);
			else
				log.error("Connection {} proxy socket close failed", id, ar.cause());
		});

		log.debug("Connection {} closed", id);

		stickyBuffer = null;

		if (!silent)
			vertxContext.runOnContext(v -> handler.close(this));

		return Future.succeededFuture();
	}

	public Future<Void> close() {
		return close(false);
	}

	private static <T> T requireInitialized(@Nullable T obj, String name) {
		return Objects.requireNonNull(obj, "INTERNAL ERROR: inconsistent state - " + name + " not initialized");
	}
}