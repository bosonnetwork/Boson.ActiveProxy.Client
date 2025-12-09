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

import io.vertx.core.Context;
import io.vertx.core.Future;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.net.NetSocket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.bosonnetwork.CryptoContext;
import io.bosonnetwork.Id;
import io.bosonnetwork.crypto.CryptoBox;
import io.bosonnetwork.crypto.Random;

@SuppressWarnings("UnusedReturnValue")
public class ProxyConnection {
	private static final int KEEP_ALIVE_INTERVAL = 60000;
	private static final int MAX_KEEP_ALIVE_RETRY = 3;

	private final int id;
	private Context vertxContext;
	private CryptoContext peerContext;
	private CryptoContext sessionContext;
	private ProxyConnectionHandler handler;

	private NetSocket proxySocket;
	private NetSocket upstreamSocket;

	private State state;
	private Buffer stickyBuffer;

	private long lastReceiveTimestamp;
	private int disconnectConfirms;

	private static final Logger log = LoggerFactory.getLogger(ProxyConnection.class);

	private enum State {
		Initializing {
			@Override
			public boolean accept(PacketType type) {
				return type == PacketType.CHALLENGE;
			}
		},
		Authenticating {
			@Override
			public boolean accept(PacketType type) {
				return type == PacketType.AUTH_ACK;
			}
		},
		Attaching {
			@Override
			public boolean accept(PacketType type) {
				return type == PacketType.ATTACH_ACK;
			}
		},
		Idling {
			@Override
			public boolean accept(PacketType type) {
				return type == PacketType.PING_ACK || type == PacketType.CONNECT;
			}
		},
		Connecting {
			@Override
			public boolean accept(PacketType type) {
				return type == PacketType.PING_ACK || type == PacketType.DISCONNECT;
			}
		},
		Relaying {
			@Override
			public boolean accept(PacketType type) {
				return type == PacketType.DATA || type == PacketType.DISCONNECT || type == PacketType.PING_ACK;
			}
		},
		Disconnecting {
			@Override
			public boolean accept(PacketType type) {
				return type == PacketType.DISCONNECT || type == PacketType.DISCONNECT_ACK ||
						type == PacketType.DATA || type == PacketType.PING_ACK;
			}
		},
		Closed {
			@Override
			public boolean accept(PacketType type) {
				return false;
			}
		};

		public abstract boolean accept(PacketType type);
	}

	protected ProxyConnection(int id, Context vertxContext, CryptoContext peerContext, CryptoContext sessionContext,
							  NetSocket proxySocket, ProxyConnectionHandler handler) {
		this.id = id;
		this.vertxContext = vertxContext;
		this.peerContext = peerContext;
		this.sessionContext = sessionContext;
		this.handler = handler;
		this.state = State.Initializing;

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
	public int getId() {
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
		Packet.Data dat = new Packet.Data(data);
		Future<Void> future = sendPacket(PacketType.DATA, dat.encode(sessionContext));

		// Flow control for the upstream to the proxy
		if (proxySocket.writeQueueFull()) {
			log.trace("Proxy socket write queue full, pause upstream reading");
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
		}

		while (remaining > 0) {
			if (remaining < Packet.HEADER_BYTES) {
				stickyBuffer = Buffer.buffer();
				stickyBuffer.appendBuffer(buffer, pos, remaining);
				return;
			}

			int packetSize = buffer.getUnsignedShort(pos);
			if (remaining < packetSize) {
				stickyBuffer = Buffer.buffer(packetSize);
				stickyBuffer.appendBuffer(buffer, pos, remaining);
				return;
			}

			packetHandler(buffer.slice(pos, pos + packetSize));
			pos += packetSize;
			remaining -= packetSize;
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
			log.error("Connection {} can not accept {} packet in {} state", id, type, state);
			close();
			return;
		}

		try {
			switch (type) {
				case CHALLENGE -> HandleChallenge(Packet.Challenge.decode(packet));
				case AUTH_ACK -> handleAuthAck(Packet.AuthAck.decode(packet, peerContext));
				case ATTACH_ACK -> handleAttachAck(Packet.AttachAck.decode(packet));
				case PING_ACK -> handlePingAck(Packet.PingAck.decode(packet));
				case CONNECT -> handleConnect(Packet.Connect.decode(packet, sessionContext));
				case DATA -> handleData(Packet.Data.decode(packet, sessionContext));
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

	private void HandleChallenge(Packet.Challenge packet) {
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
		vertxContext.runOnContext(v -> handler.busy(this));
		log.debug("Connection {} connecting to the upstream...", id);
		handler.connectUpstream().andThen(ar -> {
			disconnectConfirms = 0;

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
			log.trace("Connection {} got DATA packet from proxy socket not in relaying state, ignore.", id);
			return;
		}

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
			upstreamSocket.drainHandler(v-> {
				if (proxySocket != null)
					proxySocket.resume();
			});
		}
	}

	private void handleDisconnect(@SuppressWarnings("unused") Packet.Disconnect packet) {
		// disconnected from the client side before connected to the upstream.
		// - assume the upstream is disconnected
		//   - increment the disconnectConfirms
		//   - send disconnect
		// - change the state to disconnecting
		if (state == State.Connecting && upstreamSocket == null) {
			disconnectConfirms++;
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

			upstreamSocket.close(); // safe; idempotent
			upstreamSocket = null;
			disconnectUpstream();
		});
	}

	private void upstreamSocketExceptionHandler(Throwable t) {
		if (log.isDebugEnabled())
			log.error("Client socket error", t);
		else
			log.error("Client socket error: {}", t.getMessage());

		upstreamSocket.close();
	}

	private void upstreamDataHandler(Buffer data) {
		if (state != State.Relaying) {
			log.trace("Connection {} dropping data from upstream due the connection not in relaying state.", id);
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

	private void disconnectUpstream() {
		if (upstreamSocket != null)
			upstreamSocket.close();

		if (++disconnectConfirms == 3) {
			log.trace("Connection {} disconnect confirmed, change state to idle.", id);
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
			upstreamSocket.close();
			upstreamSocket = null;
		}

		if (proxySocket != null) {
			proxySocket.handler(null);
			proxySocket.endHandler(null);
			proxySocket.exceptionHandler(null);
			proxySocket.close();
			proxySocket = null;
		}

		log.debug("Connection {} closed", id);
		if (!silent)
			vertxContext.runOnContext(v -> handler.close(this));

		vertxContext = null;
		peerContext = null;
		sessionContext = null;
		handler = null;
		stickyBuffer = null;

		return Future.succeededFuture();
	}

	public Future<Void> close() {
		return close(false);
	}
}