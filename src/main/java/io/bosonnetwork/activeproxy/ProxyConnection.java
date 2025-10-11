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
				return type == PacketType.CHALLENGE || type == PacketType.PING_ACK;
			}
		},
		Authenticating {
			@Override
			public boolean accept(PacketType type) {
				return type == PacketType.AUTH_ACK || type == PacketType.PING_ACK;
			}
		},
		Attaching {
			@Override
			public boolean accept(PacketType type) {
				return type == PacketType.ATTACH_ACK || type == PacketType.PING_ACK;
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
		proxySocket.closeHandler(v -> close());
		proxySocket.exceptionHandler(v -> close());
		proxySocket.handler(this::proxyHandler);
	}

	@SuppressWarnings("unused")
	public int getId() {
		return id;
	}

	protected Future<Void> sendAuth(Id userId, Id deviceId, CryptoBox.PublicKey clientSessionPk, boolean nameAccess,
						 byte[] userSig, byte[] deviceSig, CryptoContext peerContext) {
		state = State.Authenticating;
		Packet.Auth auth = new Packet.Auth(Packet.VERSION, userId, deviceId, clientSessionPk, nameAccess, userSig, deviceSig);
		return proxySocket.write(auth.encode(peerContext)).andThen(ar -> {
			if (ar.failed())
				close();
		});
	}

	protected Future<Void> sendAttach(Id deviceId, CryptoBox.PublicKey clientSessionPk, byte[] deviceSig, CryptoContext peerContext) {
		state = State.Attaching;
		Packet.Attach attach = new Packet.Attach(deviceId, clientSessionPk, deviceSig);
		return proxySocket.write(attach.encode(peerContext)).andThen(ar -> {
			if (ar.failed())
				close();
		});
	}

	private Future<Void> sendPingRequest() {
		return proxySocket.write(Packet.Ping.encode()).andThen(ar -> {
			if (ar.failed())
				close();
		});
	}

	private Future<Void> sendConnectAck(boolean succeeded) {
		Packet.ConnectAck ack = Packet.ConnectAck.of(succeeded);
		return proxySocket.write(ack.encode()).andThen(ar -> {
			if (ar.failed())
				close();
		});
	}

	private Future<Void> sendDisconnect() {
		return proxySocket.write(Packet.Disconnect.encode()).andThen(ar -> {
			if (ar.failed())
				close();
		});
	}

	private Future<Void> sendDisconnectAck() {
		return proxySocket.write(Packet.DisconnectAck.encode()).andThen(ar -> {
			if (ar.failed())
				close();
		});
	}

	private Future<Void> sendData(byte[] data) {
		Packet.Data packet = new Packet.Data(data);
		Future<Void> future = proxySocket.write(packet.encode(sessionContext)).andThen(ar -> {
			if (ar.failed())
				close();
		});

		// Flow control for the upstream to the proxy
		if (proxySocket.writeQueueFull()) {
			log.trace("Proxy socket write queue full, pause upstream reading");
			upstreamSocket.pause();
			proxySocket.drainHandler(v -> {
				if (upstreamSocket != null)
					upstreamSocket.resume();
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
		handler.authenticated(this, packet.serverSessionPk(), packet.maxConnections(),
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
		handler.connectUpstream().andThen(ar -> {
			disconnectConfirms = 0;

			if (ar.succeeded()) {
				log.debug("Connection {} connected to the upstream: {}", id, upstreamSocket.remoteAddress());
				connectUpstream(ar.result());
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

		upstreamSocket.write(Buffer.buffer(packet.data()));
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

	private void upstreamSocketCloseHandler(Void unused) {
		log.debug("Connection {} disconnected upstream.", id);
		state = State.Disconnecting;

		proxySocket.drainHandler(null);
		proxySocket.resume();

		upstreamSocket = null;
		sendDisconnect();
		disconnectUpstream();
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

			upstreamSocket.closeHandler(this::upstreamSocketCloseHandler);
			upstreamSocket.exceptionHandler(this::upstreamSocketExceptionHandler);
			upstreamSocket.handler(this::upstreamDataHandler);
		} else {
			// disconnected from the client side before connected to the upstream.
			// close and drop the upstream socket, keep the status no change
			log.warn("Connection {} dropped the upstream socket in {} state", id, state);
			upstreamSocket.close();
		}
	}

	private void disconnectUpstream() {
		if (upstreamSocket != null)
			upstreamSocket.close();

		if (++disconnectConfirms == 3) {
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
			sendPingRequest();
	}

	public Future<Void> close(boolean silent) {
		if (state == State.Closed)
			return Future.succeededFuture();

		state = State.Closed;

		// just close the sockets without handle close futures
		if (upstreamSocket != null) {
			upstreamSocket.closeHandler(null);
			upstreamSocket.exceptionHandler(null);
			upstreamSocket.handler(null);
			upstreamSocket.close();
			upstreamSocket = null;
		}

		if (proxySocket != null) {
			proxySocket.closeHandler(null);
			proxySocket.exceptionHandler(null);
			proxySocket.handler(null);
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