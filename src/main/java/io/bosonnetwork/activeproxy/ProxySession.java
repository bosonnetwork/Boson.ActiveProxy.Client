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
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.net.NetClient;
import io.vertx.core.net.NetClientOptions;
import io.vertx.core.net.NetSocket;
import io.vertx.core.net.SocketAddress;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.bosonnetwork.CryptoContext;
import io.bosonnetwork.Id;
import io.bosonnetwork.Node;
import io.bosonnetwork.PeerInfo;
import io.bosonnetwork.crypto.CryptoBox;
import io.bosonnetwork.crypto.CryptoException;
import io.bosonnetwork.crypto.CryptoIdentity;
import io.bosonnetwork.vertx.BosonVerticle;

class ProxySession extends BosonVerticle {
	private static final int PERIODIC_CHECK_INTERVAL = 15 * 1000;       // 15 seconds
	private static final int IDLE_CHECK_INTERVAL = 60 * 1000;           // 1 minute
	private static final int STOP_DELAY = 5 * 1000;                     // 5 seconds
	private static final int RE_ANNOUNCE_INTERVAL = 60 * 60 * 1000;     // 60 minutes
	private static final int MAX_IDLE_TIME = 5 * 60 * 1000;             // 5 minutes
	private static final int PROXY_SOCKET_CONNECT_TIMEOUT = 16000;      // 16 seconds
	private static final int PROXY_SOCKET_IDLE_TIMEOUT = 120;           // 120 seconds
	private static final int UPSTREAM_SOCKET_CONNECT_TIMEOUT = 8000;    // 8 seconds
	private static final int UPSTREAM_SOCKET_IDLE_TIMEOUT = 60;         // 60 seconds
	private static final int SEND_BUFFER_SIZE = 0x7FFF;
	private static final int RECEIVE_BUFFER_SIZE = 0x7FFF - Packet.HEADER_BYTES - CryptoBox.Nonce.BYTES - CryptoBox.MAC_BYTES;

	private final Id servicePeerId;

	private final @Nullable Node node;
	private final Configuration config;

	private final Id userId;
	private final CryptoIdentity deviceIdentity;
	private @Nullable SocketAddress serviceAddress;
	private final SocketAddress upstreamAddress;

	private volatile boolean nameAccessEnabled;
	private volatile @Nullable String endpoint;
	private volatile @Nullable String namedEndpoint;
	private @Nullable PeerInfo peerInfo;

	// Proxy and upstream with different buffer size, so should not share the same NetClient
	private @Nullable NetClient proxyClient;
	private @Nullable NetClient upstreamClient;
	private CryptoBox.@Nullable KeyPair clientSessionKeyPair;
	private final CryptoContext peerContext;
	private @Nullable CryptoContext sessionContext;

	private final ProxyConnectionHandler connectionHandler;

	private volatile @Nullable ConnectionStatusListener connectionStatusListener;

	private volatile boolean connected;
	private long nextConnectionId;
	private int maxConnections;
	private int connectFailures;
	private int pendingConnects;	// connections currently being dialed but not yet established
	private final ConnectionRegistry<ProxyConnection> connections;

	private long periodicCheckTimer;
	private volatile boolean running;
	private long danglingTimestamp;
	private long idleTimestamp;
	private long lastAnnounceTimestamp;
	private long lastIdleCheckTimestamp;

	private static final Logger log = LoggerFactory.getLogger(ProxySession.class);

	protected ProxySession(@Nullable Node node, Configuration config) {
		if (node == null && config.getServiceHost() == null)
			throw new IllegalArgumentException("Either node or service host must be specified");

		this.node = node;
		this.config = config;

		this.userId = config.getUserId();
		this.deviceIdentity = new CryptoIdentity(config.getDeviceKey());
		this.servicePeerId = config.getServicePeerId();
		this.upstreamAddress = SocketAddress.inetSocketAddress(config.getUpstreamPort(), config.getUpstreamHost());

		this.nextConnectionId = 0;
		this.maxConnections = 1;
		this.connections = new ConnectionRegistry<>();
		this.connected = false;
		this.connectFailures = 0;
		this.pendingConnects = 0;

		this.running = false;

		try {
			this.peerContext = deviceIdentity.createCryptoContext(servicePeerId);
		} catch (CryptoException e) {
			log.error("Failed to create peer crypto context", e);
			throw new IllegalArgumentException("Invalid config, failed to create peer context", e);
		}

		this.connectionHandler = new ProxyConnectionHandler() {
			@Override
			public void challenge(ProxyConnection connection, byte[] challenge) {
				connectionChallengeHandler(connection, challenge);
			}

			@Override
			public CryptoContext authenticated(ProxyConnection connection, CryptoBox.PublicKey serverSessionPk,
											   int maxConnections, boolean nameAccess,
											   String endpoint, @Nullable String namedEndpoint) {
				return authenticatedHandler(connection, serverSessionPk, maxConnections, nameAccess, endpoint, namedEndpoint);
			}

			@Override
			public void open(ProxyConnection connection) {
				connectionOpenHandler(connection);
			}

			@Override
			public void close(ProxyConnection connection) {
				connectionClosedHandler(connection);
			}

			@Override
			public void idle(ProxyConnection connection) {
				connectionIdleHandler(connection);
			}

			@Override
			public void busy(ProxyConnection connection) {
				connectionBusyHandler(connection);
			}

			@Override
			public boolean allow(InetAddress clientAddress, int clientPort) {
				return true;
			}

			@Override
			public Future<NetSocket> connectUpstream() {
				return requireInitialized(upstreamClient, "upstreamClient").connect(upstreamAddress);
			}
		};
	}

	public boolean isRunning() {
		return running;
	}

	public boolean isConnected() {
		return connected;
	}

	public String getEndpoint() {
		String endpoint = this.endpoint;
		if (!connected || endpoint == null)
			throw new IllegalStateException("Session is not connected");
		return endpoint;
	}

	public @Nullable String getNamedEndpoint() {
		String namedEndpoint = this.namedEndpoint;
		if (!connected)
			throw new IllegalStateException("Session is not connected");

		return namedEndpoint;
	}

	public boolean isNameAccessEnabled() {
		return nameAccessEnabled;
	}

	public void setConnectionListener(@Nullable ConnectionStatusListener listener) {
		this.connectionStatusListener = listener;
	}

	@Override
	protected Future<Void> deploy() {
		Vertx vertx = requireInitialized(this.vertx, "vertx");
		proxyClient = vertx.createNetClient(new NetClientOptions()
				.setSsl(false)
				.setConnectTimeout(PROXY_SOCKET_CONNECT_TIMEOUT)
				.setTcpKeepAlive(true)
				.setIdleTimeout(PROXY_SOCKET_IDLE_TIMEOUT)
				.setIdleTimeoutUnit(TimeUnit.SECONDS)
				.setSendBufferSize(SEND_BUFFER_SIZE));

		upstreamClient = vertx.createNetClient(new NetClientOptions()
				.setSsl(false)
				.setConnectTimeout(UPSTREAM_SOCKET_CONNECT_TIMEOUT)
				.setTcpKeepAlive(true)
				.setIdleTimeout(UPSTREAM_SOCKET_IDLE_TIMEOUT)
				.setIdleTimeoutUnit(TimeUnit.SECONDS)
				.setReceiveBufferSize(RECEIVE_BUFFER_SIZE));

		lastIdleCheckTimestamp = System.currentTimeMillis();
		periodicCheckTimer = vertx.setPeriodic(PERIODIC_CHECK_INTERVAL, this::periodicCheck);

		running = true;
		return connect().andThen(ar -> {
			if (ar.succeeded()) {
				vertx.cancelTimer(periodicCheckTimer);
				periodicCheckTimer = 0;
				log.debug("Proxy session {} started", servicePeerId);
			} else {
				running = false;
				log.error("Proxy session {} failed to start", servicePeerId, ar.cause());
			}
		});
	}

	@Override
	protected Future<Void> undeploy() {
		if (!running)
			return Future.succeededFuture();

		Vertx vertx = requireInitialized(this.vertx, "vertx");
		NetClient proxyClient = requireInitialized(this.proxyClient, "proxyClient");
		NetClient upstreamClient = requireInitialized(this.upstreamClient, "upstreamClient");

		log.debug("Stopping proxy session {}", servicePeerId);
		running = false;

		vertx.cancelTimer(periodicCheckTimer);

		List.copyOf(connections.connections()).forEach(c -> c.close(true));
		connections.clear();

		if (connected) {
			connected = false;
			endpoint = null;
			namedEndpoint = null;
			runOnContext(unused -> {
				ConnectionStatusListener listener = connectionStatusListener;
				if (listener != null)
					listener.disconnected();
			});
		}

		return Future.join(proxyClient.close(), upstreamClient.close())
				.andThen(ar -> {
					this.proxyClient = null;
					this.upstreamClient = null;

					if (ar.succeeded())
						log.debug("Proxy session {} stopped", servicePeerId);
					else
						log.error("Proxy session {} failed to stop", servicePeerId, ar.cause());
				}).mapEmpty();
	}

	private void periodicCheck(@SuppressWarnings("unused") long timerId) {
		tryCloseIdleConnections();
		healthCheck();
		tryAnnouncePeer();
	}

	private void tryCloseIdleConnections() {
		long now = System.currentTimeMillis();
		if (now - lastIdleCheckTimestamp < IDLE_CHECK_INTERVAL)
			return;

		lastIdleCheckTimestamp = now;
		log.info("STATUS: session={}, connections={}, inFlight={}, idleTime={}",
				servicePeerId, connections.size(), connections.inFlight(),
				idleTimestamp == 0 ? 0 : Duration.ofMillis(now - idleTimestamp));

		if (connections.inFlight() != 0 || idleTimestamp == 0 || connections.size() <= 1 || now - idleTimestamp < MAX_IDLE_TIME)
			return;

		log.info("Session {} closing the idle connections...", servicePeerId);
		// All connections are idle here (inFlight == 0); keep one and close the rest.
		List<ProxyConnection> idle = List.copyOf(connections.connections());
		for (int i = 1; i < idle.size(); i++) {
			ProxyConnection c = idle.get(i);
			connections.remove(c);
			c.close(true);
		}
	}

	private void healthCheck() {
		List<ProxyConnection> cs = List.copyOf(connections.connections());
		cs.forEach(ProxyConnection::healthCheck);
	}

	private void tryAnnouncePeer() {
		long now = System.currentTimeMillis();
		if (node == null || peerInfo == null || now - lastAnnounceTimestamp < RE_ANNOUNCE_INTERVAL)
			return;

		log.info("Session {} announcing peer info {} ...", servicePeerId, peerInfo);
		node.announcePeer(peerInfo).thenRun(() -> {
			log.info("Session {} peer info announced", servicePeerId);
			lastAnnounceTimestamp = now;
		}).exceptionally(e -> {
			log.error("Session {} failed to announce peer info", servicePeerId, e);
			// retry after 1 minute
			lastAnnounceTimestamp = now - RE_ANNOUNCE_INTERVAL + 60000;
			return null;
		});
	}

	private void reset() {
		connected = false;
		endpoint = null;
		namedEndpoint = null;
		danglingTimestamp = 0;
	}

	private boolean needsNewConnection() {
		if (!running)
			return false;

		// Count in-flight dials against the ceiling so concurrent busy/close handlers cannot
		// over-provision past maxConnections while a CONNECT is still pending.
		if (connections.size() + pendingConnects >= maxConnections)
			return false;

		// A new connection is needed only when there is no idle (or pending) spare ready to serve the
		// next CONNECT. Idle established = connections.size() - inFlight; pending dials will become
		// idle once established.
		int spares = (connections.size() - connections.inFlight()) + pendingConnects;
		return spares == 0;
	}

	private Future<SocketAddress> resolveServicePeer() {
		if (config.getServiceHost() == null || config.getServicePort() == 0) {
			Node node = requireInitialized(this.node, "node");
			log.info("Looking up service peer {} ...", config.getServicePeerId());
			return Future.fromCompletionStage(node.findPeer(config.getServicePeerId())).compose(p -> {
				if (p.isEmpty()) {
					log.error("Service peer not found {}", config.getServicePeerId());
					return Future.failedFuture("Service peer not found: " + config.getServicePeerId());
				}

				PeerInfo peer = p.get();
				URI uri = URI.create(peer.getEndpoint());
				if (!uri.getScheme().equals("tcp") || uri.getPort() <= 0) {
					log.error("Service peer endpoint {} is invalid", peer.getEndpoint());
					return Future.failedFuture("Service peer endpoint is invalid: " + peer.getEndpoint());
				}

				SocketAddress addr = SocketAddress.inetSocketAddress(uri.getPort(), uri.getHost());
				return Future.succeededFuture(addr);
			});
		} else {
			SocketAddress addr = SocketAddress.inetSocketAddress(config.getServicePort(), config.getServiceHost());
			return Future.succeededFuture(addr);
		}
	}

	private Future<Void> connect() {
		Vertx vertx = requireInitialized(this.vertx, "vertx");
		// Count this dial as pending until it settles, so needsNewConnection() won't launch a
		// redundant CONNECT (or exceed maxConnections) while it is in flight.
		pendingConnects++;
		return resolveServicePeer().compose(addr -> {
			this.serviceAddress = addr;
			log.debug("Creating new proxy connection to service {}@{} ...", servicePeerId, serviceAddress);
			return requireInitialized(proxyClient, "proxyClient").connect(serviceAddress);
		}).andThen(ar -> {
			pendingConnects--;
			if (ar.succeeded()) {
				long connectionId = nextConnectionId++;
				log.info("Created new proxy connection {} to service {}@{}", connectionId, servicePeerId, serviceAddress);
				ProxyConnection connection = new ProxyConnection(connectionId,
						requireInitialized(vertxContext, "vertxContext"), peerContext, sessionContext, ar.result(), connectionHandler);
				connections.add(connection);	// starts idle until it relays
			} else {
				connectFailures++;
				if (log.isDebugEnabled())
					log.error("Create new proxy connection to service {}@{} failed({})",
							servicePeerId, serviceAddress, connectFailures, ar.cause());
				else
					log.error("Create new proxy connection to service {}@{} failed({}): {}",
							servicePeerId, serviceAddress, connectFailures, ar.cause().getMessage());

				if (running) {
					int reconnectDelay = Math.min(connectFailures * 5, 60) * 1000;
					vertx.setTimer(reconnectDelay, unused -> {
						if (needsNewConnection())
							connect();
					});
				}
			}
		}).mapEmpty();
	}

	private void connectionChallengeHandler(ProxyConnection connection, byte[] challenge) {
		byte[] deviceSig = deviceIdentity.sign(challenge);

		if (!connected) {
			clientSessionKeyPair = CryptoBox.KeyPair.random();
			connection.sendAuth(userId, deviceIdentity.getId(), clientSessionKeyPair.publicKey(),
					config.isNameAccessEnabled(), deviceSig, peerContext);
		} else {
			CryptoBox.KeyPair sessionKeyPair = requireInitialized(this.clientSessionKeyPair, "clientSessionKeyPair");
			connection.sendAttach(deviceIdentity.getId(), sessionKeyPair.publicKey(), deviceSig, peerContext);
		}
	}

	private CryptoContext authenticatedHandler(@SuppressWarnings("unused") ProxyConnection connection,
									  CryptoBox.PublicKey serverSessionPk, int maxConnections,
									  boolean nameAccess, String endpoint, @Nullable String namedEndpoint) {
		CryptoBox.KeyPair sessionKeyPair = requireInitialized(this.clientSessionKeyPair, "clientSessionKeyPair");

		this.maxConnections = maxConnections;
		this.nameAccessEnabled = nameAccess;
		this.endpoint = config.getUpstreamScheme() + endpoint;
		this.namedEndpoint = namedEndpoint == null ? null : config.getUpstreamScheme() + namedEndpoint;
		this.sessionContext = new CryptoContext(servicePeerId, serverSessionPk, sessionKeyPair.privateKey());
		this.connected = true;
		log.info("Proxy session {} authenticated, max connections: {}, endpoint: {}, named endpoint: {}",
				servicePeerId, maxConnections, endpoint, namedEndpoint != null ? namedEndpoint : "N/A");

		if (config.isAnnouncePeer()) {
			PeerInfo.Builder pb = PeerInfo.builder()
					.key(config.getDeviceKey());
			if (node != null)
				pb.node(node);
			if (namedEndpoint != null) {
				pb.endpoint(namedEndpoint);
				pb.extra(Map.of("altEndpoint", endpoint));
			} else {
				pb.endpoint(endpoint);
			}
			this.peerInfo = pb.build();

			tryAnnouncePeer();
		}

		runOnContext(unused -> {
			ConnectionStatusListener listener = connectionStatusListener;
			if (listener != null)
				listener.connected();
		});

		return sessionContext;
	}

	private void connectionOpenHandler(@SuppressWarnings("unused") ProxyConnection connection) {
		connectFailures = 0;
		danglingTimestamp = 0;
	}

	private void connectionClosedHandler(ProxyConnection connection) {
		Vertx vertx = requireInitialized(this.vertx, "vertx");
		connections.remove(connection);	// keeps inFlight accurate even if torn down while relaying
		if (connections.isEmpty()) {
			log.warn("Proxy session {} is dangling ...", servicePeerId);
			danglingTimestamp = System.currentTimeMillis();
			vertx.setTimer(STOP_DELAY, unused -> {
				if (danglingTimestamp > 0 && System.currentTimeMillis() - danglingTimestamp >= STOP_DELAY) {
					log.info("Proxy session {} disconnected, reset session to reconnect", servicePeerId);
					reset();
					runOnContext(v -> {
						ConnectionStatusListener listener = connectionStatusListener;
						if (listener != null)
							listener.disconnected();
					});
				}
			});
		}

		if (needsNewConnection())
			connect();
	}

	private void connectionIdleHandler(ProxyConnection connection) {
		if (connections.markIdle(connection) && connections.inFlight() == 0)
			idleTimestamp = System.currentTimeMillis();
	}

	private void connectionBusyHandler(ProxyConnection connection) {
		connections.markBusy(connection);
		idleTimestamp = 0;
		if (needsNewConnection())
			connect();
	}

	public Future<Void> close() {
		if (running)
			throw new IllegalStateException("Proxy session is still running");

		connectionStatusListener = null;

		if (sessionContext != null) {
			sessionContext.close();
			sessionContext = null;
		}

		peerContext.close();

		if (clientSessionKeyPair != null) {
			clientSessionKeyPair.privateKey().destroy();
			clientSessionKeyPair = null;
		}

		deviceIdentity.destroy();

		log.debug("Proxy session {} closed", servicePeerId);
		return Future.succeededFuture();
	}

	private static <T> T requireInitialized(@Nullable T obj, String name) {
		return Objects.requireNonNull(obj, "INTERNAL ERROR: inconsistent state - " + name + " not initialized");
	}
}