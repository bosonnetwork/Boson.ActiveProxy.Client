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
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import io.vertx.core.Future;
import io.vertx.core.net.NetClient;
import io.vertx.core.net.NetClientOptions;
import io.vertx.core.net.NetSocket;
import io.vertx.core.net.SocketAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.bosonnetwork.CryptoContext;
import io.bosonnetwork.Id;
import io.bosonnetwork.Identity;
import io.bosonnetwork.Node;
import io.bosonnetwork.PeerInfo;
import io.bosonnetwork.crypto.CryptoBox;
import io.bosonnetwork.crypto.CryptoException;
import io.bosonnetwork.crypto.CryptoIdentity;
import io.bosonnetwork.vertx.BosonVerticle;

public class ProxySession extends BosonVerticle {
	private static final int PERIODIC_CHECK_INTERVAL = 15 * 1000;	// 15 seconds
	private static final int IDLE_CHECK_INTERVAL = 60 * 1000;		// 1 minute
	private static final int STOP_DELAY = 5 * 1000; 				// 5 seconds
	private static final int RE_ANNOUNCE_INTERVAL = 60 * 60 * 1000;	// 60 minutes
	private static final int MAX_IDLE_TIME = 5 * 60 * 1000;			// 5 minutes

	private final Id servicePeerId;

	private Node node;
	private Configuration config;

	private Id userId;
	private Identity deviceIdentity;
	private SocketAddress serviceAddress;
	private SocketAddress upstreamAddress;

	private boolean nameAccessEnabled;
	private String endpoint;
	private String namedEndpoint;
	private PeerInfo peerInfo;

	// Proxy and upstream with different buffer size, so should not share the same NetClient
	private NetClient proxyClient;
	private NetClient upstreamClient;
	private CryptoBox.KeyPair clientSessionKeyPair;
	private CryptoContext peerContext;
	private CryptoContext sessionContext;

	private final ProxyConnectionHandler connectionHandler;

	private ConnectionStatusListener connectionStatusListener;

	private boolean connected;
	private int nextConnectionId;
	private int maxConnections;
	private int connectFailures;
	private int inFlights;
	private final Map<ProxyConnection, Boolean> connections;

	private long periodicCheckTimer;
	private volatile boolean running;
	private long danglingTimestamp;
	private long idleTimestamp;
	private long lastAnnounceTimestamp;
	private long lastIdleCheckTimestamp;

	private static final Logger log = LoggerFactory.getLogger(ProxySession.class);

	protected ProxySession(Node node, Configuration config) {
		this.node = node;
		this.config = config;

		this.userId = config.getUserId();
		this.deviceIdentity = new CryptoIdentity(config.getDeviceKey());
		this.servicePeerId = config.getServicePeerId();
		this.serviceAddress = SocketAddress.inetSocketAddress(config.getServicePort(), config.getServiceHost());
		this.upstreamAddress = SocketAddress.inetSocketAddress(config.getUpstreamPort(), config.getUpstreamHost());

		this.nextConnectionId = 0;
		this.maxConnections = 1;
		this.connections = new HashMap<>();
		this.connected = false;
		this.connectFailures = 0;
		this.inFlights = 0;

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
			public CryptoContext authenticated(ProxyConnection connection, CryptoBox.PublicKey serverSessionPk, int maxConnections, boolean nameAccess, String endpoint, String namedEndpoint) {
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
				return upstreamClient.connect(upstreamAddress);
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
		return endpoint;
	}

	public String getNamedEndpoint() {
		return namedEndpoint;
	}

	public boolean isNameAccessEnabled() {
		return nameAccessEnabled;
	}

	public void addConnectionStatusListener(ConnectionStatusListener listener) {
		assert (listener != null) : "Invalid listener";
		if (this.connectionStatusListener == null) {
			this.connectionStatusListener = listener;
		} else {
			if (this.connectionStatusListener instanceof ListenerArray listeners)
				listeners.add(listener);
			else
				this.connectionStatusListener = new ListenerArray(this.connectionStatusListener, listener);
		}
	}

	public void removeConnectionStatusListener(ConnectionStatusListener listener) {
		ConnectionStatusListener current = this.connectionStatusListener;
		if (current == listener)
			this.connectionStatusListener = null;
		else if (current instanceof ListenerArray listeners)
			listeners.remove(listener);
	}

	@Override
	protected Future<Void> deploy() {
		proxyClient = vertx.createNetClient(new NetClientOptions()
				.setSsl(false)
				.setConnectTimeout(16000)
				.setTcpKeepAlive(true)
				.setIdleTimeout(120)
				.setIdleTimeoutUnit(TimeUnit.SECONDS)
				.setSendBufferSize(0x7FFF));

		upstreamClient = vertx.createNetClient(new NetClientOptions()
				.setSsl(false)
				.setConnectTimeout(8000)
				.setTcpKeepAlive(true)
				.setIdleTimeout(60)
				.setIdleTimeoutUnit(TimeUnit.SECONDS)
				.setReceiveBufferSize(0x7FFF - Packet.HEADER_BYTES - CryptoBox.Nonce.BYTES - CryptoBox.MAC_BYTES));

		lastIdleCheckTimestamp = System.currentTimeMillis();
		periodicCheckTimer = vertx.setPeriodic(PERIODIC_CHECK_INTERVAL, this::periodicCheck);

		running = true;
		return connect();
	}

	@Override
	protected Future<Void> undeploy() {
		if (!running)
			return Future.succeededFuture();

		log.debug("Stopping proxy session {}", servicePeerId);
		running = false;

		vertx.cancelTimer(periodicCheckTimer);

		connections.keySet().forEach(c -> c.close(true));
		connections.clear();
		inFlights = 0;

		if (connected) {
			connected = false;
			endpoint = null;
			namedEndpoint = null;
			runOnContext(unused -> {
				if (connectionStatusListener != null)
					connectionStatusListener.disconnected();
			});
		}

		return Future.join(proxyClient.close(), upstreamClient.close())
				.andThen(ar -> {
					proxyClient = null;
					upstreamClient = null;

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
		log.info("STATUS: session={}, connections={}, inFlights={}, idleTime={}",
				servicePeerId, connections.size(), inFlights,
				idleTimestamp == 0 ? 0 : Duration.ofMillis(now - idleTimestamp));

		if (inFlights != 0 || idleTimestamp == 0 || connections.size() <= 1 || now - idleTimestamp < MAX_IDLE_TIME)
			return;

		log.info("Session {} closing the idle connections...", servicePeerId);
		Iterator<Map.Entry<ProxyConnection, Boolean>> iterator = connections.entrySet().iterator();
		while (connections.size() > 1 && iterator.hasNext()) {
			Map.Entry<ProxyConnection, Boolean> entry = iterator.next();
			ProxyConnection c = entry.getKey();
			iterator.remove();
			c.close(true);
		}
	}

	private void healthCheck() {
		List<ProxyConnection> cs = List.copyOf(connections.keySet());
		cs.forEach(ProxyConnection::healthCheck);
	}

	private void tryAnnouncePeer() {
		long now = System.currentTimeMillis();
		if (peerInfo == null || now - lastAnnounceTimestamp < RE_ANNOUNCE_INTERVAL)
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

		if (connections.size() >= maxConnections)
			return false;

		if (connections.isEmpty())
			return true;

		return inFlights == connections.size();
	}

	private Future<Void> connect() {
		log.debug("Creating new proxy connection to service {}@{} ...", servicePeerId, serviceAddress);
		return proxyClient.connect(serviceAddress).andThen(ar -> {
			if (ar.succeeded()) {
				int connectionId = nextConnectionId++;
				log.info("Created new proxy connection {} to service {}@{}", connectionId, servicePeerId, serviceAddress);
				ProxyConnection connection = new ProxyConnection(connectionId, vertxContext, peerContext, sessionContext, ar.result(), connectionHandler);
				connections.put(connection, Boolean.TRUE);
			} else {
				connectFailures++;
				if (log.isDebugEnabled())
					log.error("Create new proxy connection to service {}@{} failed({})",
							servicePeerId, serviceAddress, connectFailures, ar.cause());
				else
					log.error("Create new proxy connection to service {}@{} failed({}): {}",
							servicePeerId, serviceAddress, connectFailures, ar.cause().getMessage());

				if (running) {
					int reconnectDelay = Math.min((1 << connectFailures), 60) * 1000;
					vertx.setTimer(reconnectDelay, unused -> {
						if (needsNewConnection())
							connect();
					});
				}
			}
		}).otherwiseEmpty().mapEmpty();
	}

	private void connectionChallengeHandler(ProxyConnection connection, byte[] challenge) {
		byte[] deviceSig = deviceIdentity.sign(challenge);

		if (!connected) {
			clientSessionKeyPair = CryptoBox.KeyPair.random();
			connection.sendAuth(userId, deviceIdentity.getId(), clientSessionKeyPair.publicKey(),
					config.isNameAccessEnabled(), deviceSig, peerContext);
		} else {
			connection.sendAttach(deviceIdentity.getId(), clientSessionKeyPair.publicKey(), deviceSig, peerContext);
		}
	}

	private CryptoContext authenticatedHandler(@SuppressWarnings("unused") ProxyConnection connection,
									  CryptoBox.PublicKey serverSessionPk, int maxConnections,
									  boolean nameAccess, String endpoint, String namedEndpoint) {
		this.connected = true;
		this.maxConnections = maxConnections;
		this.nameAccessEnabled = nameAccess;
		this.endpoint = config.getUpstreamScheme() + endpoint;
		this.namedEndpoint = namedEndpoint == null ? null : config.getUpstreamScheme() + namedEndpoint;
		this.sessionContext = new CryptoContext(servicePeerId, serverSessionPk, clientSessionKeyPair.privateKey());
		log.info("Proxy session {} authenticated, max connections: {}, endpoint: {}, named endpoint: {}",
				servicePeerId, maxConnections, endpoint, namedEndpoint != null ? namedEndpoint : "N/A");

		if (config.isAnnouncePeer()) {
			PeerInfo.Builder pb = PeerInfo.builder()
					.key(config.getDeviceKey())
					.node(node);
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
			if (connectionStatusListener != null)
				connectionStatusListener.connected();
		});

		return sessionContext;
	}

	private void connectionOpenHandler(@SuppressWarnings("unused") ProxyConnection connection) {
		connectFailures = 0;
		danglingTimestamp = 0;
	}

	private void connectionClosedHandler(ProxyConnection connection) {
		connections.remove(connection);
		if (connections.isEmpty()) {
			log.warn("Proxy session {} is dangling ...", servicePeerId);
			danglingTimestamp = System.currentTimeMillis();
			vertx.setTimer(STOP_DELAY, unused -> {
				if (danglingTimestamp > 0 && System.currentTimeMillis() - danglingTimestamp >= STOP_DELAY) {
					log.info("Proxy session {} disconnected, reset session to reconnect", servicePeerId);
					reset();
					runOnContext(v -> {
						if (connectionStatusListener != null)
							connectionStatusListener.disconnected();
					});
				}
			});
		}

		if (needsNewConnection())
			connect();
	}

	private void connectionIdleHandler(@SuppressWarnings("unused") ProxyConnection connection) {
		if (--inFlights == 0)
			idleTimestamp = System.currentTimeMillis();
	}

	private void connectionBusyHandler(@SuppressWarnings("unused") ProxyConnection connection) {
		++inFlights;
		idleTimestamp = 0;
		if (needsNewConnection())
			connect();
	}

	public Future<Void> close() {
		if (running)
			throw new IllegalStateException("Proxy session is still running");

		serviceAddress = null;
		upstreamAddress = null;
		userId = null;
		deviceIdentity = null;
		node = null;
		config = null;

		connectionStatusListener = null;

		if (sessionContext != null) {
			sessionContext.close();
			sessionContext = null;
		}

		if (peerContext != null) {
			peerContext.close();
			peerContext = null;
		}

		if (clientSessionKeyPair != null) {
			clientSessionKeyPair.privateKey().destroy();
			clientSessionKeyPair = null;
		}

		log.debug("Proxy session {} closed", servicePeerId);
		return Future.succeededFuture();
	}

	private static class ListenerArray extends ArrayList<ConnectionStatusListener> implements ConnectionStatusListener {
		private static final long serialVersionUID = 3382171779027882437L;

		public ListenerArray(ConnectionStatusListener existing, ConnectionStatusListener newListener) {
			super();
			add(existing);
			add(newListener);
		}

		@Override
		public void connected() {
			for (ConnectionStatusListener listener : this)
				listener.connected();
		}

		@Override
		public void disconnected() {
			for (ConnectionStatusListener listener : this)
				listener.disconnected();
		}
	}
}