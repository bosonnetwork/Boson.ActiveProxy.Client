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
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.bosonnetwork.Node;
import io.bosonnetwork.vertx.ContextualFuture;

/**
 * Entry point for the Boson Active Proxy client.
 * <p>
 * An {@code ActiveProxyClient} maintains an encrypted, authenticated tunnel from the local machine
 * to a Boson super node running the Active Proxy service, and forwards external connections that
 * arrive at the super node to a local upstream service. The local service is thereby reachable from
 * the public internet without port forwarding, a VPN, or a static IP.
 * <p>
 * The client is configured with an immutable {@link Configuration}. After construction, call
 * {@link #start()} to bring up the tunnel and {@link #stop()} to tear it down; both return a
 * {@link ContextualFuture} that completes when the operation finishes. Register a
 * {@link ConnectionStatusListener} to observe connect/disconnect events, and query
 * {@link #getEndpoint()} / {@link #getNamedEndpoint()} for the public endpoint(s) once connected.
 * <p>
 * <b>Threading:</b> the tunnel runs on a Vert.x event loop, but all methods on this class are safe
 * to call from any thread. {@link ConnectionStatusListener} callbacks are dispatched on the
 * event-loop thread and must not block.
 *
 * @see Configuration
 * @see ConnectionStatusListener
 */
public class ActiveProxyClient {
	private final Vertx vertx;

	private final @Nullable Node node;
	private final Configuration config;

	private final AtomicBoolean started;
	private volatile @Nullable ProxySession session;

	private final ListenerArray connectionStatusListener;

	private static final Logger log = LoggerFactory.getLogger(ActiveProxyClient.class);

	/**
	 * Creates a new client for the given configuration.
	 * <p>
	 * The {@code node} is required when the service host/port are not pinned in the configuration,
	 * because the super node's address must then be resolved through the DHT. If {@code vertx} is
	 * {@code null}, the {@link Vertx} instance is taken from {@code node}; if that is also
	 * unavailable, the client creates and manages its own internal {@link Vertx} instance (which it
	 * closes again on {@link #stop()}).
	 *
	 * @param vertx  the Vert.x instance to run on, or {@code null} to derive/create one
	 * @param node   the Boson DHT node used for service-peer lookup and (optionally) peer
	 *               announcement; required unless both {@code service.host} and {@code service.port}
	 *               are configured
	 * @param config the client configuration
	 * @throws NullPointerException     if {@code node} is required (no fixed service host/port) but
	 *                                  {@code null}
	 * @throws IllegalArgumentException if the configuration is invalid (for example, a key that cannot
	 *                                  establish a crypto context with the service peer)
	 */
	public ActiveProxyClient(@Nullable Vertx vertx, @Nullable Node node, Configuration config) {
		if (config.getServiceHost() == null || config.getServicePort() == 0)
			Objects.requireNonNull(node, "node is required if service host/port is not configured");

		Vertx v = vertx != null ? vertx : (node != null ? node.unwrap(Vertx.class).orElse(null) : null);
		this.vertx = Objects.requireNonNull(v, "No Vertx instance available: provide a Vertx, or a Node that exposes one");

		this.node = node;
		this.config = config;

		this.started = new AtomicBoolean(false);
		this.connectionStatusListener = new ListenerArray();
	}

	/**
	 * Starts the client and brings up the tunnel to the Active Proxy super node.
	 * <p>
	 * This resolves the service peer (via DHT when no fixed host/port is configured), deploys the
	 * internal session, and begins the authentication handshake. The returned future completes once
	 * the session has been deployed; the tunnel may continue to (re)connect afterward, with status
	 * reported through registered {@link ConnectionStatusListener}s.
	 * <p>
	 * Calling {@code start()} on an already-started client is a no-op and returns a succeeded future.
	 *
	 * @return a future that completes when the session has started, or fails if startup failed
	 */
	public ContextualFuture<Void> start() {
		if (!started.compareAndSet(false, true))
			return ContextualFuture.succeededFuture();

		ProxySession s = new ProxySession(node, config);
		s.setConnectionListener(connectionStatusListener);

		Future<Void> deployFuture = vertx.deployVerticle(s).andThen(ar -> {
			if (ar.succeeded()) {
				this.session = s;
			} else {
				s.close();
				started.set(false);
			}
		}).mapEmpty();

		return ContextualFuture.of(deployFuture);
	}

	/**
	 * Stops the client and tears down the tunnel.
	 * <p>
	 * Undeploys the internal session, closes all connections, and releases cryptographic resources.
	 * Calling {@code stop()} on a client that is not started is a no-op and returns a succeeded
	 * future.
	 *
	 * @return a future that completes when the client has fully stopped
	 */
	public ContextualFuture<Void> stop() {
		if (!started.compareAndSet(true, false))
			return ContextualFuture.succeededFuture();

		ProxySession s = session;
		if (s == null)
			return ContextualFuture.failedFuture(new IllegalStateException("Client is not running"));

		Future<Void> future = vertx.undeploy(s.deploymentID())
				.compose(na -> {
					session = null;
					return s.close();
				});

		return ContextualFuture.of(future);
	}

	/**
	 * Returns whether the client has been started and the session is running.
	 * <p>
	 * Note that "running" does not imply the tunnel is currently connected; use {@link #isConnected()}
	 * for that.
	 *
	 * @return {@code true} if the session is running
	 */
	public boolean isRunning() {
		ProxySession s = session;
		return s != null && s.isRunning();
	}

	/**
	 * Returns whether the tunnel to the super node is currently connected and authenticated.
	 *
	 * @return {@code true} if the tunnel is connected
	 */
	public boolean isConnected() {
		ProxySession s = session;
		return s != null && s.isConnected();
	}

	/**
	 * Returns whether the super node has granted name (DNS) access for this session.
	 * <p>
	 * This reflects the value negotiated during authentication and is meaningful only once the
	 * tunnel is connected.
	 *
	 * @return {@code true} if a named endpoint is available
	 * @throws IllegalStateException if the client is not connected
	 */
	public boolean isNameAccessEnabled() {
		ProxySession s = session;
		if (s == null || !s.isRunning() || !s.isConnected())
			throw new IllegalStateException("Client is not connected");
		return s.isNameAccessEnabled();
	}

	/**
	 * Returns the public endpoint (scheme + {@code ip:port}) allocated by the super node.
	 *
	 * @return the public endpoint
	 * @throws IllegalStateException if the client is not connected
	 */
	public String getEndpoint() {
		ProxySession s = session;
		if (s == null || !s.isRunning() || !s.isConnected())
			throw new IllegalStateException("Client is not connected");
		return s.getEndpoint();
	}

	/**
	 * Returns the public named (DNS) endpoint allocated by the super node when name access is
	 * enabled.
	 *
	 * @return the named endpoint, or an empty {@link Optional} if no named endpoint was assigned
	 * @throws IllegalStateException if the client is not connected
	 */
	public Optional<String> getNamedEndpoint() {
		ProxySession s = session;
		if (s == null || !s.isRunning() || !s.isConnected())
			throw new IllegalStateException("Client is not connected");
		return Optional.ofNullable(s.getNamedEndpoint());
	}

	/**
	 * Registers a listener for tunnel connect/disconnect events.
	 * <p>
	 * The same listener may be registered once; callbacks are dispatched on the event-loop thread.
	 * Safe to call from any thread, including before {@link #start()}.
	 *
	 * @param listener the listener to add; must not be {@code null}
	 * @throws NullPointerException if {@code listener} is {@code null}
	 */
	public void addConnectionListener(ConnectionStatusListener listener) {
		Objects.requireNonNull(listener, "listener");
		connectionStatusListener.add(listener);
	}

	/**
	 * Removes a previously registered connection status listener.
	 * <p>
	 * Has no effect if the listener was not registered. Safe to call from any thread.
	 *
	 * @param listener the listener to remove
	 */
	public void removeConnectionListener(ConnectionStatusListener listener) {
		connectionStatusListener.remove(listener);
	}

	private static class ListenerArray extends CopyOnWriteArrayList<ConnectionStatusListener> implements ConnectionStatusListener {
		private static final long serialVersionUID = 3382171779027882437L;

		public ListenerArray() {
			super();
		}

		@Override
		public void connected() {
			for (ConnectionStatusListener listener : this) {
				try {
					listener.connected();
				} catch (Throwable t) {
					log.error("Error dispatching connected to listener: {}", listener, t);
				}
			}
		}

		@Override
		public void disconnected() {
			for (ConnectionStatusListener listener : this) {
				try {
					listener.disconnected();
				} catch (Throwable t) {
					log.error("Error dispatching disconnected to listener: {}", listener, t);
				}
			}
		}
	}
}