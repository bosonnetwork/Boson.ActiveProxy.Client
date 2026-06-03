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
import java.util.concurrent.atomic.AtomicBoolean;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
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
public class ActiveProxyClient  {
	private Vertx vertx;
	private final boolean internalVertx;

	private final Node node;
	private final Configuration config;

	private ProxySession session;
	private final AtomicBoolean started;

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
	 * @throws IllegalArgumentException if the configuration is invalid (for example a key that cannot
	 *                                  establish a crypto context with the service peer)
	 */
	public ActiveProxyClient(Vertx vertx, Node node, Configuration config) {
		if (config.getServiceHost() == null || config.getServicePort() == 0)
			Objects.requireNonNull(node, "node");

		this.vertx = vertx != null ? vertx : node.unwrap(Vertx.class);
		this.internalVertx = this.vertx == null;

		this.node = node;
		this.config = config;

		this.started = new AtomicBoolean(false);
	}

	/**
	 * Starts the client and brings up the tunnel to the Active Proxy super node.
	 * <p>
	 * This resolves the service peer (via DHT when no fixed host/port is configured), deploys the
	 * internal session, and begins the authentication handshake. The returned future completes once
	 * the session has been deployed; the tunnel may continue to (re)connect afterwards, with status
	 * reported through registered {@link ConnectionStatusListener}s.
	 * <p>
	 * Calling {@code start()} on an already-started client is a no-op and returns a succeeded future.
	 *
	 * @return a future that completes when the session has started, or fails if startup failed
	 */
	public ContextualFuture<Void> start() {
		if (!started.compareAndSet(false, true))
			return ContextualFuture.succeededFuture();

		if (internalVertx)
			this.vertx = Vertx.vertx();

		this.session = new ProxySession(node, config);

		Future<Void> deployFuture = vertx.deployVerticle(session).andThen(ar -> {
			if (ar.failed()) {
				session.close();
				if (internalVertx) {
					vertx.close();
					vertx = null;
				}

				started.set(false);
			}
		}).mapEmpty();

		return ContextualFuture.of(deployFuture);
	}

	/**
	 * Stops the client and tears down the tunnel.
	 * <p>
	 * Undeploys the internal session, closes all connections, and releases cryptographic resources.
	 * If this client created its own internal {@link Vertx} instance, that instance is closed as
	 * well. Calling {@code stop()} on a client that is not started is a no-op and returns a succeeded
	 * future.
	 *
	 * @return a future that completes when the client has fully stopped
	 */
	public ContextualFuture<Void> stop() {
		if (!started.compareAndSet(true, false))
			return ContextualFuture.succeededFuture();

		Future<Void> future = vertx.undeploy(session.deploymentID())
				.compose(v -> session.close());

		if (internalVertx)
			future = future.compose(v -> vertx.close())
					.andThen(ar -> vertx = null);

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
		return session.isRunning();
	}

	/**
	 * Returns whether the tunnel to the super node is currently connected and authenticated.
	 *
	 * @return {@code true} if the tunnel is connected
	 */
	public boolean isConnected() {
		return session.isConnected();
	}

	/**
	 * Returns whether name (DNS) access has been granted for this session by the super node.
	 * <p>
	 * This reflects the value negotiated during authentication and is meaningful only once the
	 * tunnel is connected.
	 *
	 * @return {@code true} if a named endpoint is available
	 */
	public boolean isNameAccessEnabled() {
		return session.isNameAccessEnabled();
	}

	/**
	 * Returns the public endpoint (scheme + {@code ip:port}) allocated by the super node.
	 *
	 * @return the public endpoint, or an empty {@link Optional} if the tunnel is not yet connected
	 */
	public Optional<String> getEndpoint() {
		return Optional.ofNullable(session.getEndpoint());
	}

	/**
	 * Returns the public named (DNS) endpoint allocated by the super node, when name access is
	 * enabled.
	 *
	 * @return the named endpoint, or an empty {@link Optional} if the tunnel is not connected or no
	 *         named endpoint was assigned
	 */
	public Optional<String> getNamedEndpoint() {
		return Optional.ofNullable(session.getNamedEndpoint());
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
		session.addConnectionListener(listener);
	}

	/**
	 * Removes a previously registered connection status listener.
	 * <p>
	 * Has no effect if the listener was not registered. Safe to call from any thread.
	 *
	 * @param listener the listener to remove
	 */
	public void removeConnectionListener(ConnectionStatusListener listener) {
		session.removeConnectionListener(listener);
	}
}