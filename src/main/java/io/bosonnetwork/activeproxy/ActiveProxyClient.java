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

import java.net.URI;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.bosonnetwork.Node;
import io.bosonnetwork.vertx.VertxFuture;

public class ActiveProxyClient  {
	private final Vertx vertx;
	private final Node node;
	private final Configuration config;

	private final ProxySession session;

	private static final Logger log = LoggerFactory.getLogger(ActiveProxyClient.class);

	public ActiveProxyClient(Vertx vertx, Node node, Configuration config) {
		this.vertx = vertx;
		this.node = node;
		this.config = config;
		this.session = new ProxySession(node, config);
	}

	private Future<Void> resolvePeer() {
		if (config.getServiceHost() == null || config.getServicePort() == 0) {
			log.info("Looking up service peer {} ...", config.getServicePeerId());
			return Future.fromCompletionStage(node.findPeer(config.getServicePeerId())).compose(peer -> {
				if (peer == null) {
					log.error("Service peer not found {}", config.getServicePeerId());
					return Future.failedFuture("Service peer not found: " + config.getServicePeerId());
				}

				URI uri = URI.create(peer.getEndpoint());
				if (!uri.getScheme().equals("tcp") || uri.getPort() <= 0) {
					log.error("Service peer endpoint {} is invalid", peer.getEndpoint());
					return Future.failedFuture("Service peer endpoint is invalid: " + peer.getEndpoint());
				}

				config.setServiceHost(uri.getHost());
				config.setServicePort(uri.getPort());
				return Future.succeededFuture();
			});
		} else {
			return Future.succeededFuture();
		}
	}

	public VertxFuture<Void> start() {

		Future<Void> deployFuture = resolvePeer().compose(v ->
			vertx.deployVerticle(session).andThen(ar -> {
				if (ar.failed())
					session.close();
			}).mapEmpty()
		);

		return VertxFuture.of(deployFuture);
	}

	public VertxFuture<Void> stop() {
		if (!session.isRunning())
			return VertxFuture.succeededFuture();

		return VertxFuture.of(vertx.undeploy(session.deploymentID()).compose(v -> session.close()));
	}

	public boolean isRunning() {
		return session.isRunning();
	}

	public boolean isConnected() {
		return session.isConnected();
	}

	public boolean isNameAccessEnabled() {
		if (!isRunning())
			throw new IllegalStateException("not running");

		return session.isNameAccessEnabled();
	}

	public String getEndpoint() {
		if (!isRunning())
			throw new IllegalStateException("not running");

		return session.getEndpoint();
	}

	public String getNamedEndpoint() {
		if (!isRunning())
			throw new IllegalStateException("not running");

		return session.getNamedEndpoint();
	}

	public void addConnectionListener(ConnectionStatusListener listener) {
		session.addConnectionStatusListener(listener);
	}

	public void removeConnectionListener(ConnectionStatusListener listener) {
		session.removeConnectionStatusListener(listener);
	}
}