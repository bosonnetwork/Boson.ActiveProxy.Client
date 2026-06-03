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

/**
 * Client library for the <b>Boson Active Proxy</b> — a Boson layer-2 service that lets a device
 * expose a local TCP service to the public internet even when it sits behind NAT, a firewall, or
 * has no public IP address.
 *
 * <h2>Overview</h2>
 * A Boson super node running the Active Proxy service acts as a public relay: it owns a public IP
 * address and allocates a TCP endpoint (and, for subscribed clients, a DNS name) that the outside
 * world can reach. This library maintains an encrypted, authenticated tunnel from the local machine
 * out to that super node and transparently forwards incoming external connections to a local
 * upstream service.
 *
 * <h2>Public API</h2>
 * Only three types form the supported public surface of this package:
 * <ul>
 *   <li>{@link io.bosonnetwork.activeproxy.ActiveProxyClient} — the entry point that starts and
 *       stops the tunnel and reports its status;</li>
 *   <li>{@link io.bosonnetwork.activeproxy.Configuration} — immutable client configuration, built
 *       from a YAML map via {@link io.bosonnetwork.activeproxy.Configuration#fromMap(java.util.Map)}
 *       or programmatically through {@link io.bosonnetwork.activeproxy.Configuration#builder()};</li>
 *   <li>{@link io.bosonnetwork.activeproxy.ConnectionStatusListener} — a callback for tunnel
 *       connect/disconnect events.</li>
 * </ul>
 * All other types in this package are internal implementation details and may change without notice.
 *
 * <h2>Typical usage</h2>
 * <pre>{@code
 * Configuration config = Configuration.fromMap(yamlMap);
 * ActiveProxyClient client = new ActiveProxyClient(vertx, node, config);
 * client.addConnectionListener(new ConnectionStatusListener() {
 *     public void connected() {
 *         client.getEndpoint().ifPresent(ep -> System.out.println("Public endpoint: " + ep));
 *     }
 *     public void disconnected() {
 *         System.out.println("Tunnel disconnected");
 *     }
 * });
 * client.start().toCompletionStage().toCompletableFuture().get();
 * // ... later ...
 * client.stop().toCompletionStage().toCompletableFuture().get();
 * }</pre>
 *
 * <h2>Threading model</h2>
 * The client runs on a Vert.x event loop. All internal state is confined to that event loop; the
 * public accessors and listener-management methods on {@link io.bosonnetwork.activeproxy.ActiveProxyClient}
 * are safe to call from any thread. {@link io.bosonnetwork.activeproxy.ConnectionStatusListener}
 * callbacks are always dispatched on the client's event-loop thread, so they must not block.
 *
 * @see <a href="https://github.com/bosonnetwork">Boson Network</a>
 */
package io.bosonnetwork.activeproxy;
