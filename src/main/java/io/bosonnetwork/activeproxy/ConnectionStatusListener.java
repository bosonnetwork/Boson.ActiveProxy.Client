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

/**
 * Listener for Active Proxy tunnel connectivity changes.
 * <p>
 * Register an implementation with
 * {@link ActiveProxyClient#addConnectionListener(ConnectionStatusListener)} to be notified when the
 * encrypted tunnel to the super node becomes available or is lost. A {@link #connected()} event is
 * always eventually followed by a {@link #disconnected()} event (and the pair may repeat as the
 * tunnel reconnects).
 * <p>
 * <b>Threading:</b> callbacks are invoked on the client's Vert.x event-loop thread. Implementations
 * must return promptly and must not perform blocking work; any exception thrown by a callback is
 * caught and logged so that other listeners still run.
 */
public interface ConnectionStatusListener {
	/**
	 * Invoked after the tunnel has been authenticated and a public endpoint has been allocated.
	 * <p>
	 * Once this fires, {@link ActiveProxyClient#getEndpoint()} (and, when name access is enabled,
	 * {@link ActiveProxyClient#getNamedEndpoint()}) return the assigned endpoint(s).
	 */
	void connected();

	/**
	 * Invoked when the tunnel to the super node is lost.
	 * <p>
	 * The client attempts to reconnect automatically; a subsequent {@link #connected()} event is
	 * delivered if the tunnel is re-established.
	 */
	void disconnected();
}