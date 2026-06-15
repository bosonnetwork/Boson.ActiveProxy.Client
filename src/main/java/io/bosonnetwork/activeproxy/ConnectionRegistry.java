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

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Tracks a session's established proxy connections and their busy state.
 * <p>
 * Each connection maps to {@code TRUE} while it is relaying (in-flight) and {@code FALSE} while idle.
 * The in-flight count is maintained as the number of busy connections through every transition -
 * including {@link #remove} - so it cannot drift when a busy connection is torn down abnormally
 * rather than through the normal idle handshake. All transitions are idempotent: a repeated mark, or
 * a mark on a connection that is no longer tracked, is a no-op.
 * <p>
 * Not thread-safe; confined to the owning session's event loop.
 */
class ConnectionRegistry<T> {
	private final Map<T, Boolean> connections = new HashMap<>();
	private int inFlight;

	/** Registers a newly established connection in the idle state. */
	void add(T connection) {
		connections.put(connection, Boolean.FALSE);
	}

	/**
	 * Marks a tracked connection as busy (relaying).
	 *
	 * @return {@code true} if this was an idle to busy transition; {@code false} if the connection
	 *         was already busy or is not tracked
	 */
	boolean markBusy(T connection) {
		if (connections.replace(connection, Boolean.TRUE) == Boolean.FALSE) {
			inFlight++;
			return true;
		}
		return false;
	}

	/**
	 * Marks a tracked connection as idle.
	 *
	 * @return {@code true} if this was a busy to idle transition; {@code false} if the connection
	 *         was already idle or is not tracked
	 */
	boolean markIdle(T connection) {
		if (connections.replace(connection, Boolean.FALSE) == Boolean.TRUE) {
			inFlight--;
			return true;
		}
		return false;
	}

	/**
	 * Removes a connection, keeping the in-flight count accurate if it was still busy.
	 *
	 * @return {@code true} if the connection was busy when removed
	 */
	boolean remove(T connection) {
		if (connections.remove(connection) == Boolean.TRUE) {
			inFlight--;
			return true;
		}
		return false;
	}

	/** @return the number of tracked connections (idle and busy) */
	int size() {
		return connections.size();
	}

	/** @return the number of busy (relaying) connections */
	int inFlight() {
		return inFlight;
	}

	boolean isEmpty() {
		return connections.isEmpty();
	}

	/** A live view of the tracked connections; copy it before mutating the registry while iterating. */
	Collection<T> connections() {
		return connections.keySet();
	}

	void clear() {
		connections.clear();
		inFlight = 0;
	}
}
