package io.bosonnetwork.activeproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ConnectionRegistry}, pinning the invariant that {@code inFlight()} always
 * equals the number of busy connections across every transition - in particular that it does not
 * leak when a busy connection is removed (torn down) instead of going idle first.
 */
class ConnectionRegistryTest {
	@Test
	void addStartsIdle() {
		ConnectionRegistry<String> registry = new ConnectionRegistry<>();
		registry.add("c1");

		assertEquals(1, registry.size());
		assertEquals(0, registry.inFlight());
		assertFalse(registry.isEmpty());
		assertTrue(registry.connections().contains("c1"));
	}

	@Test
	void busyAndIdleTransitionsAreCountedOnce() {
		ConnectionRegistry<String> registry = new ConnectionRegistry<>();
		registry.add("c1");

		assertTrue(registry.markBusy("c1"));   // idle -> busy
		assertEquals(1, registry.inFlight());

		assertFalse(registry.markBusy("c1"));  // already busy, no double count
		assertEquals(1, registry.inFlight());

		assertTrue(registry.markIdle("c1"));   // busy -> idle
		assertEquals(0, registry.inFlight());

		assertFalse(registry.markIdle("c1"));  // already idle, no underflow
		assertEquals(0, registry.inFlight());
	}

	@Test
	void marksOnUnknownConnectionAreNoOps() {
		ConnectionRegistry<String> registry = new ConnectionRegistry<>();

		assertFalse(registry.markBusy("ghost"));
		assertFalse(registry.markIdle("ghost"));
		// A mark must not insert an untracked connection.
		assertEquals(0, registry.size());
		assertEquals(0, registry.inFlight());
	}

	@Test
	void removingBusyConnectionKeepsInFlightAccurate() {
		// The regression: a busy connection torn down abnormally (close, not idle handshake).
		ConnectionRegistry<String> registry = new ConnectionRegistry<>();
		registry.add("c1");
		registry.markBusy("c1");
		assertEquals(1, registry.inFlight());

		assertTrue(registry.remove("c1"));     // was busy when removed
		assertEquals(0, registry.size());
		assertEquals(0, registry.inFlight());  // must not leak
	}

	@Test
	void removingIdleConnectionLeavesInFlightUnchanged() {
		ConnectionRegistry<String> registry = new ConnectionRegistry<>();
		registry.add("c1");
		registry.add("c2");
		registry.markBusy("c2");
		assertEquals(1, registry.inFlight());

		assertFalse(registry.remove("c1"));    // idle removal
		assertEquals(1, registry.size());
		assertEquals(1, registry.inFlight());

		assertFalse(registry.remove("ghost")); // unknown removal
		assertEquals(1, registry.inFlight());
	}

	@Test
	void inFlightTracksBusyCountUnderMixedOperations() {
		ConnectionRegistry<String> registry = new ConnectionRegistry<>();
		registry.add("c1");
		registry.add("c2");
		registry.add("c3");

		registry.markBusy("c1");
		registry.markBusy("c2");
		assertEquals(2, registry.inFlight());
		assertEquals(3, registry.size());

		registry.remove("c1");                 // remove one while busy
		assertEquals(1, registry.inFlight());

		registry.markIdle("c2");               // other goes idle normally
		assertEquals(0, registry.inFlight());
		assertEquals(2, registry.size());
	}

	@Test
	void clearResetsSizeAndInFlight() {
		ConnectionRegistry<String> registry = new ConnectionRegistry<>();
		registry.add("c1");
		registry.markBusy("c1");

		registry.clear();
		assertTrue(registry.isEmpty());
		assertEquals(0, registry.size());
		assertEquals(0, registry.inFlight());
	}
}
