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

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonProcessingException;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import org.jspecify.annotations.Nullable;

import io.bosonnetwork.Id;
import io.bosonnetwork.json.Json;
import io.bosonnetwork.utils.ApplicationLock;
import io.bosonnetwork.utils.FileUtils;

/**
 * Command line entry point for the standalone Boson Active Proxy client.
 * <p>
 * The launcher runs the client <em>without</em> a Boson DHT node, which keeps the process small but
 * constrains the configuration in two ways:
 * <ul>
 *   <li>{@code service.host} must be set, because there is no node to resolve the service peer
 *       through the DHT;</li>
 *   <li>{@code announcePeer} cannot be honoured, because announcing requires a node.</li>
 * </ul>
 * Both conditions are checked up front and reported before anything is started.
 * <p>
 * Only one instance may run per device identity: the launcher holds a file lock named after the
 * device id for its whole lifetime. Two processes sharing a {@code devicePrivateKey} would otherwise
 * race for the same session on the super node, each tearing down the other's tunnel. Configurations
 * with different device keys run side by side without interfering.
 * <p>
 * Exit codes: {@code 0} clean shutdown, {@code 1} runtime failure, {@code 2} invalid command line,
 * {@code 3} missing or invalid configuration, {@code 4} another instance holds the lock.
 */
public final class Launcher {
	private static final String PROGRAM_NAME = "active-proxy";
	private static final String DEFAULT_CONFIG_FILE = "active-proxy.yaml";

	private static final int EXIT_SUCCESS = 0;
	private static final int EXIT_FAILURE = 1;
	private static final int EXIT_USAGE = 2;
	private static final int EXIT_CONFIG = 3;
	private static final int EXIT_LOCKED = 4;

	/** Upper bound on how long shutdown waits for the client and for Vert.x, each. */
	private static final long SHUTDOWN_TIMEOUT = 30;

	private static final AtomicBoolean shuttingDown = new AtomicBoolean(false);
	/** Parks the main thread for the lifetime of the client; {@link #shutdown()} releases it. */
	private static final CountDownLatch running = new CountDownLatch(1);

	private static volatile @Nullable Vertx vertx;
	private static volatile @Nullable ActiveProxyClient client;
	private static volatile @Nullable ApplicationLock instanceLock;

	private Launcher() {
	}

	/**
	 * The parsed command line.
	 *
	 * @param configFile the {@code --config} value, or {@code null} to use the default location
	 * @param help       whether {@code --help} was given
	 * @param version    whether {@code --version} was given
	 */
	private record Options(@Nullable Path configFile, boolean help, boolean version) {
	}

	/** Signals a configuration that could not be read or is not usable; carries a ready-to-print message. */
	private static class ConfigException extends Exception {
		private static final long serialVersionUID = -6069564830424564461L;

		// Kept alongside the inherited message so that callers have a non-null one to print.
		private final String message;

		ConfigException(String message) {
			super(message);
			this.message = message;
		}

		ConfigException(String message, Throwable cause) {
			super(message, cause);
			this.message = message;
		}

		String message() {
			return message;
		}
	}

	/**
	 * Parses the command line.
	 * <p>
	 * Options may be written as {@code -c FILE}, {@code --config FILE} or {@code --config=FILE}. A
	 * bare {@code --} ends option processing; since the launcher takes no operands, anything after it
	 * is an error, as is any unknown option or stray operand.
	 *
	 * @param args the raw arguments
	 * @return the parsed options
	 * @throws IllegalArgumentException if the command line is not valid; the message is user facing
	 */
	private static Options parseArgs(String[] args) throws IllegalArgumentException {
		Path configFile = null;
		boolean help = false;
		boolean version = false;
		boolean endOfOptions = false;

		for (int i = 0; i < args.length; i++) {
			String arg = args[i];

			if (endOfOptions)
				throw new IllegalArgumentException("Unexpected argument: " + arg);

			String value = null;
			int eq = arg.indexOf('=');
			if (arg.startsWith("--") && eq > 0) {
				value = arg.substring(eq + 1);
				arg = arg.substring(0, eq);
			}

			switch (arg) {
				case "-c", "--config" -> {
					if (value == null) {
						if (i + 1 >= args.length)
							throw new IllegalArgumentException("Missing file path for the " + arg + " option");

						value = args[++i];
					}

					if (value.isBlank())
						throw new IllegalArgumentException("Empty file path for the " + arg + " option");

					try {
						// The file itself is validated later, together with the default location.
						configFile = Paths.get(value);
					} catch (InvalidPathException e) {
						throw new IllegalArgumentException("Invalid file path for the " + arg + " option: " + value);
					}
				}
				case "-h", "--help" -> {
					rejectValue(arg, value);
					help = true;
				}
				case "-v", "--version" -> {
					rejectValue(arg, value);
					version = true;
				}
				case "--" -> {
					rejectValue(arg, value);
					endOfOptions = true;
				}
				default -> {
					if (arg.startsWith("-"))
						throw new IllegalArgumentException("Unknown option: " + arg);

					throw new IllegalArgumentException("Unexpected argument: " + arg +
							" (use -c " + arg + " to pass a configuration file)");
				}
			}
		}

		return new Options(configFile, help, version);
	}

	private static void rejectValue(String option, @Nullable String value) throws IllegalArgumentException {
		if (value != null)
			throw new IllegalArgumentException("The " + option + " option does not take a value");
	}

	/**
	 * Resolves the configuration file to load: the one given on the command line, or the per-user
	 * default location.
	 *
	 * @param options the parsed command line
	 * @return the configuration file path
	 * @throws ConfigException if no path was given and the default location cannot be determined
	 */
	private static Path resolveConfigFile(Options options) throws ConfigException {
		Path configFile = options.configFile();
		if (configFile != null)
			return configFile;

		try {
			return FileUtils.getUserConfigDir()
					.resolve("boson")
					.resolve("client")
					.resolve(DEFAULT_CONFIG_FILE);
		} catch (RuntimeException e) {
			// getUserConfigDir() reads environment variables that may be unset on the platform.
			throw new ConfigException("Cannot determine the default configuration directory: " +
					describe(e) + System.lineSeparator() +
					"Specify a configuration file explicitly with -c <FILE>.", e);
		}
	}

	/**
	 * Reads and parses the configuration file, and checks that it can be served without a DHT node.
	 *
	 * @param configFile the file to read
	 * @param explicit   whether the path came from the command line (changes the "not found" hint)
	 * @return the parsed configuration
	 * @throws ConfigException if the file is unusable or the configuration is invalid; the message is
	 *                         user facing and already names the file
	 */
	private static Configuration loadConfig(Path configFile, boolean explicit) throws ConfigException {
		// Normalized so that a relative path such as ./x.yaml reads cleanly in every message below.
		Path path = configFile.toAbsolutePath().normalize();

		if (!Files.exists(path))
			throw new ConfigException(explicit ?
					"Configuration file not found: " + path :
					"No configuration file found at " + path + System.lineSeparator() +
							"Create it, or point at another one with -c <FILE>.");

		if (!Files.isRegularFile(path))
			throw new ConfigException("Configuration path is not a regular file: " + path);

		if (!Files.isReadable(path))
			throw new ConfigException("Configuration file is not readable, check its permissions: " + path);

		byte[] content;
		try {
			content = Files.readAllBytes(path);
		} catch (IOException e) {
			throw new ConfigException("Cannot read configuration file " + path + ": " + describe(e), e);
		}

		if (new String(content, StandardCharsets.UTF_8).isBlank())
			throw new ConfigException("Configuration file is empty: " + path);

		Map<String, Object> map;
		try {
			map = Json.yamlMapper().readValue(content, Json.mapType());
		} catch (JsonProcessingException e) {
			JsonLocation location = e.getLocation();
			String where = location == null ? "" :
					" at line " + location.getLineNr() + ", column " + location.getColumnNr();
			throw new ConfigException("Malformed YAML in " + path + where + ": " + e.getOriginalMessage(), e);
		} catch (IOException e) {
			throw new ConfigException("Cannot read configuration file " + path + ": " + describe(e), e);
		}

		if (map.isEmpty())
			throw new ConfigException("Configuration file is empty: " + path);

		Configuration config;
		try {
			config = Configuration.fromMap(map);
		} catch (IllegalArgumentException | IllegalStateException e) {
			throw new ConfigException("Invalid configuration in " + path + ": " + describe(e), e);
		}

		// The launcher runs without a DHT node, so the service peer cannot be looked up.
		if (config.getServiceHost() == null)
			throw new ConfigException("Invalid configuration in " + path + ": service.host is required" +
					System.lineSeparator() +
					"The standalone launcher runs without a DHT node and cannot resolve the service" +
					" peer, so the super node address must be configured.");

		return config;
	}

	/**
	 * Returns the lock file that guards this configuration's device identity.
	 * <p>
	 * The name is derived from the device id rather than from the configuration file path: the device
	 * key is what the super node authenticates, so two processes sharing one are in conflict even
	 * when they were started from different files, and two with different device keys never are. The
	 * file lives beside the other per-user Boson state rather than in a cache directory, which a
	 * cleaner may empty while the process is still running.
	 *
	 * @param config the configuration being launched
	 * @return the path of the lock file
	 */
	private static Path lockFile(Configuration config) {
		Id deviceId = Id.of(config.getDeviceKey().publicKey().bytes());
		return FileUtils.getUserStateDir()
				.resolve("boson")
				.resolve("client")
				.resolve("active-proxy-" + deviceId + ".lock");
	}

	/**
	 * Takes the single-instance lock, or terminates the process explaining who holds it.
	 *
	 * @param config the configuration being launched
	 */
	private static void lockInstance(Configuration config) {
		Path lockFile;
		try {
			lockFile = lockFile(config);
		} catch (RuntimeException e) {
			// getUserDataDir() reads environment variables that may be unset on the platform.
			die(EXIT_FAILURE, "Cannot determine the lock file location: " + describe(e), null);
			return;
		}

		try {
			instanceLock = new ApplicationLock(lockFile);
		} catch (IllegalStateException e) {
			die(EXIT_LOCKED, "Another instance is already running for this device identity.",
					"Lock file: " + lockFile + owner(lockFile));
		} catch (IOException e) {
			die(EXIT_FAILURE, "Cannot create the lock file " + lockFile + ": " + describe(e), null);
		}
	}

	/**
	 * Reads the owner marker that {@link ApplicationLock} writes into the lock file, so the conflict
	 * message can name the process that is holding it.
	 * <p>
	 * Only ever called from the process that just <em>failed</em> to take the lock, and it must stay
	 * that way: reading the file opens and closes a descriptor for it, which on POSIX systems
	 * releases every lock the calling process holds on that file - silently, and with the lock still
	 * reporting itself as valid.
	 *
	 * @param lockFile the lock file to inspect
	 * @return a parenthesized description, or an empty string if the marker cannot be read
	 */
	private static String owner(Path lockFile) {
		try {
			String marker = Files.readString(lockFile).trim();
			return marker.isEmpty() ? "" : " (held by pid/since: " + marker + ")";
		} catch (IOException | RuntimeException e) {
			// The marker is informational; its absence says nothing about the lock itself.
			return "";
		}
	}

	private static void printUsage(PrintStream out) {
		out.println("Boson Active Proxy client");
		out.println();
		out.println("Usage: " + PROGRAM_NAME + " [OPTIONS]");
		out.println();
		out.println("Options:");
		out.println("  -c, --config <FILE>   Path to the YAML configuration file.");
		out.println("                        Default: <user config dir>/boson/client/" + DEFAULT_CONFIG_FILE);
		out.println("  -v, --version         Print the version and exit.");
		out.println("  -h, --help            Print this help and exit.");
		out.println();
		out.println("Exit codes:");
		out.println("  " + EXIT_SUCCESS + "  clean shutdown");
		out.println("  " + EXIT_FAILURE + "  runtime failure");
		out.println("  " + EXIT_USAGE + "  invalid command line");
		out.println("  " + EXIT_CONFIG + "  missing or invalid configuration");
		out.println("  " + EXIT_LOCKED + "  another instance is already running for this device");
	}

	private static String version() {
		String version = Launcher.class.getPackage().getImplementationVersion();
		return version != null ? version : "(development build)";
	}

	/**
	 * Renders a throwable for a single-line, user-facing message: the message when there is one, the
	 * class name otherwise, so that the output is never an empty string.
	 *
	 * @param e the throwable to describe
	 * @return a non-empty description
	 */
	private static String describe(Throwable e) {
		String message = e.getMessage();
		if (message == null || message.isBlank())
			return e.getClass().getSimpleName();

		Throwable cause = e.getCause();
		// build() wraps the offending field's exception; its message carries the useful detail.
		if (cause != null && cause != e) {
			String causeMessage = cause.getMessage();
			if (causeMessage != null && !causeMessage.isBlank() && !message.contains(causeMessage))
				return message + " (" + causeMessage + ")";
		}

		return message;
	}

	/**
	 * Stops the client and closes Vert.x, in that order and at most once.
	 * <p>
	 * Runs both from the shutdown hook and from the failure paths in {@link #main(String[])}; the
	 * first caller wins and later callers return immediately. Every step is bounded by
	 * {@link #SHUTDOWN_TIMEOUT} so a wedged tunnel cannot hang the process forever, and a failure in
	 * one step never skips the next.
	 */
	private static void shutdown() {
		if (!shuttingDown.compareAndSet(false, true))
			return;

		ActiveProxyClient c = client;
		client = null;
		if (c != null) {
			// stop() is called even when the client never came up (it is then a no-op), but the
			// progress messages would only be noise on that path.
			boolean wasRunning = c.isRunning();
			if (wasRunning)
				System.out.println("Stopping the Active Proxy client ...");

			try {
				c.stop().get(SHUTDOWN_TIMEOUT, TimeUnit.SECONDS);
				if (wasRunning)
					System.out.println("Active Proxy client stopped.");
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				System.err.println("Interrupted while stopping the Active Proxy client.");
			} catch (TimeoutException e) {
				System.err.println("Timed out after " + SHUTDOWN_TIMEOUT +
						"s while stopping the Active Proxy client, closing anyway.");
			} catch (ExecutionException e) {
				Throwable cause = e.getCause();
				System.err.println("Failed to stop the Active Proxy client cleanly: " +
						describe(cause != null ? cause : e));
			}
		}

		// Vert.x is closed only after the client's future has settled: closing it stops the event
		// loops, and any handler still pending would then never run.
		Vertx v = vertx;
		vertx = null;
		if (v != null) {
			try {
				v.close().toCompletionStage().toCompletableFuture().get(SHUTDOWN_TIMEOUT, TimeUnit.SECONDS);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				System.err.println("Interrupted while closing Vert.x.");
			} catch (TimeoutException e) {
				System.err.println("Timed out after " + SHUTDOWN_TIMEOUT + "s while closing Vert.x.");
			} catch (ExecutionException e) {
				Throwable cause = e.getCause();
				System.err.println("Failed to close Vert.x cleanly: " + describe(cause != null ? cause : e));
			}
		}

		// Released last: the lock must outlive everything it protects, so that a successor process
		// cannot take it while this one is still talking to the super node.
		ApplicationLock lock = instanceLock;
		instanceLock = null;
		if (lock != null)
			lock.close();

		running.countDown();
	}

	/**
	 * Prints an error to standard error and terminates the process, releasing any resources that were
	 * already acquired.
	 *
	 * @param code    the exit code
	 * @param message the error message, printed with an {@code Error:} prefix
	 * @param hint    an optional follow-up line, such as a pointer to {@code --help}
	 */
	private static void die(int code, String message, @Nullable String hint) {
		System.err.println("Error: " + message);
		if (hint != null)
			System.err.println(hint);

		shutdown();
		System.exit(code);
	}

	/**
	 * Runs the standalone Active Proxy client until the process is interrupted.
	 *
	 * @param args the command line arguments; see {@link #printUsage(PrintStream)}
	 */
	public static void main(String[] args) {
		Options options;
		try {
			options = parseArgs(args);
		} catch (IllegalArgumentException e) {
			die(EXIT_USAGE, describe(e), "Try '" + PROGRAM_NAME + " --help' for more information.");
			return;
		}

		if (options.help()) {
			printUsage(System.out);
			System.exit(EXIT_SUCCESS);
			return;
		}

		if (options.version()) {
			System.out.println(PROGRAM_NAME + " " + version());
			System.exit(EXIT_SUCCESS);
			return;
		}

		Configuration config;
		try {
			Path configFile = resolveConfigFile(options);
			config = loadConfig(configFile, options.configFile() != null);
		} catch (ConfigException e) {
			die(EXIT_CONFIG, e.message(), null);
			return;
		}

		if (config.isAnnouncePeer())
			System.err.println("Warning: announcePeer is enabled but the standalone launcher runs" +
					" without a DHT node; the endpoint will not be announced.");

		// Registered before anything is created so that a signal arriving mid-startup still runs the
		// same single shutdown path; shutdown() tolerates the half-initialized state.
		Runtime.getRuntime().addShutdownHook(new Thread(Launcher::shutdown, "active-proxy-shutdown"));

		// Taken before any resource is created, and released last by shutdown().
		lockInstance(config);

		Vertx v = Vertx.vertx(new VertxOptions()
				.setWorkerPoolSize(2)
				.setEventLoopPoolSize(2)
				.setPreferNativeTransport(true));
		vertx = v;

		ActiveProxyClient proxyClient;
		try {
			// Keep a non-null local: the listener callbacks below cannot rely on the nullable field,
			// which shutdown() clears.
			proxyClient = new ActiveProxyClient(v, null, config);
		} catch (RuntimeException e) {
			die(EXIT_CONFIG, "Cannot create the Active Proxy client: " + describe(e), null);
			return;
		}

		client = proxyClient;
		proxyClient.addConnectionListener(new ConnectionStatusListener() {
			@Override
			public void connected() {
				try {
					System.out.println("Connected to the Active Proxy service " + config.getServicePeerId());
					System.out.println("  Public endpoint: " + proxyClient.getEndpoint());
					if (proxyClient.isNameAccessEnabled())
						System.out.println("  Named endpoint:  " + proxyClient.getNamedEndpoint().orElse("N/A"));
					System.out.println("  Upstream:        " + config.getUpstreamHost() + ":" + config.getUpstreamPort());
				} catch (IllegalStateException e) {
					// The tunnel dropped again before the endpoint could be read; the reconnect
					// reports it. Never let a listener throw back into the event loop.
				}
			}

			@Override
			public void disconnected() {
				if (client != null)
					System.out.println("Disconnected from the Active Proxy service " + config.getServicePeerId() +
							", reconnecting ...");
			}
		});

		System.out.println("Starting the Active Proxy client ...");
		System.out.println("  Service peer: " + config.getServicePeerId());
		System.out.println("  Service host: " + config.getServiceHost() + ":" + config.getServicePort());
		System.out.println("  Upstream:     " + config.getUpstreamHost() + ":" + config.getUpstreamPort());
		try {
			proxyClient.start().get();
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			die(EXIT_FAILURE, "Interrupted while starting the Active Proxy client.", null);
			return;
		} catch (ExecutionException e) {
			Throwable cause = e.getCause();
			die(EXIT_FAILURE, "Failed to start the Active Proxy client: " +
					describe(cause != null ? cause : e), null);
			return;
		}

		System.out.println("Active Proxy client started. Press Ctrl+C to stop.");

		try {
			// Parked until shutdown() runs, whether that is from the signal hook or from this thread
			// being interrupted. On the signal path the JVM is already halting by the time we wake.
			running.await();
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}

		shutdown();
		// Only reached on the interrupt path; kept so a library thread that outlives Vert.x cannot
		// leave the process hanging. On the signal path the JVM's own exit status wins.
		System.exit(EXIT_SUCCESS);
	}
}
