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

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import org.jspecify.annotations.NullUnmarked;
import org.jspecify.annotations.Nullable;

import io.bosonnetwork.Id;
import io.bosonnetwork.crypto.Signature;
import io.bosonnetwork.utils.Base58;
import io.bosonnetwork.utils.ConfigMap;
import io.bosonnetwork.utils.Hex;

/**
 * Immutable configuration for an {@link ActiveProxyClient}.
 * <p>
 * A configuration captures three things: which Active Proxy super node to use ({@code service}),
 * the client identity that authenticates to it ({@code client}: a user identity and a per-device
 * key), and which local service to expose ({@code upstream}), plus the {@code nameAccess} and
 * {@code announcePeer} flags.
 * <p>
 * Build one either from a parsed YAML/JSON map with {@link #fromMap(Map)} or programmatically with
 * the fluent {@link #builder()}. Instances are immutable and may be shared across clients.
 *
 * <h2>Service address resolution</h2>
 * The service {@code host}/{@code port} are optional. When omitted, the client resolves the super
 * node's TCP endpoint from the DHT using the service {@code peerId} (which requires a Boson
 * {@link io.bosonnetwork.Node}); when both are present, the client connects directly and skips the
 * lookup.
 *
 * @see ActiveProxyClient
 */
public class Configuration {
	private static final String DEFAULT_SCHEME = "http";
	private static final int DEFAULT_PORT = 9090;
	/** RFC 3986 section 3.1, applied after the scheme has been lower cased. */
	private static final Pattern SCHEME_PATTERN = Pattern.compile("[a-z][a-z0-9+.-]*");

	private final Id servicePeerId;
	private final @Nullable String serviceHost; // optional
	private final int servicePort;	// optional

	private final Id userId;
	private final Signature.@Nullable KeyPair userKey;
	private final Signature.KeyPair deviceKey;

	private final String upstreamHost;
	private final int upstreamPort;
	private final String upstreamScheme;

	private final boolean nameAccess;
	private final boolean announcePeer;

	private Configuration(Builder builder) {
		this.servicePeerId = Objects.requireNonNull(builder.servicePeerId, "Missing service peer id (service.peerId)");
		this.serviceHost = builder.serviceHost;
		this.servicePort = builder.servicePort;

		this.userId = Objects.requireNonNull(builder.userId,
				"Missing user identity: set client.userId or client.userPrivateKey");
		this.userKey = builder.userKey;
		this.deviceKey = Objects.requireNonNull(builder.deviceKey,"Missing device key (client.devicePrivateKey)");

		this.upstreamHost = Objects.requireNonNull(builder.upstreamHost, "Missing upstream host (upstream.host)");
		if (builder.upstreamPort <= 0)
			throw new IllegalArgumentException("Missing upstream port (upstream.port)");
		this.upstreamPort = builder.upstreamPort;
		this.upstreamScheme = builder.upstreamScheme;

		// Name access publishes the session as https://<name>. The super node's reverse proxy
		// (Nginx or Caddy) terminates that TLS and routes each request by its HTTP Host header,
		// so the upstream behind it must speak plain HTTP:
		//  - TLS for the named endpoint belongs at the super node. An HTTPS upstream would make the
		//    reverse proxy open a second TLS session to it through the Active Proxy tunnel, which is
		//    already encrypted, spending the super node's resources for no added protection.
		//  - The result is not end to end: the super node sees the decrypted HTTP. An upstream that
		//    needs TLS all the way through should use the port-mapped endpoint instead, which relays
		//    the bytes untouched and so works with an HTTPS upstream.
		if (builder.nameAccess && !this.upstreamScheme.equals("http"))
			throw new IllegalArgumentException("Name access requires an http upstream, but upstream.scheme is '"
					+ this.upstreamScheme + "': set it to http, or disable nameAccess");

		this.nameAccess = builder.nameAccess;
		this.announcePeer = builder.announcePeer;
	}

	/**
	 * Creates a configuration from a parsed YAML/JSON map.
	 * <p>
	 * Expected structure (see the project README for the full reference):
	 * <pre>{@code
	 * service:
	 *   peerId: <Base58 peer id>     # required
	 *   host: <hostname/ip>          # optional; skips DHT lookup when set
	 *   port: <tcp port>             # optional; defaults to 9090
	 * client:
	 *   userId: <Base58 user id>     # required unless userPrivateKey is given
	 *   userPrivateKey: <Base58|0x>  # optional; derives userId
	 *   devicePrivateKey: <Base58|0x># required
	 * upstream:
	 *   host: <hostname/ip>          # required
	 *   port: <tcp port>             # required
	 *   scheme: <e.g. http>          # optional; URI scheme of the upstream, defaults to http
	 * nameAccess: false              # optional; requires an http upstream
	 * announcePeer: false            # optional
	 * }</pre>
	 * Private keys may be Base58-encoded or {@code 0x}-prefixed hex.
	 *
	 * @param map the configuration map
	 * @return the parsed configuration
	 * @throws IllegalArgumentException if a required section/field is missing or a value is invalid
	 */
	public static Configuration fromMap(Map<String, Object> map) throws IllegalArgumentException {
		return new Builder().fromMap(map).build();
	}

	/**
	 * Serializes this configuration back into a map suitable for YAML/JSON output.
	 * <p>
	 * The result round-trips through {@link #fromMap(Map)}. Note that private keys are written in
	 * clear (Base58), so treat the output as sensitive.
	 *
	 * @return a new mutable map representing this configuration
	 */
	public Map<String, Object> toMap() {
		Objects.requireNonNull(servicePeerId, "Malformed configuration: missing servicePeerId");
		Objects.requireNonNull(upstreamHost, "Malformed configuration: missing upstreamHost");

		Map<String, Object> map = new LinkedHashMap<>();

		Map<String, Object> subMap = new LinkedHashMap<>();
		subMap.put("peerId", servicePeerId.toString());
		if (serviceHost != null)
			subMap.put("host", serviceHost);
		if (servicePort > 0)
			subMap.put("port", servicePort);
		map.put("service", subMap);

		subMap = new LinkedHashMap<>();
		if (userKey != null)
			subMap.put("userPrivateKey", Base58.encode(userKey.privateKey().bytes()));
		else
			subMap.put("userId", userId.toString());
		subMap.put("devicePrivateKey", Base58.encode(deviceKey.privateKey().bytes()));
		map.put("client", subMap);

		subMap = new LinkedHashMap<>();
		subMap.put("host", upstreamHost);
		subMap.put("port", upstreamPort);
		subMap.put("scheme", upstreamScheme);
		map.put("upstream", subMap);

		map.put("nameAccess", nameAccess);
		map.put("announcePeer", announcePeer);
		return map;
	}

	/**
	 * @return the DHT peer id of the Active Proxy super node (never {@code null})
	 */
	public Id getServicePeerId() {
		return servicePeerId;
	}

	/**
	 * @return the fixed super-node host, or {@code null} to resolve it via the DHT
	 */
	public @Nullable String getServiceHost() {
		return serviceHost;
	}

	/**
	 * @return the fixed super-node TCP port, or {@code 0} to resolve it via the DHT
	 */
	public int getServicePort() {
		return servicePort;
	}

	/**
	 * @return the Boson user id this client authenticates as (never {@code null})
	 */
	public Id getUserId() {
		return userId;
	}

	/**
	 * @return the user key pair, or {@code null} if only the user id (not the private key) was
	 *         supplied
	 */
	public Signature.@Nullable KeyPair getUserKey() {
		return userKey;
	}

	/**
	 * @return the per-device key pair identifying this device to the service (never {@code null})
	 */
	public Signature.KeyPair getDeviceKey() {
		return deviceKey;
	}

	/**
	 * @return the host of the local upstream service to expose
	 */
	public String getUpstreamHost() {
		return upstreamHost;
	}

	/**
	 * @return the port of the local upstream service to expose
	 */
	public int getUpstreamPort() {
		return upstreamPort;
	}

	/**
	 * Returns the URI scheme of the upstream service, lower case and without {@code ://}.
	 * <p>
	 * It is used as the scheme of the port-mapped public endpoint, since that endpoint relays bytes
	 * unchanged and so speaks whatever the upstream speaks. The named endpoint is always
	 * {@code https}, regardless of this value.
	 *
	 * @return the upstream scheme, {@code http} unless configured otherwise
	 */
	public String getUpstreamScheme() {
		return upstreamScheme;
	}

	/**
	 * @return {@code true} if a DNS name should be requested for the public endpoint; the name is
	 *         served as an {@code https} URL, with TLS terminated at the super node
	 */
	public boolean isNameAccessEnabled() {
		return nameAccess;
	}

	/**
	 * @return {@code true} if the proxied endpoint should be announced to the DHT for peer discovery
	 */
	public boolean isAnnouncePeer() {
		return announcePeer;
	}

	/**
	 * Creates a new, empty configuration builder.
	 *
	 * @return a fresh {@link Builder}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Fluent builder for {@link Configuration}.
	 * <p>
	 * Set the service peer, the client identity (a user id or user key, plus a device key), and the
	 * upstream service, then call {@link #build()}. A builder is reusable: {@link #build()} returns a
	 * snapshot of the current state and leaves that state intact, so it may be called repeatedly,
	 * optionally with setters applied in between.
	 * <p>
	 * The builder is not thread-safe.
	 */
	@NullUnmarked
	public static class Builder {
		private Id servicePeerId;
		private String serviceHost; // optional
		private int servicePort;	// optional

		private Id userId;
		private Signature.KeyPair userKey;
		private Signature.KeyPair deviceKey;

		private String upstreamHost;
		private int upstreamPort;
		private String upstreamScheme = DEFAULT_SCHEME;

		private boolean nameAccess;
		private boolean announcePeer;

		private Builder() {
		}

		/**
		 * Sets the service peer id together with a fixed host and port (skips DHT resolution).
		 *
		 * @param peerId the super-node peer id
		 * @param host   the super-node host
		 * @param port   the super-node TCP port
		 * @return this builder
		 */
		public Builder service(Id peerId, String host, int port) {
			service(peerId);
			serviceHost(host);
			servicePort(port);
			return this;
		}

		/**
		 * Sets only the service peer id, leaving the host/port to be resolved via the DHT.
		 *
		 * @param servicePeerId the super-node peer id
		 * @return this builder
		 */
		public Builder service(Id servicePeerId) {
			Objects.requireNonNull(servicePeerId, "servicePeerId");
			this.servicePeerId = servicePeerId;
			return this;
		}

		/**
		 * Sets a fixed super-node host, bypassing DHT resolution (requires {@link #servicePort(int)}).
		 *
		 * @param serviceHost the super-node host
		 * @return this builder
		 */
		public Builder serviceHost(@Nullable String serviceHost) {
			this.serviceHost = serviceHost;
			return this;
		}

		/**
		 * Sets a fixed super-node TCP port.
		 *
		 * @param servicePort the port, in {@code 1..65535}
		 * @return this builder
		 * @throws IllegalArgumentException if the port is out of range
		 */
		public Builder servicePort(int servicePort) {
			if (servicePort <= 0 || servicePort > 65535)
				throw new IllegalArgumentException("Invalid service port " + servicePort + ": must be 1-65535");

			this.servicePort = servicePort;
			return this;
		}

		/**
		 * Sets the client identity by user id only (clears any previously set user key).
		 *
		 * @param userId the Boson user id
		 * @return this builder
		 */
		public Builder userId(Id userId) {
			Objects.requireNonNull(userId, "userId");
			this.userId = userId;
			this.userKey = null;
			return this;
		}

		/**
		 * Sets the client identity by user key pair; the user id is derived from it.
		 *
		 * @param userKey the user key pair
		 * @return this builder
		 */
		public Builder userKey(Signature.@Nullable KeyPair userKey) {
			this.userKey = userKey;
			this.userId = userKey == null ? null : Id.of(userKey.publicKey().bytes());
			return this;
		}

		/**
		 * Generates a fresh random user key pair and sets it as the client identity.
		 *
		 * @return this builder
		 */
		public Builder generateUserKey() {
			return userKey(Signature.KeyPair.random());
		}

		/**
		 * Sets the user key from raw private-key bytes.
		 *
		 * @param userKey the private key bytes
		 * @return this builder
		 * @throws IllegalArgumentException if the byte length is not a valid private key
		 */
		public Builder userKey(byte @Nullable [] userKey) {
			if (userKey == null) {
				this.userKey = null;
				this.userId = null;
				return this;
			}

			if (userKey.length != Signature.PrivateKey.BYTES)
				throw new IllegalArgumentException("Invalid user private key: expected " + Signature.PrivateKey.BYTES
						+ " bytes, got " + userKey.length);

			return userKey(Signature.KeyPair.fromPrivateKey(userKey));
		}

		/**
		 * Sets the user key from an encoded private key string (Base58 or {@code 0x}-prefixed hex).
		 *
		 * @param userKey the encoded private key
		 * @return this builder
		 */
		public Builder userKey(@Nullable String userKey) {
			if (userKey == null) {
				this.userKey = null;
				this.userId = null;
				return this;
			}

			return userKey(decodeKey(userKey, "user private key"));
		}

		/**
		 * Sets the per-device key pair.
		 *
		 * @param deviceKey the device key pair
		 * @return this builder
		 */
		public Builder deviceKey(Signature.KeyPair deviceKey) {
			Objects.requireNonNull(deviceKey, "deviceKey");
			this.deviceKey = deviceKey;
			return this;
		}

		/**
		 * Generates a fresh random device key pair and sets it.
		 *
		 * @return this builder
		 */
		public Builder generateDeviceKey() {
			return deviceKey(Signature.KeyPair.random());
		}

		/**
		 * Sets the device key from raw private-key bytes.
		 *
		 * @param deviceKey the private key bytes
		 * @return this builder
		 * @throws IllegalArgumentException if the byte length is not a valid private key
		 */
		public Builder deviceKey(byte[] deviceKey) {
			Objects.requireNonNull(deviceKey, "deviceKey");
			if (deviceKey.length != Signature.PrivateKey.BYTES)
				throw new IllegalArgumentException("Invalid device private key: expected " + Signature.PrivateKey.BYTES
						+ " bytes, got " + deviceKey.length);

			return deviceKey(Signature.KeyPair.fromPrivateKey(deviceKey));
		}

		/**
		 * Sets the device key from an encoded private key string (Base58 or {@code 0x}-prefixed hex).
		 *
		 * @param deviceKey the encoded private key
		 * @return this builder
		 */
		public Builder deviceKey(String deviceKey) {
			Objects.requireNonNull(deviceKey, "deviceKey");
			return deviceKey(decodeKey(deviceKey, "device private key"));
		}

		/**
		 * Decodes an encoded private key, naming the key in the error if the encoding is bad: the
		 * decoders' own messages ({@code Invalid character '0' at position 3}) do not say which of the
		 * configured keys they are about.
		 */
		private static byte[] decodeKey(String encoded, String what) {
			try {
				return encoded.startsWith("0x") ?
						Hex.decode(encoded, 2, encoded.length() - 2) :
						Base58.decode(encoded);
			} catch (IllegalArgumentException e) {
				throw new IllegalArgumentException("Invalid " + what + ": not Base58 or 0x-prefixed hex ("
						+ e.getMessage() + ")", e);
			}
		}

		/**
		 * Sets the local upstream service to expose.
		 *
		 * @param host   the upstream host
		 * @param port   the upstream port
		 * @param scheme the upstream's URI scheme, as accepted by {@link #upstreamScheme(String)}
		 * @return this builder
		 * @throws IllegalArgumentException if the port is out of range or the scheme is invalid
		 */
		public Builder upstream(String host, int port, String scheme) {
			upstreamHost(host);
			upstreamPort(port);
			upstreamScheme(scheme);
			return this;
		}

		/**
		 * Sets the local upstream host to expose.
		 *
		 * @param upstreamHost the upstream host
		 * @return this builder
		 */
		public Builder upstreamHost(String upstreamHost) {
			Objects.requireNonNull(upstreamHost, "upstreamHost");
			this.upstreamHost = upstreamHost;
			return this;
		}

		/**
		 * Sets the local upstream port to expose.
		 *
		 * @param upstreamPort the port, in {@code 1..65535}
		 * @return this builder
		 * @throws IllegalArgumentException if the port is out of range
		 */
		public Builder upstreamPort(int upstreamPort) {
			if (upstreamPort <= 0 || upstreamPort > 65535)
				throw new IllegalArgumentException("Invalid upstream port " + upstreamPort + ": must be 1-65535");

			this.upstreamPort = upstreamPort;
			return this;
		}

		/**
		 * Sets the URI scheme of the upstream service, which becomes the scheme of the port-mapped
		 * public endpoint.
		 * <p>
		 * The value is normalized before it is checked: surrounding whitespace is trimmed, it is lower
		 * cased, and one trailing {@code ://} is removed, so {@code HTTP://} and {@code http} are the
		 * same. The result must then be a valid URI scheme (RFC 3986: a letter followed by letters,
		 * digits, {@code +}, {@code -} or {@code .}).
		 * <p>
		 * Defaults to {@code http}. An upstream that does not speak HTTP - SSH, a database, MQTT -
		 * should set its own scheme ({@code tcp}, {@code ssh}, {@code mqtt}, ...), or its endpoint
		 * will be advertised as {@code http}. Name access accepts only {@code http}; see
		 * {@link #nameAccess(boolean)}.
		 *
		 * @param scheme the scheme, for example {@code http}, {@code https} or {@code tcp}
		 * @return this builder
		 * @throws IllegalArgumentException if the normalized value is not a valid URI scheme
		 */
		public Builder upstreamScheme(String scheme) {
			Objects.requireNonNull(scheme, "scheme");
			String s = scheme.trim().toLowerCase(Locale.ROOT);
			if (s.endsWith("://"))
				s = s.substring(0, s.length() - 3);

			if (!SCHEME_PATTERN.matcher(s).matches())
				throw new IllegalArgumentException("Invalid upstream scheme '" + scheme
						+ "': expected a URI scheme such as http, https or tcp");

			this.upstreamScheme = s;
			return this;
		}

		/**
		 * Sets whether to request a DNS name for the public endpoint.
		 * <p>
		 * The name is served as {@code https://<name>}: the super node terminates TLS and routes
		 * requests by their HTTP Host header, so the upstream must be plain {@code http} and
		 * {@link #build()} rejects any other scheme. The super node may also decline the request,
		 * depending on its configuration and the user's subscription; the session then carries on
		 * with the port-mapped endpoint only.
		 *
		 * @param nameAccess {@code true} to request name access
		 * @return this builder
		 */
		public Builder nameAccess(boolean nameAccess) {
			this.nameAccess = nameAccess;
			return this;
		}

		/**
		 * Sets whether to announce the proxied endpoint to the DHT for peer discovery.
		 *
		 * @param announcePeer {@code true} to announce
		 * @return this builder
		 */
		public Builder announcePeer(boolean announcePeer) {
			this.announcePeer = announcePeer;
			return this;
		}

		/**
		 * Applies a parsed YAML/JSON configuration map to this builder.
		 * <p>
		 * The accepted structure is the one documented on {@link Configuration#fromMap(Map)}. The
		 * client identity may be given as {@code userId}, as {@code userPrivateKey}, or as both; the
		 * private key is applied last and therefore wins, supplying the user id itself.
		 * <p>
		 * Absent optional keys are applied as their defaults rather than skipped, so this
		 * <em>overwrites</em> the corresponding builder state instead of merging into it: calling
		 * {@code nameAccess(true).fromMap(map)} with a map that has no {@code nameAccess} key leaves
		 * name access disabled. Apply setters after this method, not before, to override what the map
		 * specifies.
		 *
		 * @param map the configuration map
		 * @return this builder
		 * @throws IllegalArgumentException if a required section/field is missing or a value is invalid
		 */
		public Builder fromMap(Map<String, Object> map) throws IllegalArgumentException {
			ConfigMap cm = new ConfigMap(map);

			section(cm, "service", service -> {
				service(service.getId("peerId"));
				serviceHost(service.getString("host", null));
				servicePort(service.getPort("port", DEFAULT_PORT));
			});

			section(cm, "client", client -> {
				if (client.containsKey("userId"))
					userId(client.getId("userId", null));
				if (client.containsKey("userPrivateKey"))
					userKey(client.getString("userPrivateKey", null));
				deviceKey(client.getString("devicePrivateKey"));
			});

			section(cm, "upstream", upstream -> {
				upstreamHost(upstream.getString("host"));
				upstreamPort(upstream.getPort("port"));
				upstreamScheme(upstream.getString("scheme", DEFAULT_SCHEME));
			});

			nameAccess(cm.getBoolean("nameAccess", false));
			announcePeer(cm.getBoolean("announcePeer", false));

			return this;
		}

		/**
		 * Applies one required section of the configuration map, prefixing any error with the
		 * section's name: both {@code service} and {@code upstream} have a {@code host} and a
		 * {@code port}, so a bare {@code Missing value - host} would not say which one to fix.
		 */
		private static void section(ConfigMap cm, String name, Consumer<ConfigMap> body) {
			ConfigMap section = cm.getObject(name);
			if (section == null || section.isEmpty())
				throw new IllegalArgumentException("Missing or empty '" + name + "' section");

			try {
				body.accept(section);
			} catch (IllegalArgumentException e) {
				throw new IllegalArgumentException(name + ": " + e.getMessage(), e);
			}
		}

		/**
		 * Builds an immutable {@link Configuration} from the current builder state.
		 *
		 * @return the built configuration
		 * @throws IllegalStateException if the configuration is incomplete or invalid; the message
		 *                               identifies the offending field
		 */
		public Configuration build() {
			try {
				return new Configuration(this);
			} catch (NullPointerException | IllegalArgumentException e) {
				throw new IllegalStateException("Invalid configuration: " + e.getMessage(), e);
			}
		}
	}
}
