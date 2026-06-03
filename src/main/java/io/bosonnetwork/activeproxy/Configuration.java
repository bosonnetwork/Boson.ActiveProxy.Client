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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

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
	private static final String DEFAULT_SCHEME = "tcp://";

	private Id servicePeerId;
	private String serviceHost; // optional
	private int servicePort;	// optional

	private Id userId;
	private Signature.KeyPair userKey;
	private Signature.KeyPair deviceKey;

	private String upstreamHost;
	private int upstreamPort;
	private String upstreamScheme;

	private boolean nameAccess;
	private boolean announcePeer;

	private Configuration() {
		this.upstreamScheme = DEFAULT_SCHEME;
	}

	/**
	 * Creates a configuration from a parsed YAML/JSON map.
	 * <p>
	 * Expected structure (see the project README for the full reference):
	 * <pre>{@code
	 * service:
	 *   peerId: <Base58 peer id>     # required
	 *   host: <hostname/ip>          # optional; skips DHT lookup when set with port
	 *   port: <tcp port>             # optional
	 * client:
	 *   userId: <Base58 user id>     # required unless userPrivateKey is given
	 *   userPrivateKey: <Base58|0x>  # optional; derives userId
	 *   devicePrivateKey: <Base58|0x># required
	 * upstream:
	 *   host: <hostname/ip>          # required
	 *   port: <tcp port>             # required
	 *   scheme: <e.g. http://>       # optional; defaults to tcp://
	 * nameAccess: false              # optional
	 * announcePeer: false            # optional
	 * }</pre>
	 * Private keys may be Base58-encoded or {@code 0x}-prefixed hex.
	 *
	 * @param map the configuration map
	 * @return the parsed configuration
	 * @throws IllegalArgumentException if a required section/field is missing or a value is invalid
	 */
	public static Configuration fromMap(Map<String, Object> map) throws IllegalArgumentException {
		ConfigMap cm = new ConfigMap(map);
		Configuration config = new Configuration();

		ConfigMap service = cm.getObject("service");
		if (service == null || service.isEmpty())
			throw new IllegalArgumentException("Missing service");

		config.servicePeerId = service.getId("peerId");
		// optional
		config.serviceHost = service.getString("host", null);
		config.servicePort = service.getPort("port", 0);

		ConfigMap client = cm.getObject("client");
		if (client == null || client.isEmpty())
			throw new IllegalArgumentException("Missing client");

		config.userId = client.getId("userId", null);
		String sk = client.getString("userPrivateKey", null);
		if (sk == null) {
			if (config.userId == null)
				throw new IllegalArgumentException("Missing client userId or userPrivateKey");
		} else {
			try {
				config.userKey = Signature.KeyPair.fromPrivateKey(sk.startsWith("0x") ?
						Hex.decode(sk, 2, sk.length() - 2) :
						Base58.decode(sk));
			} catch (Exception e) {
				throw new IllegalArgumentException("Invalid client userPrivateKey: not a valid Base58 or 0x-hex private key", e);
			}

			Id uid = Id.of(config.userKey.publicKey().bytes());
			if (config.userId != null && !config.userId.equals(uid))
				throw new IllegalArgumentException("Both client userId and userPrivateKey are set, but they don't match");
			config.userId = uid;
		}

		sk = client.getString("devicePrivateKey", null);
		if (sk == null || sk.isEmpty())
			throw new IllegalArgumentException("Missing client devicePrivateKey");

		try {
			config.deviceKey = Signature.KeyPair.fromPrivateKey(sk.startsWith("0x") ?
					Hex.decode(sk, 2, sk.length() - 2) :
					Base58.decode(sk));
		} catch (Exception e) {
			throw new IllegalArgumentException("Invalid client devicePrivateKey: not a valid Base58 or 0x-hex private key", e);
		}

		ConfigMap upstream = cm.getObject("upstream");
		if (upstream == null || upstream.isEmpty())
			throw new IllegalArgumentException("Missing upstream");

		config.upstreamHost = upstream.getString("host", null);
		if (config.upstreamHost == null || config.upstreamHost.isEmpty())
			throw new IllegalArgumentException("Missing upstream host");
		config.upstreamPort = upstream.getPort("port");
		config.upstreamScheme = upstream.getString("scheme", DEFAULT_SCHEME);

		config.nameAccess = cm.getBoolean("nameAccess", false);
		config.announcePeer = cm.getBoolean("announcePeer", false);

		return config;
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
		Map<String, Object> map = new LinkedHashMap<>();

		Map<String, Object> subMap = new LinkedHashMap<>();
		subMap.put("peerId", servicePeerId.toString());
		if (serviceHost != null)
			subMap.put("host", serviceHost);
		if (servicePort > 0)
			subMap.put("port", servicePort);
		map.put("service", subMap);

		subMap = new LinkedHashMap<>();
		if (userId != null)
			subMap.put("userId", userId.toString());
		if (userKey != null)
			subMap.put("userPrivateKey", Base58.encode(userKey.privateKey().bytes()));
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
	public String getServiceHost() {
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
	public Signature.KeyPair getUserKey() {
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
	 * @return the scheme prefix applied to the public endpoint string (defaults to {@code tcp://})
	 */
	public String getUpstreamScheme() {
		return upstreamScheme;
	}

	/**
	 * @return {@code true} if a DNS name should be requested for the public endpoint
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
	 * upstream service, then call {@link #build()}. A builder is reusable: each {@link #build()}
	 * returns a snapshot and resets the builder to an empty state.
	 * <p>
	 * The builder is not thread-safe.
	 */
	public static class Builder {
		private Configuration config;

		private Builder() {
			config = new Configuration();
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
			config.servicePeerId = servicePeerId;
			return this;
		}

		/**
		 * Sets a fixed super-node host, bypassing DHT resolution (requires {@link #servicePort(int)}).
		 *
		 * @param serviceHost the super-node host
		 * @return this builder
		 */
		public Builder serviceHost(String serviceHost) {
			Objects.requireNonNull(serviceHost, "serviceHost");
			config.serviceHost = serviceHost;
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
				throw new IllegalArgumentException("Invalid servicePort: " + servicePort + " (must be 1-65535)");

			config.servicePort = servicePort;
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
			config.userId = userId;
			config.userKey = null;
			return this;
		}

		/**
		 * Sets the client identity by user key pair; the user id is derived from it.
		 *
		 * @param userKey the user key pair
		 * @return this builder
		 */
		public Builder userKey(Signature.KeyPair userKey) {
			Objects.requireNonNull(userKey, "userKey");
			config.userKey = userKey;
			config.userId = Id.of(userKey.publicKey().bytes());
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
		public Builder userKey(byte[] userKey) {
			Objects.requireNonNull(userKey, "userKey");
			if (userKey.length != Signature.PrivateKey.BYTES)
				throw new IllegalArgumentException("Invalid userKey: expected a " + Signature.PrivateKey.BYTES
						+ "-byte private key, got " + userKey.length + " bytes");

			return userKey(Signature.KeyPair.fromPrivateKey(userKey));
		}

		/**
		 * Sets the user key from an encoded private key string (Base58 or {@code 0x}-prefixed hex).
		 *
		 * @param userKey the encoded private key
		 * @return this builder
		 */
		public Builder userKey(String userKey) {
			Objects.requireNonNull(userKey, "userKey");
			byte[] sk = userKey.startsWith("0x") ?
					Hex.decode(userKey, 2, userKey.length() - 2) :
					Base58.decode(userKey);
			return userKey(sk);
		}

		/**
		 * Sets the per-device key pair.
		 *
		 * @param deviceKey the device key pair
		 * @return this builder
		 */
		public Builder deviceKey(Signature.KeyPair deviceKey) {
			Objects.requireNonNull(deviceKey, "deviceKey");
			config.deviceKey = deviceKey;
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
				throw new IllegalArgumentException("Invalid deviceKey: expected a " + Signature.PrivateKey.BYTES
						+ "-byte private key, got " + deviceKey.length + " bytes");

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
			byte[] sk = deviceKey.startsWith("0x") ?
					Hex.decode(deviceKey, 2, deviceKey.length() - 2) :
					Base58.decode(deviceKey);
			return deviceKey(sk);
		}

		/**
		 * Sets the local upstream service to expose.
		 *
		 * @param host   the upstream host
		 * @param port   the upstream port
		 * @param scheme the scheme prefix for the public endpoint string (e.g. {@code http://})
		 * @return this builder
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
			config.upstreamHost = upstreamHost;
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
				throw new IllegalArgumentException("Invalid upstreamPort: " + upstreamPort + " (must be 1-65535)");

			config.upstreamPort = upstreamPort;
			return this;
		}

		/**
		 * Sets the scheme prefix applied to the public endpoint string.
		 *
		 * @param scheme the scheme (e.g. {@code http://}); defaults to {@code tcp://} if never set
		 * @return this builder
		 */
		public Builder upstreamScheme(String scheme) {
			Objects.requireNonNull(scheme, "scheme");
			config.upstreamScheme = scheme;
			return this;
		}

		/**
		 * Sets whether to request a DNS name for the public endpoint (requires a subscription).
		 *
		 * @param nameAccess {@code true} to request name access
		 * @return this builder
		 */
		public Builder nameAccess(boolean nameAccess) {
			config.nameAccess = nameAccess;
			return this;
		}

		/**
		 * Sets whether to announce the proxied endpoint to the DHT for peer discovery.
		 *
		 * @param announcePeer {@code true} to announce
		 * @return this builder
		 */
		public Builder announcePeer(boolean announcePeer) {
			config.announcePeer = announcePeer;
			return this;
		}

		/**
		 * Builds an immutable {@link Configuration} from the current builder state and resets the
		 * builder so it can be reused.
		 *
		 * @return the built configuration
		 * @throws IllegalStateException if the configuration is incomplete; the message names the
		 *                               missing required fields
		 */
		public Configuration build() {
			List<String> missing = new ArrayList<>();
			if (config.servicePeerId == null)
				missing.add("service peerId");
			if (config.userId == null)
				missing.add("client userId or userKey");
			if (config.deviceKey == null)
				missing.add("client deviceKey");
			if (config.upstreamHost == null)
				missing.add("upstream host");
			if (config.upstreamPort <= 0)
				missing.add("upstream port");

			if (!missing.isEmpty())
				throw new IllegalStateException("Incomplete configuration, missing: " + String.join(", ", missing));

			Configuration c = config;
			config = new Configuration();
			return c;
		}
	}
}