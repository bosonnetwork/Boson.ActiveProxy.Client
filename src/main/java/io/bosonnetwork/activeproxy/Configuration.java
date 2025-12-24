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
import java.util.Map;
import java.util.Objects;

import io.bosonnetwork.Id;
import io.bosonnetwork.crypto.Signature;
import io.bosonnetwork.utils.Base58;
import io.bosonnetwork.utils.ConfigMap;
import io.bosonnetwork.utils.Hex;

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
	}

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
				throw new IllegalArgumentException("config error, invalid client userPrivateKey", e);
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
			throw new IllegalArgumentException("config error, invalid client devicePrivateKey", e);
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

	public Id getServicePeerId() {
		return servicePeerId;
	}

	public String getServiceHost() {
		return serviceHost;
	}

	protected void setServiceHost(String serviceHost) {
		this.serviceHost = serviceHost;
	}

	public int getServicePort() {
		return servicePort;
	}

	protected void setServicePort(int servicePort) {
		this.servicePort = servicePort;
	}

	public Id getUserId() {
		return userId;
	}

	public Signature.KeyPair getUserKey() {
		return userKey;
	}

	public Signature.KeyPair getDeviceKey() {
		return deviceKey;
	}

	public String getUpstreamHost() {
		return upstreamHost;
	}

	public int getUpstreamPort() {
		return upstreamPort;
	}

	public String getUpstreamScheme() {
		return upstreamScheme;
	}

	public boolean isNameAccessEnabled() {
		return nameAccess;
	}

	public boolean isAnnouncePeer() {
		return announcePeer;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder {
		private Configuration config;

		private Builder() {
			config = new Configuration();
		}

		private Configuration config() {
			return config == null ? config = new Configuration() : config;
		}

		public Builder service(Id peerId, String host, int port) {
			servicePeerId(peerId);
			serviceHost(host);
			servicePort(port);
			return this;
		}

		public Builder servicePeerId(Id servicePeerId) {
			Objects.requireNonNull(servicePeerId, "servicePeerId");
			config().servicePeerId = servicePeerId;
			return this;
		}

		public Builder serviceHost(String serviceHost) {
			Objects.requireNonNull(serviceHost, "serviceHost");
			config().serviceHost = serviceHost;
			return this;
		}

		public Builder servicePort(int servicePort) {
			if (servicePort <= 0 || servicePort > 65535)
				throw new IllegalArgumentException("Invalid servicePort");

			config().servicePort = servicePort;
			return this;
		}

		public Builder userId(Id userId) {
			Objects.requireNonNull(userId, "userId");
			config().userId = userId;
			config().userKey = null;
			return this;
		}

		public Builder userKey(Signature.KeyPair userKey) {
			Objects.requireNonNull(userKey, "userKey");
			config().userKey = userKey;
			config().userId = Id.of(userKey.publicKey().bytes());
			return this;
		}

		public Builder generateUserKey() {
			return userKey(Signature.KeyPair.random());
		}

		public Builder userKey(byte[] userKey) {
			Objects.requireNonNull(userKey, "userKey");
			if (userKey.length != Signature.PrivateKey.BYTES)
				throw new IllegalArgumentException("Invalid private key");

			return userKey(Signature.KeyPair.fromPrivateKey(userKey));
		}

		public Builder userKey(String userKey) {
			Objects.requireNonNull(userKey, "userKey");
			byte[] sk = userKey.startsWith("0x") ?
					Hex.decode(userKey, 2, userKey.length() - 2) :
					Base58.decode(userKey);
			return userKey(sk);
		}

		public Builder deviceKey(Signature.KeyPair deviceKey) {
			Objects.requireNonNull(deviceKey, "deviceKey");
			config().deviceKey = deviceKey;
			return this;
		}

		public Builder generateDeviceKey() {
			return deviceKey(Signature.KeyPair.random());
		}

		public Builder deviceKey(byte[] deviceKey) {
			Objects.requireNonNull(deviceKey, "deviceKey");
			if (deviceKey.length != Signature.PrivateKey.BYTES)
				throw new IllegalArgumentException("Invalid private key");

			return deviceKey(Signature.KeyPair.fromPrivateKey(deviceKey));
		}

		public Builder deviceKey(String deviceKey) {
			Objects.requireNonNull(deviceKey, "deviceKey");
			byte[] sk = deviceKey.startsWith("0x") ?
					Hex.decode(deviceKey, 2, deviceKey.length() - 2) :
					Base58.decode(deviceKey);
			return deviceKey(sk);
		}

		public Builder upstream(String host, int port, String scheme) {
			upstreamHost(host);
			upstreamPort(port);
			upstreamScheme(scheme);
			return this;
		}

		public Builder upstreamHost(String upstreamHost) {
			Objects.requireNonNull(upstreamHost, "upstreamHost");
			config().upstreamHost = upstreamHost;
			return this;
		}

		public Builder upstreamPort(int upstreamPort) {
			if (upstreamPort <= 0 || upstreamPort > 65535)
				throw new IllegalArgumentException("Invalid upstreamPort");

			config().upstreamPort = upstreamPort;
			return this;
		}

		public Builder upstreamScheme(String scheme) {
			Objects.requireNonNull(scheme, "scheme");
			config().upstreamScheme = scheme;
			return this;
		}

		public Builder nameAccess(boolean nameAccess) {
			config().nameAccess = nameAccess;
			return this;
		}

		public Builder announcePeer(boolean announcePeer) {
			config().announcePeer = announcePeer;
			return this;
		}

		private boolean verify() {
			return config().servicePeerId != null && config().userId != null && config().deviceKey != null
					&& config().upstreamHost != null && config().upstreamPort > 0;
		}

		public Configuration build() {
			if (!verify())
				throw new IllegalStateException("Incomplete configuration");

			Configuration c = config();
			config = null;
			return c;
		}
	}
}