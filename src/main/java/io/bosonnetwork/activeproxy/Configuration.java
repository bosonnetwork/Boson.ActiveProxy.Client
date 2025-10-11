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
import io.bosonnetwork.utils.Hex;

public class Configuration {
	private static final String DEFAULT_SCHEME = "tcp://";

	private Id servicePeerId;
	private String serviceHost; // optional
	private int servicePort;	// optional

	private Signature.KeyPair userKey;
	private Signature.KeyPair deviceKey;

	private String upstreamHost;
	private int upstreamPort;
	private String upstreamScheme;

	private boolean nameAccess;
	private boolean announcePeer;

	public Configuration(Map<String, Object> config) throws IllegalArgumentException {
		try {
			@SuppressWarnings("unchecked")
			Map<String, Object> service = (Map<String, Object>) config.get("service");
			if (service == null || service.isEmpty())
				throw new IllegalArgumentException("Missing service");

			String s = (String) service.get("peerId");
			if (s == null || s.isEmpty())
				throw new IllegalArgumentException("Missing service peerId");
			servicePeerId = Id.of(s);

			// optional
			serviceHost = (String) service.get("host");
			servicePort = (int) service.get("port");

			@SuppressWarnings("unchecked")
			Map<String, Object> client = (Map<String, Object>) config.get("client");
			if (client == null || client.isEmpty())
				throw new IllegalArgumentException("Missing client");

			s = (String) client.get("userPrivateKey");
			if (s == null || s.isEmpty())
				throw new IllegalArgumentException("Missing client userPrivateKey");
			userKey = Signature.KeyPair.fromPrivateKey(s.startsWith("0x") ?
					Hex.decode(s, 2, s.length() - 2) : Base58.decode(s));

			s = (String) client.get("devicePrivateKey");
			if (s == null || s.isEmpty())
				throw new IllegalArgumentException("Missing client devicePrivateKey");
			deviceKey = Signature.KeyPair.fromPrivateKey(s.startsWith("0x") ?
					Hex.decode(s, 2, s.length() - 2) : Base58.decode(s));

			@SuppressWarnings("unchecked")
			Map<String, Object> upstream = (Map<String, Object>) config.get("upstream");
			if (upstream == null || upstream.isEmpty())
				throw new IllegalArgumentException("Missing upstream");

			upstreamHost = (String) upstream.get("host");
			if (upstreamHost == null || upstreamHost.isEmpty())
				throw new IllegalArgumentException("Missing upstream host");
			upstreamPort = (int) upstream.get("port");
			if (upstreamPort <= 0)
				throw new IllegalArgumentException("Invalid upstream port");

			upstreamScheme = (String) upstream.getOrDefault("scheme", DEFAULT_SCHEME);

			nameAccess = (boolean) config.getOrDefault("nameAccess", false);
			announcePeer = (boolean) config.getOrDefault("announcePeer", false);

			if (!isQualified())
				throw new IllegalArgumentException("Incomplete configuration");
		} catch (ClassCastException e) {
			throw new IllegalArgumentException("Invalid config", e);
		}
	}

	private Configuration() {
		nameAccess = false;
		announcePeer = false;
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

	@SuppressWarnings("BooleanMethodIsAlwaysInverted")
	private boolean isQualified() {
		return servicePeerId != null && userKey != null && deviceKey != null && upstreamHost != null && upstreamPort > 0;
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

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder {
		private Configuration config;

		private Builder() {
			config = new Configuration();
		}

		public Builder service(Id peerId, String host, int port) {
			servicePeerId(peerId);
			serviceHost(host);
			servicePort(port);
			return this;
		}

		public Builder servicePeerId(Id servicePeerId) {
			Objects.requireNonNull(servicePeerId, "servicePeerId");
			config.servicePeerId = servicePeerId;
			return this;
		}

		public Builder serviceHost(String serviceHost) {
			Objects.requireNonNull(serviceHost, "serviceHost");
			config.serviceHost = serviceHost;
			return this;
		}

		public Builder servicePort(int servicePort) {
			if (servicePort <= 0 || servicePort > 65535)
				throw new IllegalArgumentException("Invalid servicePort");

			config.servicePort = servicePort;
			return this;
		}

		public Builder userKey(Signature.KeyPair userKey) {
			Objects.requireNonNull(userKey, "userKey");
			config.userKey = userKey;
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
			config.deviceKey = deviceKey;
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
			config.upstreamHost = upstreamHost;
			return this;
		}

		public Builder upstreamPort(int upstreamPort) {
			if (upstreamPort <= 0 || upstreamPort > 65535)
				throw new IllegalArgumentException("Invalid upstreamPort");

			config.upstreamPort = upstreamPort;
			return this;
		}

		public Builder upstreamScheme(String scheme) {
			Objects.requireNonNull(scheme, "scheme");

			config.upstreamScheme = scheme;
			return this;
		}

		public Builder nameAccess(boolean nameAccess) {
			config.nameAccess = nameAccess;
			return this;
		}

		public Builder announcePeer(boolean announcePeer) {
			config.announcePeer = announcePeer;
			return this;
		}

		public Configuration build() {
			if (!config.isQualified())
				throw new IllegalStateException("Incomplete configuration");

			Configuration c = config;
			config = null;
			return c;
		}
	}
}