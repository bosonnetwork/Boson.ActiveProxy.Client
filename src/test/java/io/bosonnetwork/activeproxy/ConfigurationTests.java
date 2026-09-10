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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import io.bosonnetwork.Id;
import io.bosonnetwork.crypto.Signature;
import io.bosonnetwork.utils.Base58;
import io.bosonnetwork.utils.FileUtils;
import io.bosonnetwork.utils.Hex;
import io.bosonnetwork.json.Json;

public class ConfigurationTests {
	private static final Path testDir = Paths.get(System.getProperty("java.io.tmpdir"), "boson", "ActiveProxyClient");

	private static final Id SERVICE_PEER_ID = Id.random();
	private static final Signature.KeyPair USER_KEY = Signature.KeyPair.random();
	private static final Signature.KeyPair DEVICE_KEY = Signature.KeyPair.random();

	private static final Id USER_ID = Id.of(USER_KEY.publicKey().bytes());
	private static final String USER_PRIVATE_KEY = Base58.encode(USER_KEY.privateKey().bytes());
	private static final String DEVICE_PRIVATE_KEY = Base58.encode(DEVICE_KEY.privateKey().bytes());

	@BeforeAll
	static void setup() throws Exception {
		if (Files.exists(testDir))
			FileUtils.deleteFile(testDir);

		Files.createDirectories(testDir);
	}

	@AfterAll
	static void tearDown() throws Exception {
		if (Files.exists(testDir))
			FileUtils.deleteFile(testDir);
	}

	@Test
	void testBuildConfig() {
		Configuration config = Configuration.builder()
				.service(Id.random())
				.serviceHost("10.0.0.1")
				.servicePort(10090)
				.userId(Id.random())
				.generateDeviceKey()
				.upstreamHost("192.168.1.8")
				.upstreamPort(8888)
				.upstreamScheme("http")
				.nameAccess(false)
				.announcePeer(false)
				.build();
		assertNotNull(config);

		config = Configuration.builder()
				.service(Id.random())
				.userKey(Base58.encode(Signature.KeyPair.random().privateKey().bytes()))
				.deviceKey("0x" + Hex.encode(Signature.KeyPair.random().privateKey().bytes()))
				.upstreamHost("192.168.1.8")
				.upstreamPort(8888)
				.build();
		assertNotNull(config);

		assertThrows(IllegalStateException.class, () -> Configuration.builder().build());

		assertThrows(IllegalStateException.class, () ->
			Configuration.builder()
					.userKey(Signature.KeyPair.random())
					.deviceKey(Signature.KeyPair.random())
					.upstreamHost("192.168.1.8")
					.upstreamPort(8888)
					.upstreamScheme("http")
					.build()
		);

		assertThrows(IllegalStateException.class, () ->
				Configuration.builder()
						.service(Id.random())
						.deviceKey(Signature.KeyPair.random())
						.upstreamHost("192.168.1.8")
						.upstreamPort(8888)
						.build()
		);

		assertThrows(IllegalStateException.class, () ->
				Configuration.builder()
						.service(Id.random())
						.userKey(Signature.KeyPair.random())
						.deviceKey(Signature.KeyPair.random())
						.upstreamPort(8888)
						.upstreamScheme("http")
						.build()
		);
	}

	@Test
	void testUpstreamPortValidation() {
		// The setter rejects out-of-range ports immediately.
		assertThrows(IllegalArgumentException.class, () -> Configuration.builder().upstreamPort(0));
		assertThrows(IllegalArgumentException.class, () -> Configuration.builder().upstreamPort(-1));
		assertThrows(IllegalArgumentException.class, () -> Configuration.builder().upstreamPort(70000));

		// build() rejects a configuration whose upstream port was never set (defaults to 0).
		assertThrows(IllegalStateException.class, () ->
				Configuration.builder()
						.service(Id.random())
						.userKey(Signature.KeyPair.random())
						.deviceKey(Signature.KeyPair.random())
						.upstreamHost("192.168.1.8")
						.build());
	}

	@Test
	void saveAndLoad() throws Exception {
		Signature.KeyPair userKey = Signature.KeyPair.random();
		Signature.KeyPair deviceKey = Signature.KeyPair.random();

		Configuration config = Configuration.builder()
				.service(Id.random(), "192.168.8.80", 9090)
				.userKey(userKey)
				.deviceKey(deviceKey)
				.upstream("127.0.0.1", 8888, "http")
				.nameAccess(true)
				.announcePeer(false)
				.build();

		Map<String, Object> configMap = config.toMap();
		Path testFile = testDir.resolve("config.yaml");
		Json.yamlMapper().writeValue(testFile.toFile(), configMap);

		System.out.println("User id: " + Id.of(userKey.publicKey().bytes()));
		System.out.println("Device id: " + Id.of(deviceKey.publicKey().bytes()));

		System.out.println("Configuration:\n-------------");
		Files.readAllLines(testFile).forEach(System.out::println);

		Map<String, Object> loadedMap = Json.yamlMapper().readValue(testFile.toFile(), Json.mapType());
		assertEquals(configMap, loadedMap);

		Configuration loaded = Configuration.fromMap(loadedMap);
		assertEquals(config.getServicePeerId(), loaded.getServicePeerId());
		assertEquals(config.getServiceHost(), loaded.getServiceHost());
		assertEquals(config.getServicePort(), loaded.getServicePort());
		assertEquals(config.getUserKey(), loaded.getUserKey());
		assertEquals(config.getDeviceKey(), loaded.getDeviceKey());
		assertEquals(config.getUpstreamHost(), loaded.getUpstreamHost());
		assertEquals(config.getUpstreamPort(), loaded.getUpstreamPort());
		assertEquals(config.getUpstreamScheme(), loaded.getUpstreamScheme());
		assertEquals(config.isNameAccessEnabled(), loaded.isNameAccessEnabled());
		assertEquals(config.isAnnouncePeer(), loaded.isAnnouncePeer());
	}

	/**
	 * A fully populated map; individual tests strip or override the entries they are about.
	 */
	private static Map<String, Object> fullMap() {
		Map<String, Object> service = new LinkedHashMap<>();
		service.put("peerId", SERVICE_PEER_ID.toString());
		service.put("host", "192.168.8.80");
		service.put("port", 9090);

		Map<String, Object> client = new LinkedHashMap<>();
		client.put("userId", USER_ID.toString());
		client.put("devicePrivateKey", DEVICE_PRIVATE_KEY);

		Map<String, Object> upstream = new LinkedHashMap<>();
		upstream.put("host", "127.0.0.1");
		upstream.put("port", 8888);
		upstream.put("scheme", "http");

		Map<String, Object> map = new LinkedHashMap<>();
		map.put("service", service);
		map.put("client", client);
		map.put("upstream", upstream);
		map.put("nameAccess", true);
		map.put("announcePeer", true);
		return map;
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> section(Map<String, Object> map, String name) {
		return (Map<String, Object>) map.get(name);
	}

	@Test
	void fromMapParsesEveryField() {
		Configuration config = Configuration.fromMap(fullMap());

		assertEquals(SERVICE_PEER_ID, config.getServicePeerId());
		assertEquals("192.168.8.80", config.getServiceHost());
		assertEquals(9090, config.getServicePort());
		assertEquals(USER_ID, config.getUserId());
		assertEquals(DEVICE_KEY, config.getDeviceKey());
		assertEquals("127.0.0.1", config.getUpstreamHost());
		assertEquals(8888, config.getUpstreamPort());
		assertEquals("http", config.getUpstreamScheme());
		assertTrue(config.isNameAccessEnabled());
		assertTrue(config.isAnnouncePeer());
	}

	/**
	 * Regression: a client section carrying only {@code userId} (no {@code userPrivateKey}) must
	 * keep that id. Reading an absent {@code userPrivateKey} as {@code null} and feeding it to the
	 * builder used to clear the just-parsed userId, so this configuration shape failed to build.
	 */
	@Test
	void userIdOnlyClientIsAccepted() {
		Map<String, Object> map = fullMap();
		assertFalse(section(map, "client").containsKey("userPrivateKey"));

		Configuration config = Configuration.fromMap(map);

		assertEquals(USER_ID, config.getUserId());
		assertNull(config.getUserKey(), "no private key was configured");
	}

	/**
	 * The mirror case: only {@code userPrivateKey}, with the id derived from it.
	 */
	@Test
	void userPrivateKeyOnlyClientDerivesUserId() {
		Map<String, Object> map = fullMap();
		Map<String, Object> client = section(map, "client");
		client.remove("userId");
		client.put("userPrivateKey", USER_PRIVATE_KEY);

		Configuration config = Configuration.fromMap(map);

		assertEquals(USER_ID, config.getUserId());
		assertEquals(USER_KEY, config.getUserKey());
	}

	/**
	 * When both are present the private key is applied last and therefore wins; it also supplies
	 * the id, so a redundant (but matching) userId is harmless.
	 */
	@Test
	void userPrivateKeyTakesPrecedenceOverUserId() {
		Map<String, Object> map = fullMap();
		Map<String, Object> client = section(map, "client");
		client.put("userId", Id.random().toString()); // deliberately not the key's id
		client.put("userPrivateKey", USER_PRIVATE_KEY);

		Configuration config = Configuration.fromMap(map);

		assertEquals(USER_KEY, config.getUserKey());
		assertEquals(USER_ID, config.getUserId(), "userId must follow the private key");
	}

	@Test
	void clientWithoutAnyUserIdentityIsRejected() {
		Map<String, Object> map = fullMap();
		section(map, "client").remove("userId");

		assertThrows(IllegalStateException.class, () -> Configuration.fromMap(map));
	}

	@Test
	void hexEncodedPrivateKeysAreAccepted() {
		Map<String, Object> map = fullMap();
		Map<String, Object> client = section(map, "client");
		client.remove("userId");
		client.put("userPrivateKey", "0x" + Hex.encode(USER_KEY.privateKey().bytes()));
		client.put("devicePrivateKey", "0x" + Hex.encode(DEVICE_KEY.privateKey().bytes()));

		Configuration config = Configuration.fromMap(map);

		assertEquals(USER_KEY, config.getUserKey());
		assertEquals(DEVICE_KEY, config.getDeviceKey());
	}

	@Test
	void optionalFieldsFallBackToDefaults() {
		Map<String, Object> map = fullMap();
		Map<String, Object> service = section(map, "service");
		service.remove("host");
		service.remove("port");
		section(map, "upstream").remove("scheme");
		map.remove("nameAccess");
		map.remove("announcePeer");

		Configuration config = Configuration.fromMap(map);

		assertNull(config.getServiceHost(), "host stays unset so the endpoint is resolved via the DHT");
		assertEquals(9090, config.getServicePort(), "default service port");
		assertEquals("http", config.getUpstreamScheme(), "default upstream scheme");
		assertFalse(config.isNameAccessEnabled());
		assertFalse(config.isAnnouncePeer());
	}

	@Test
	void missingSectionsAreRejected() {
		for (String name : List.of("service", "client", "upstream")) {
			Map<String, Object> missing = fullMap();
			missing.remove(name);
			IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
					() -> Configuration.fromMap(missing), "missing section: " + name);
			assertTrue(e.getMessage().contains(name), e.getMessage());

			Map<String, Object> empty = fullMap();
			empty.put(name, new LinkedHashMap<String, Object>());
			assertThrows(IllegalArgumentException.class,
					() -> Configuration.fromMap(empty), "empty section: " + name);
		}
	}

	@Test
	void missingRequiredScalarsAreRejected() {
		Map<String, Object> noPeerId = fullMap();
		section(noPeerId, "service").remove("peerId");
		assertThrows(IllegalArgumentException.class, () -> Configuration.fromMap(noPeerId));

		Map<String, Object> noUpstreamPort = fullMap();
		section(noUpstreamPort, "upstream").remove("port");
		assertThrows(IllegalArgumentException.class, () -> Configuration.fromMap(noUpstreamPort));
	}

	/**
	 * {@code devicePrivateKey} and the upstream {@code host} are required, so omitting either must
	 * fail the same way every other missing field does - with an {@link IllegalArgumentException}
	 * naming the key, as {@link Configuration#fromMap(Map)} documents. They were previously read
	 * with a {@code null} default and handed to setters that {@code requireNonNull}, which surfaced
	 * a bare {@link NullPointerException} instead.
	 */
	@Test
	void missingDeviceKeyAndUpstreamHostAreRejected() {
		Map<String, Object> noDeviceKey = fullMap();
		section(noDeviceKey, "client").remove("devicePrivateKey");
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
				() -> Configuration.fromMap(noDeviceKey));
		assertTrue(e.getMessage().contains("devicePrivateKey"), e.getMessage());

		Map<String, Object> noUpstreamHost = fullMap();
		section(noUpstreamHost, "upstream").remove("host");
		e = assertThrows(IllegalArgumentException.class, () -> Configuration.fromMap(noUpstreamHost));
		assertTrue(e.getMessage().contains("host"), e.getMessage());
	}

	/**
	 * An explicitly null YAML value ({@code userId:} with nothing after it) is distinct from an
	 * absent key: the key is present, so it is parsed and rejected instead of silently skipped.
	 */
	@Test
	void explicitlyNullValuesAreRejected() {
		Map<String, Object> nullUserId = fullMap();
		Map<String, Object> client = section(nullUserId, "client");
		client.put("userId", null);
		assertThrows(IllegalArgumentException.class, () -> Configuration.fromMap(nullUserId));

		Map<String, Object> nullUserKey = fullMap();
		section(nullUserKey, "client").put("userPrivateKey", null);
		assertThrows(IllegalArgumentException.class, () -> Configuration.fromMap(nullUserKey));
	}

	@Test
	void invalidValuesAreRejected() {
		Map<String, Object> badPeerId = fullMap();
		section(badPeerId, "service").put("peerId", "not-a-peer-id");
		assertThrows(IllegalArgumentException.class, () -> Configuration.fromMap(badPeerId));

		Map<String, Object> badServicePort = fullMap();
		section(badServicePort, "service").put("port", 70000);
		assertThrows(IllegalArgumentException.class, () -> Configuration.fromMap(badServicePort));

		Map<String, Object> zeroServicePort = fullMap();
		section(zeroServicePort, "service").put("port", 0);
		assertThrows(IllegalArgumentException.class, () -> Configuration.fromMap(zeroServicePort),
				"0 passes ConfigMap's [0,65535] check but the setter requires 1-65535");

		Map<String, Object> badUpstreamPort = fullMap();
		section(badUpstreamPort, "upstream").put("port", -1);
		assertThrows(IllegalArgumentException.class, () -> Configuration.fromMap(badUpstreamPort));

		Map<String, Object> badDeviceKey = fullMap();
		section(badDeviceKey, "client").put("devicePrivateKey", Base58.encode(new byte[16]));
		assertThrows(IllegalArgumentException.class, () -> Configuration.fromMap(badDeviceKey));

		Map<String, Object> notASection = fullMap();
		notASection.put("upstream", "127.0.0.1:8888");
		assertThrows(IllegalArgumentException.class, () -> Configuration.fromMap(notASection));
	}

	@Test
	void builderFromMapIsChainableAndOverridable() {
		Configuration.Builder builder = Configuration.builder();
		assertSame(builder, builder.fromMap(fullMap()), "fromMap must return the same builder");

		// Setters applied after fromMap win.
		Configuration config = builder
				.serviceHost("10.0.0.1")
				.servicePort(10090)
				.upstreamPort(9999)
				.announcePeer(false)
				.build();

		assertEquals("10.0.0.1", config.getServiceHost());
		assertEquals(10090, config.getServicePort());
		assertEquals(9999, config.getUpstreamPort());
		assertFalse(config.isAnnouncePeer());
		assertEquals(SERVICE_PEER_ID, config.getServicePeerId(), "untouched fields survive");
	}

	/**
	 * fromMap applies defaults for absent optional keys, so it overwrites prior builder state
	 * rather than merging into it.
	 */
	@Test
	void builderFromMapOverwritesPriorState() {
		Map<String, Object> map = fullMap();
		map.remove("nameAccess");
		section(map, "service").remove("host");

		Configuration config = Configuration.builder()
				.nameAccess(true)
				.serviceHost("10.0.0.1")
				.fromMap(map)
				.build();

		assertFalse(config.isNameAccessEnabled(), "absent nameAccess resets to the default");
		assertNull(config.getServiceHost(), "absent host resets to the default");
	}

	@Test
	void userIdOnlyConfigurationRoundTripsThroughToMap() {
		Configuration config = Configuration.fromMap(fullMap());

		Map<String, Object> map = config.toMap();
		Map<String, Object> client = section(map, "client");
		assertEquals(USER_ID.toString(), client.get("userId"));
		assertFalse(client.containsKey("userPrivateKey"), "no private key to write back");

		Configuration reloaded = Configuration.fromMap(map);
		assertEquals(config.getServicePeerId(), reloaded.getServicePeerId());
		assertEquals(config.getServiceHost(), reloaded.getServiceHost());
		assertEquals(config.getServicePort(), reloaded.getServicePort());
		assertEquals(config.getUserId(), reloaded.getUserId());
		assertNull(reloaded.getUserKey());
		assertEquals(config.getDeviceKey(), reloaded.getDeviceKey());
		assertEquals(config.getUpstreamHost(), reloaded.getUpstreamHost());
		assertEquals(config.getUpstreamPort(), reloaded.getUpstreamPort());
		assertEquals(config.getUpstreamScheme(), reloaded.getUpstreamScheme());
		assertEquals(config.isNameAccessEnabled(), reloaded.isNameAccessEnabled());
		assertEquals(config.isAnnouncePeer(), reloaded.isAnnouncePeer());
	}

	/**
	 * The bundled testConfig.yaml is the shape the launcher actually loads from disk; parsing it
	 * keeps the resource and the parser honest about each other.
	 */
	@Test
	void bundledTestConfigYamlParses() throws Exception {
		Map<String, Object> map;
		try (InputStream in = getClass().getClassLoader().getResourceAsStream("testConfig.yaml")) {
			assertNotNull(in, "testConfig.yaml must be on the test classpath");
			map = Json.yamlMapper().readValue(in, Json.mapType());
		}

		Configuration config = Configuration.fromMap(map);

		assertEquals(Id.of("7oswzEbvf5Frkr5B8PwiCABqkRJXYzTWUvZnb87r63JZ"), config.getServicePeerId());
		assertEquals("192.168.8.80", config.getServiceHost());
		assertEquals(9090, config.getServicePort());
		assertEquals(Id.of("C5ioCZVtMMjRB9d1Ge78kzEAHs5nZroFxXkuySKEMVPu"), config.getUserId());
		assertNull(config.getUserKey(), "the resource configures the user by id only");
		assertNotNull(config.getDeviceKey());
		assertEquals("127.0.0.1", config.getUpstreamHost());
		assertEquals(8888, config.getUpstreamPort());
		assertEquals("http", config.getUpstreamScheme());
		assertTrue(config.isNameAccessEnabled());
		assertFalse(config.isAnnouncePeer());
	}

	/**
	 * The parser must not depend on the map implementation or key order handed to it.
	 */
	@Test
	void parsingIsIndependentOfMapOrdering() {
		Map<String, Object> hashed = new HashMap<>(fullMap());
		hashed.put("service", new HashMap<>(section(hashed, "service")));
		hashed.put("client", new HashMap<>(section(hashed, "client")));
		hashed.put("upstream", new HashMap<>(section(hashed, "upstream")));

		Configuration config = Configuration.fromMap(hashed);

		assertEquals(SERVICE_PEER_ID, config.getServicePeerId());
		assertEquals(USER_ID, config.getUserId());
		assertEquals(DEVICE_KEY, config.getDeviceKey());
	}

	@Test
	void nameAccessWithUnsupportedScheme() {
		Configuration.Builder builder = Configuration.builder()
				.service(SERVICE_PEER_ID)
				.serviceHost("192.168.8.80")
				.servicePort(9090)
				.deviceKey(Signature.KeyPair.random())
				.userId(Id.random())
				.upstream("127.0.0.1", 8888, "mqtts")
				.nameAccess(true);

		Exception e = assertThrows(IllegalStateException.class, builder::build);
		assertTrue(e.getMessage().contains("Name access requires an http upstream"), e.getMessage());
		assertTrue(e.getMessage().contains("'mqtts'"), "the message should name the offending scheme: " + e.getMessage());
	}

	/**
	 * An https upstream is the realistic mistake: TLS for the named endpoint is terminated at the
	 * super node, so name access must reject it even though it is a perfectly good scheme otherwise.
	 */
	@Test
	void nameAccessRejectsHttpsButAcceptsHttpInAnySpelling() {
		Configuration.Builder https = Configuration.builder()
				.service(SERVICE_PEER_ID, "192.168.8.80", 9090)
				.userId(USER_ID)
				.deviceKey(Signature.KeyPair.random())
				.upstream("127.0.0.1", 8888, "https")
				.nameAccess(true);
		assertThrows(IllegalStateException.class, https::build);

		// The same https upstream is fine without name access: the port-mapped endpoint relays bytes.
		assertEquals("https", https.nameAccess(false).build().getUpstreamScheme());

		for (String spelling : List.of("http", "HTTP", "Http://", " http:// ")) {
			Configuration config = https.upstreamScheme(spelling).nameAccess(true).build();
			assertEquals("http", config.getUpstreamScheme(), "spelling: [" + spelling + "]");
			assertTrue(config.isNameAccessEnabled());
		}
	}

	@Test
	void upstreamSchemeIsNormalized() {
		for (String[] c : new String[][] {
				{"tcp", "tcp"}, {"TCP://", "tcp"}, {"  Https  ", "https"}, {"svn+ssh", "svn+ssh"}, {"x-custom.v1", "x-custom.v1"}}) {
			Configuration config = Configuration.builder()
					.service(SERVICE_PEER_ID, "192.168.8.80", 9090)
					.userId(USER_ID)
					.deviceKey(Signature.KeyPair.random())
					.upstream("127.0.0.1", 8888, c[0])
					.build();
			assertEquals(c[1], config.getUpstreamScheme(), "input: [" + c[0] + "]");
		}
	}

	@Test
	void invalidUpstreamSchemesAreRejected() {
		for (String bad : List.of("", "   ", "://", "http:", "http:/", "1http", "ht tp", "http/", "-http", "http://x")) {
			IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
					() -> Configuration.builder().upstreamScheme(bad), "input: [" + bad + "]");
			assertTrue(e.getMessage().contains("Invalid upstream scheme"), e.getMessage());
		}
	}

	/**
	 * {@code service} and {@code upstream} both have a {@code host} and a {@code port}, so a missing
	 * one must be reported with its section, or the message does not say which to fix.
	 */
	@Test
	void fieldErrorsNameTheirSection() {
		Map<String, Object> noUpstreamHost = fullMap();
		section(noUpstreamHost, "upstream").remove("host");
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
				() -> Configuration.fromMap(noUpstreamHost));
		assertTrue(e.getMessage().startsWith("upstream: "), e.getMessage());

		Map<String, Object> badServicePort = fullMap();
		section(badServicePort, "service").put("port", 70000);
		e = assertThrows(IllegalArgumentException.class, () -> Configuration.fromMap(badServicePort));
		assertTrue(e.getMessage().startsWith("service: "), e.getMessage());

		Map<String, Object> badScheme = fullMap();
		section(badScheme, "upstream").put("scheme", "ht tp");
		e = assertThrows(IllegalArgumentException.class, () -> Configuration.fromMap(badScheme));
		assertTrue(e.getMessage().startsWith("upstream: Invalid upstream scheme"), e.getMessage());
	}

	@Test
	void malformedKeyEncodingNamesTheKey() {
		Map<String, Object> badDeviceKey = fullMap();
		section(badDeviceKey, "client").put("devicePrivateKey", "not-base58-0OIl");
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
				() -> Configuration.fromMap(badDeviceKey));
		assertTrue(e.getMessage().startsWith("client: Invalid device private key"), e.getMessage());

		Map<String, Object> badUserKey = fullMap();
		section(badUserKey, "client").put("userPrivateKey", "0xZZ");
		e = assertThrows(IllegalArgumentException.class, () -> Configuration.fromMap(badUserKey));
		assertTrue(e.getMessage().startsWith("client: Invalid user private key"), e.getMessage());
	}

	@Test
	void missingUserIdentityExplainsBothOptions() {
		Map<String, Object> noIdentity = fullMap();
		section(noIdentity, "client").remove("userId");
		section(noIdentity, "client").remove("userPrivateKey");
		IllegalStateException e = assertThrows(IllegalStateException.class, () -> Configuration.fromMap(noIdentity));
		assertTrue(e.getMessage().contains("client.userId or client.userPrivateKey"), e.getMessage());
	}
}
