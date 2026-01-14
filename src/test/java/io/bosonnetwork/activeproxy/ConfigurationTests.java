package io.bosonnetwork.activeproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
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
	private static final Path testDir = Path.of(System.getProperty("java.io.tmpdir"), "boson", "ActiveProxyClient");

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
				.servicePeerId(Id.random())
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
				.servicePeerId(Id.random())
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
						.servicePeerId(Id.random())
						.deviceKey(Signature.KeyPair.random())
						.upstreamHost("192.168.1.8")
						.upstreamPort(8888)
						.build()
		);

		assertThrows(IllegalStateException.class, () ->
				Configuration.builder()
						.servicePeerId(Id.random())
						.userKey(Signature.KeyPair.random())
						.deviceKey(Signature.KeyPair.random())
						.upstreamPort(8888)
						.upstreamScheme("http")
						.build()
		);
	}

	@Test
	void saveAndLoad() throws Exception {
		Signature.KeyPair userKey = Signature.KeyPair.random();
		Signature.KeyPair deviceKey = Signature.KeyPair.random();

		Configuration config = Configuration.builder()
				.service(Id.random(), "192.168.8.80", 8090)
				.userKey(userKey)
				.deviceKey(deviceKey)
				.upstream("127.0.0.1", 8888, "http://")
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
}