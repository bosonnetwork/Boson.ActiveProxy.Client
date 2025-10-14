package io.bosonnetwork.activeproxy;

import java.io.InputStream;
import java.util.Map;

import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;

import io.bosonnetwork.utils.Json;

public class TestClientLauncher {
	private static Vertx vertx;
	private static ActiveProxyClient client;

	private static Configuration loadConfig() throws Exception{
		try (InputStream s = TestClientLauncher.class.getClassLoader().getResourceAsStream("testConfig.yaml")) {
			Map<String, Object> map = Json.yamlMapper().readValue(s, Json.mapType());
			return Configuration.fromMap(map);
		} catch (Exception e) {
			System.err.println("Failed to load configuration file: " + e.getMessage());
			throw e;
		}
	}

	public static void main(String[] args) {
		Runtime.getRuntime().addShutdownHook(new Thread(() -> {
			if (client != null) {
				System.out.println("Shutting down the active proxy client...");
				client.stop().thenRun(() -> {
					System.out.println("Active proxy client stopped.");
				}).join();

				// Cannot chain vertx.close() to the above future because closing Vert.x will terminate its event loop,
				// preventing any pending future handlers from executing.
				System.out.print("Shutting down Vert.x gracefully...");
				vertx.close().toCompletionStage().toCompletableFuture().join();
				System.out.println("Done!");
			}
		}));

		vertx = Vertx.vertx(new VertxOptions()
				.setWorkerPoolSize(4)
				.setEventLoopPoolSize(4)
				.setPreferNativeTransport(true));

		try {
			// no node for the client. so the configuration should:
			// - provide the service peer address (to avoid the dht lookup)
			// - disable announce peer
			Configuration config = loadConfig();
			client = new ActiveProxyClient(vertx, null, config);
			client.addConnectionListener(new ConnectionStatusListener() {
				@Override
				public void connected() {
					System.out.println("Connected to the active proxy service: " + config.getServicePeerId());
					System.out.println("Endpoint: " + client.getEndpoint());
					System.out.println("Named endpoint: " +
							(client.isNameAccessEnabled() ? client.getNamedEndpoint() : "N/A"));
				}

				@Override
				public void disconnected() {
					System.out.println("Disconnected from the active proxy service: " + config.getServicePeerId());
				}
			});

			System.out.println("Starting the active proxy client...");
			client.start().thenRun(() ->
				System.out.println("Started the active proxy client")
			).join();
		} catch (Exception e) {
			e.printStackTrace(System.err);
			vertx.close();
		}
	}
}