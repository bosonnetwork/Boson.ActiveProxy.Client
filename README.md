# Boson Active Proxy Client

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://adoptium.net/)
[![Maven](https://img.shields.io/badge/Maven-3.8%2B-red.svg)](https://maven.apache.org/)

The Java client library for the **Boson Active Proxy** — a Boson layer-2 service that lets any device expose a local service to the public internet, even when it is behind NAT, a firewall, or has no public IP address.

---

## Table of Contents

- [What Is Active Proxy?](#what-is-active-proxy)
- [How It Works](#how-it-works)
- [Key Classes](#key-classes)
- [Prerequisites](#prerequisites)
- [Build](#build)
- [Adding as a Dependency](#adding-as-a-dependency)
- [Configuration](#configuration)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

---

## What Is Active Proxy?

Active Proxy is a layer-2 service built on the Boson DHT network. It solves the classic NAT traversal problem: a service running on a laptop, a Raspberry Pi, or any machine behind a home router can be reached from anywhere on the internet without port forwarding, a VPN, or a static IP.

A **Boson Super Node** running the Active Proxy service acts as the public relay:

- It holds a **public IP address** and allocates a TCP port (or a DNS name, for subscribed clients) that the outside world can connect to.
- The client library maintains an **encrypted, authenticated tunnel** from your machine outward to that super node.
- Incoming external connections are multiplexed through this tunnel and forwarded to your local upstream service transparently.

---

## How It Works

```
  External User
       │  TCP connect to public endpoint
       ▼
 ┌─────────────────────────────────┐
 │  Active Proxy Super Node        │  ← public IP, optional DNS name
 │  (Boson layer-2 service)        │
 └─────────────────────────────────┘
       │  Encrypted tunnel (NaCl / CryptoBox)
       │  Challenge → Auth → Attach → Data
       ▼
 ┌──────────────────────────────────┐
 │  ActiveProxyClient (this lib)    │  ← your machine, any network
 └──────────────────────────────────┘
       │  plain TCP (loopback or LAN)
       ▼
 ┌─────────────────┐
 │  Your service   │  e.g. HTTP, SSH, any TCP service
 └─────────────────┘
```

1. **Startup** — The client resolves the Active Proxy service peer via a DHT `FIND_PEER` lookup using the configured `peerId`, then opens a TCP connection to the super node.
2. **Handshake** — A mutual challenge–response exchange authenticates the client using its Ed25519 user and device keys. The channel is then encrypted with NaCl `CryptoBox` (X25519 + XSalsa20-Poly1305).
3. **Attach** — The client registers its upstream service address with the super node, which allocates a public endpoint (`ip:port`, and optionally a DNS hostname for subscribed users).
4. **Data relay** — For each incoming external TCP connection, the super node sends a `CONNECT` packet through the tunnel. The client opens a new connection to the local upstream service and bridges the two streams until either side disconnects.
5. **Keepalive** — `PING`/`PING_ACK` packets keep the tunnel alive and detect network failures.

---

## Prerequisites

| Requirement | Version                    |
|---|----------------------------|
| Java JDK | 17 or later                |
| Apache Maven | 3.8 or later               |
| Boson Core (`boson-api`) | same version or compatible |

---

## Build

```bash
git clone https://github.com/bosonnetwork/Boson.ActiveProxy.Client.git
cd Boson.ActiveProxy.Client
./mvnw clean package
```

The compiled JAR is placed in `target/lib/boson-active-proxy-client-<version>.jar`.

To skip tests:

```bash
./mvnw clean package -DskipTests
```

---

## Adding as a Dependency

Add the following to your Maven `pom.xml`:

```xml
<dependency>
    <groupId>io.bosonnetwork</groupId>
    <artifactId>boson-active-proxy-client</artifactId>
    <version>${boson.version}</version>
</dependency>
```

The library requires a Vert.x instance and a running Boson `Node` (from `boson-core-dht`) to be provided by the caller.

---

## Configuration

The client is configured via a YAML file or programmatically through the `Configuration.Builder`.

### YAML configuration file

```yaml
# Active Proxy service peer.
# peerId is required. The client resolves host/port via DHT if omitted.
service:
  peerId: GbRwG3WgKgApSDBr9FGo5Y3RssSWxfWhanXMBdPCo5F2
  # host: 192.168.8.80   # optional: skip DHT lookup and connect directly
  # port: 9090

# Client identity.
# Provide either userPrivateKey (which implies userId) or just userId.
# devicePrivateKey is always required.
client:
  userId: AAqCZmUwD5hPAwNZBUsf1xsqsuWMUK74za3r6b9dgioD
  # userPrivateKey: <Base58 or 0x-prefixed hex Ed25519 private key>
  devicePrivateKey: <Base58 or 0x-prefixed hex Ed25519 private key>

# The local service to expose.
upstream:
  host: 127.0.0.1
  port: 8888
  scheme: http://    # informational; defaults to tcp://

# Request a DNS hostname from the super node (requires subscription).
nameAccess: false

# Announce the proxied endpoint to the DHT for peer discovery.
announcePeer: false
```

### Configuration fields

| Section | Field | Required | Description |
|---|---|---|---|
| `service` | `peerId` | Yes | DHT peer ID of the Active Proxy super node. |
| `service` | `host` | No | Direct hostname/IP of the super node. Skips DHT lookup when set. |
| `service` | `port` | No | Direct TCP port of the super node. Required together with `host`. |
| `client` | `userId` | Conditional | Boson user ID (public key as Base58). Required if `userPrivateKey` is absent. |
| `client` | `userPrivateKey` | Conditional | Ed25519 private key (Base58 or `0x`-hex). Derives `userId` automatically. |
| `client` | `devicePrivateKey` | Yes | Device-specific Ed25519 private key. Identifies this device to the service. |
| `upstream` | `host` | Yes | Host of the local service to expose. |
| `upstream` | `port` | Yes | Port of the local service to expose. |
| `upstream` | `scheme` | No | Protocol hint (e.g. `http://`, `tcp://`). Defaults to `tcp://`. |
| — | `nameAccess` | No | Request a DNS name for the public endpoint. Defaults to `false`. |
| — | `announcePeer` | No | Announce the proxied endpoint to the DHT. Defaults to `false`. |

### Programmatic configuration

```java
Configuration config = Configuration.builder()
    .servicePeerId(Id.of("GbRwG3WgKgApSDBr9FGo5Y3RssSWxfWhanXMBdPCo5F2"))
    .userKey("<Base58-private-key>")        // derives userId automatically
    .deviceKey("<Base58-private-key>")
    .upstreamHost("127.0.0.1")
    .upstreamPort(8888)
    .upstreamScheme("http://")
    .nameAccess(false)
    .announcePeer(false)
    .build();
```

---

## Usage

```java
// Obtain a running Boson node and a Vert.x instance (application-provided).
Node node = ...;
Vertx vertx = ...;

// Load configuration from a YAML map or build programmatically.
Configuration config = Configuration.fromMap(yamlMap);

// Create and start the client.
ActiveProxyClient client = new ActiveProxyClient(vertx, node, config);
client.addConnectionListener(new ConnectionStatusListener() {
    @Override
    public void connected() {
        System.out.println("Tunnel connected. Public endpoint: " + client.getEndpoint());
        if (client.isNameAccessEnabled())
            System.out.println("DNS endpoint: " + client.getNamedEndpoint());
    }

    @Override
    public void disconnected() {
        System.out.println("Disconnected from Active Proxy service.");
    }
});

client.start().toCompletionStage().toCompletableFuture().get();

// The local service is now publicly reachable via client.getEndpoint().
System.out.println("Public endpoint: " + client.getEndpoint());

// Stop when done.
client.stop().toCompletionStage().toCompletableFuture().get();
```

---

## Contributing

We welcome contributions from the open-source community. To get started:

1. Fork this repository and create a feature branch.
2. Make your changes and add tests where applicable.
3. Ensure `./mvnw clean verify` passes.
4. Open a pull request with a clear description of the change.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

---

## License

This project is licensed under the [MIT License](LICENSE).