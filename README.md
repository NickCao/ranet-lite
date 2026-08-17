# ranet-lite

A slim client for a [ranet](https://github.com/NickCao/ranet) mesh: a
minimal IKEv2 initiator, userspace ESP, an embedded Babel routing daemon,
and a SOCKS5 front end, all in a single Go binary that needs **no root
privileges and no kernel IPsec/routing configuration** on the host.

It reads the exact same `registry.json` and Ed25519 key files as `ranet`
itself, so it can join an existing deployment without re-provisioning
anything, but it has its own local config format (see [Configuration](
#configuration)) suited to dialing out to one or a few existing mesh
nodes rather than participating in ranet's full N-to-N reconciliation.

## How it works

- **IKEv2** ([RFC 7815](https://datatracker.ietf.org/doc/html/rfc7815)
  minimal-initiator profile): authenticates with the peer using a raw
  Ed25519 key via [RFC 7427](https://datatracker.ietf.org/doc/html/rfc7427)
  Digital Signature / [RFC 8420](https://datatracker.ietf.org/doc/html/rfc8420)
  EdDSA, and only ever negotiates modern cryptography (X25519, AES-GCM /
  ChaCha20-Poly1305, SHA-256/384). It forces UDP encapsulation (NAT-T)
  even when not behind NAT, since ranet peers always run this way.
- **ESP** ([RFC 4303](https://datatracker.ietf.org/doc/html/rfc4303)):
  tunnel-mode AEAD encap/decap with anti-replay, implemented entirely in
  userspace — no kernel XFRM state.
- A **[gvisor](https://gvisor.dev/) netstack** terminates the decrypted
  IP traffic instead of a kernel TUN device.
- An embedded minimal **Babel** speaker ([RFC 8966](
  https://datatracker.ietf.org/doc/html/rfc8966), plus the RTT extension,
  [RFC 9616](https://datatracker.ietf.org/doc/html/rfc9616)) exchanges
  routes with peers — tested against [BIRD](https://bird.network.cz/) as
  the reference implementation on the other end.
- A **SOCKS5** proxy (via [go-gost](https://github.com/go-gost)) exposes
  the mesh to local applications.

### This client is a stub, never transit

ranet-lite only ever announces prefixes it originates itself; it never
redistributes a route learned from one peer to another. The gvisor stack
here has no IP forwarding enabled to back that up, so claiming transit
capability would just mean packets silently dropped for anyone who tried
to route through it.

It also handles source-specific (SADR, `draft-ietf-babel-source-specific`)
routes safely without implementing a full source-and-destination-keyed
route table: a source-specific route is installed as an ordinary route
only when its source prefix covers this node's own configured
`source_address` (i.e. it actually applies to traffic this node would
originate); otherwise it's ignored rather than mis-applied to everyone.

## Building

```sh
go build -o ranet-lite ./cmd/ranet-lite
```

## Running

```sh
./ranet-lite -config /etc/ranet-lite/config.yaml
```

## Configuration

ranet-lite reads two files:

- **`registry.json`** — the same registry ranet itself uses: a list of
  organizations, each with a shared Ed25519 public key and a list of
  nodes/endpoints. See [`internal/registry/testdata/registry.json`](
  internal/registry/testdata/registry.json) for a fully worked (synthetic)
  example.
- **A private key** — a PKCS8 PEM Ed25519 private key, same format as
  ranet's `key.rs` produces.
- **`config.yaml`** — ranet-lite's own config, see
  [`examples/config.yaml`](examples/config.yaml):

  ```yaml
  organization: example
  common_name: my-laptop
  serial_number: "0"

  private_key: /etc/ranet-lite/key.pem
  registry: /etc/ranet-lite/registry.json

  socks5_listen: "127.0.0.1:1080"

  # Source address for the local gvisor stack, used for outbound
  # connections proxied in through SOCKS5. Distinct from `originate`.
  source_address: "10.66.0.5"

  # Prefixes this node announces via babel as reachable through itself.
  originate:
    - "10.66.0.5/32"

  # Existing mesh nodes to dial as IKEv2/babel peers.
  peers:
    - organization: example   # optional, defaults to the top-level organization
      common_name: gateway
      serial_number: "0"      # optional, picks a specific endpoint

  babel:
    hello_interval: 20s
    update_interval: 80s
  ```

  Required fields: `organization`, `common_name`, `serial_number`,
  `private_key`, `registry`, and at least one entry in `peers`. Everything
  else has a default (`socks5_listen` defaults to `127.0.0.1:1080`,
  `peers[].organization` defaults to the top-level `organization`, babel
  intervals default to 20s/80s).

Your real `registry.json` and private key contain sensitive deployment
data — don't commit them. `.gitignore` already excludes `registry.json`
and `*.pem` at the repo root (aside from the synthetic test fixture under
`internal/registry/testdata/`).

## Repository layout

```
cmd/ranet-lite/     the production binary — wires everything below together
internal/ike/       minimal IKEv2 initiator
internal/esp/       userspace ESP (AEAD encap/decap, anti-replay)
internal/transport/ shared UDP socket muxing IKE and ESP traffic (NAT-T aware)
internal/netstack/  gvisor-backed mesh stack and route table
internal/babel/     embedded RFC 8966 Babel speaker with the RTT extension
internal/socks5/    SOCKS5 front end (go-gost) exposing the mesh
internal/registry/  ranet-compatible registry.json and key file loading
internal/config/    ranet-lite's own local config format
```

## Testing

```sh
go test ./... -race
```

Protocol-level correctness (IKE handshake, ESP crypto, Babel wire format
and RTT extension) has additionally been validated against a real
strongSwan responder and a real BIRD Babel peer; the throwaway test
binaries under `cmd/` (`iketest`, `esptest`, `babeltest`, `socks5test`,
`fulltest`) were used for that manual interop testing and aren't part of
the production build.

## License

MIT, see [LICENSE](LICENSE).
