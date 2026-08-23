# ranet-lite

A slim client for a [ranet](https://github.com/NickCao/ranet) mesh: a
minimal IKEv2 initiator, userspace ESP, a real Linux TUN device, and an
embedded Babel routing speaker, all in a single Go binary.

It reads the exact same `registry.json` and Ed25519 key files as `ranet`
itself, so it can join an existing deployment without re-provisioning
anything, but it has its own local config format (see [Configuration](
#configuration)) suited to dialing out to one or a few existing mesh
nodes rather than participating in ranet's full N-to-N reconciliation.

## How it works

- **IKEv2** ([RFC 7815](https://www.rfc-editor.org/rfc/rfc7815)-style
  minimal initiator) using modern cryptography only: X25519, AES-GCM /
  ChaCha20-Poly1305, SHA-256/384. Authenticates with a raw Ed25519 key via
  [RFC 7427](https://www.rfc-editor.org/rfc/rfc7427) Digital Signature
  auth ([RFC 8420](https://www.rfc-editor.org/rfc/rfc8420) EdDSA), and
  forces UDP encapsulation unconditionally on the one explicit registry
  port — interoperates with a real strongSwan responder as provisioned by
  ranet.
- **ESP** ([RFC 4303](https://www.rfc-editor.org/rfc/rfc4303)) tunnel-mode
  AEAD encap/decap with anti-replay, entirely in userspace — no kernel
  XFRM state.
- A real **TUN device**, so local applications talk to the mesh over
  ordinary IP sockets through the kernel's own TCP/IP stack — no SOCKS5
  proxy, no userspace network stack. Creating the device needs
  `CAP_NET_ADMIN`; assigning it an address and adding routes does not, and
  ranet-lite never does either itself (see [Configuration](#configuration)).
- An embedded minimal **Babel** speaker
  ([RFC 8966](https://www.rfc-editor.org/rfc/rfc8966)), including the RTT
  extension ([RFC 9616](https://www.rfc-editor.org/rfc/rfc9616)).
  Interoperates with [BIRD](https://bird.network.cz/) as the reference
  peer implementation.

## What it deliberately doesn't do

**ranet-lite is always a stub/leaf node, never transit.** It never
re-advertises routes learned from one peer to another — the embedded
Babel speaker only announces prefixes it originates itself. Nothing in
this binary enables IP forwarding, so claiming transit capability in the
routing protocol would just mean announced paths blackhole.

It implements genuine source-specific routing
([SADR](https://datatracker.ietf.org/doc/draft-ietf-babel-source-specific/)):
the mesh's route table is keyed by `(source, destination)` prefix pairs,
resolved per RFC 8966/SADR's rule (longest destination match first, source
prefix as a tiebreaker among equally-specific destinations) using each
packet's real source address as it arrives on the TUN device — not an
approximation based on a single configured "our address".

**ranet-lite never manages the TUN device's address or routes.** It
creates the device and brings it up, or attaches to the configured `tun`
device; everything else — assigning it an
address, adding a default route or more specific routes, or running a
separate routing daemon (e.g. BIRD) that peers with the embedded Babel
speaker over the device for fully automatic route installation — is up to
whoever runs it.

On Linux, ranet-lite opens one multiqueue TUN lane per Go execution context
and keeps inner flows on a stable lane. When more than one execution context
is available, an existing named TUN must therefore be created with
`IFF_MULTI_QUEUE` (for a systemd-networkd `.netdev`, set `MultiQueue=yes` in
its `[Tun]` section). Single-core processes can also attach to a legacy
single-queue TUN and retain the direct packet path.

## Deliberate protocol deviations

ranet-lite uses a private IKEv2 transport profile tailored to a ranet
deployment rather than general-purpose
[RFC 7296 NAT traversal](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.23).
The RFC uses UDP ports 500 and 4500, hashes the actual source and destination
address/port pairs in the `NAT_DETECTION_*_IP` notifications, and moves
subsequent traffic to port 4500 when NAT is detected. In contrast:

- Each ranet node listens on its registry-assigned UDP port. The local and
  remote ports are independent and need not have the same value; NAT may
  rewrite either one again.
- IKE and ESP always share that one UDP path. Every IKE packet, including
  `IKE_SA_INIT`, has the four-byte Non-ESP Marker, while an ESP packet starts
  directly with its nonzero SPI.
- The initiator deliberately hashes a random IPv4 address and port zero in
  `NAT_DETECTION_SOURCE_IP`, guaranteeing a mismatch so that strongSwan
  installs UDP encapsulation even when no NAT is present. The destination
  notification hashes the configured remote endpoint normally.
- Received NAT-detection notifications are not used to select a transport:
  there is no port-500-to-4500 transition and no dedicated
  [RFC 3948](https://www.rfc-editor.org/rfc/rfc3948.html) NAT keepalive. The
  userspace transport accepts UDP-encapsulated ESP only, not raw IP ESP.

The strongSwan peer must therefore be provisioned for the same custom port
and forced UDP encapsulation (`encap = true`). This profile remains usable
when a NAT changes the observed source port: replies follow the observed
source, and a fresh authenticated IKE request can update the stored peer
endpoint. It is deliberately not interoperable with an otherwise generic
peer expecting standard RFC 7296 port selection or raw ESP.

There is one separate SHOULD-level deviation from
[RFC 7296 section 2.25.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.25.1).
If both peers initiate a rekey of the same Child SA concurrently, ranet-lite
answers the peer's rekey with `TEMPORARY_FAILURE`. The RFC recommends
completing both exchanges, temporarily retaining the redundant SAs, and
using the four nonces to decide which new SA to delete. Returning the error
keeps ranet-lite's single-Child-SA state machine simple and causes the peer
to retry after the local rekey finishes.

The remaining narrow feature set is not counted as RFC non-compliance.
Initiator-only establishment, raw-public-key authentication without
certificates or EAP, omission of COOKIE handling, and refusal to create
additional Child SAs are all within the
[RFC 7815 minimal-initiator profile](https://www.rfc-editor.org/rfc/rfc7815.html).

## Building

```sh
go build -o ranet-lite ./cmd/ranet-lite
```

Requires Go 1.26+. Creating the TUN device needs `CAP_NET_ADMIN` (root,
or that capability granted to the binary).

## Running

```sh
sudo ./ranet-lite -config /etc/ranet-lite/config.yaml
```

On startup it logs the TUN device's name (e.g. `ranet0`). Traffic won't
flow until you configure it yourself, e.g.:

```sh
ip addr add 10.66.0.5/32 dev ranet0
ip route add ::/0 dev ranet0
```

## Configuration

ranet-lite needs two files:

- A **registry.json**, in the exact format ranet itself uses (see
  `internal/registry/testdata/registry.json` for a fully worked, synthetic
  example spanning multiple organizations, nodes, and endpoint address
  families).
- A **config.yaml** in ranet-lite's own format — see
  [`examples/config.yaml`](examples/config.yaml):

```yaml
organization: example
common_name: my-laptop
port: 13000
endpoints:
  - serial_number: "0"
    address_family: ip4

private_key: /etc/ranet-lite/key.pem      # PKCS8 PEM Ed25519 private key
registry: /etc/ranet-lite/registry.json   # same registry.json ranet itself uses

# Prefixes this node announces via babel as reachable through itself.
originate:
  - "10.66.0.5/32"

# Optional anti-replay window. Omit for strongSwan's default of 32 packets;
# set to 0 to disable replay checking.
# replay_window: 32

# Proactive rekey intervals default to 1h for Child SAs and 3h for IKE SAs.
# Set either to 0 to disable it. Rekeys run interval minus the 5m margin and
# an independently random 0-1m jitter. Margin plus jitter must be shorter
# than every enabled interval.
# child_rekey_interval: 1h
# ike_rekey_interval: 3h
# rekey_margin: 5m
# rekey_jitter: 1m
# Failed rekeys retry after 5s, doubling up to 5m.
# rekey_retry_initial: 5s
# rekey_retry_max: 5m

# The existing strongSwan netns test rig can exercise short rekey lifetimes:
# go run ./cmd/iketest -child-rekey=5s -ike-rekey=15s -run=45

# Optional fixed TUN name. It attaches to an existing compatible device
# (which must be multiqueue on multicore) or creates it when absent. Omit to
# create an automatically named ranet%d device.
# tun: ranet0

# One or more existing mesh nodes to dial as IKEv2/babel peers.
peers:
  - organization: example       # optional, defaults to the top-level organization
    common_name: gateway
    serial_number: "0"          # optional, picks a specific endpoint if the node has several

babel:
  hello_interval: 20s
  update_interval: 80s
```

Required fields: `organization`, `common_name`, `port`, at least one local
`endpoints` entry, `private_key`, `registry`, and at least one entry in `peers`. Everything
else has a default (`peers[].organization` defaults to the top-level
`organization`, and the babel intervals default to 20s/80s).

**Your `registry.json` and private key are sensitive** — they identify
and authenticate a real node in a real mesh. Never commit real copies of
either; only synthetic fixtures belong in version control (see
`.gitignore`).

## Repository layout

- `internal/ike` — the IKEv2 initiator.
- `internal/esp` — userspace ESP AEAD encap/decap and anti-replay.
- `internal/transport` — the shared UDP socket mux (IKE vs. ESP framing).
- `internal/netstack` — the TUN device and the `(source, destination)`
  route table.
- `internal/babel` — the embedded Babel speaker.
- `internal/registry` — ranet-compatible `registry.json` and Ed25519 key
  loading.
- `internal/config` — ranet-lite's own config format.
- `cmd/ranet-lite` — the production binary.
- `cmd/*test` — standalone interop/smoke-test binaries used during
  development (IKE, ESP, babel tests).

## Testing

```sh
go test ./... -race
```

None of the unit tests require root or any privileged resource. Protocol-level
interoperability is covered by the NixOS VM test exposed by `flake.nix`. It
boots separate client and gateway VMs; the client runs the packaged,
user-facing `ranet-lite` binary with a real TUN device, while the gateway runs
`charon-systemd`/`swanctl`, BIRD, and iperf3. The test verifies an
Ed25519-authenticated IKEv2 and Child SA negotiation across asymmetric local
and remote UDP ports, checks Babel route exchange in both directions, and
measures TCP bandwidth through the negotiated ESP tunnel:

```sh
nix build .#checks.x86_64-linux.integration -L
```

The VM console, systemd, strongSwan, BIRD, ranet-lite, and iperf3 output is
streamed by the Nix test driver. A failed convergence check also prints both
machines' journals, routes, XFRM state and policies, and BIRD protocol state.

## License

MIT — see [LICENSE](LICENSE).
