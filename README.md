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
  `CAP_NET_ADMIN`. Address and route configuration also require administrative
  privileges and are managed separately (see [Configuration](#configuration)).
- An embedded minimal **Babel** speaker
  ([RFC 8966](https://www.rfc-editor.org/rfc/rfc8966)), including the RTT
  extension ([RFC 9616](https://www.rfc-editor.org/rfc/rfc9616)) and IPv4
  announcements with an IPv6 next hop
  ([RFC 9229](https://www.rfc-editor.org/rfc/rfc9229)).
  Interoperates with [BIRD](https://bird.network.cz/) as the reference
  peer implementation.

## What it deliberately doesn't do

**ranet-lite is always a stub/leaf node, never transit.** It never
re-advertises routes learned from one peer to another — the embedded
Babel speaker only announces prefixes it originates itself. Nothing in
this binary enables IP forwarding, so claiming transit capability in the
routing protocol would just mean announced paths blackhole.

It implements genuine source-specific routing
([SADR, RFC 9079](https://www.rfc-editor.org/rfc/rfc9079)):
the mesh's route table is keyed by `(source, destination)` prefix pairs,
resolved per RFC 8966/SADR's rule (longest destination match first, source
prefix as a tiebreaker among equally-specific destinations) using each
packet's real source address as it arrives on the TUN device — not an
approximation based on a single configured "our address".

**ranet-lite never manages the TUN device's address or routes.** It
creates the device and brings it up, or attaches to the configured `tun`
device. Assign its addresses and kernel routes externally. Babel only exchanges
control packets inside authenticated ESP tunnels; a local routing daemon cannot
peer with the embedded speaker over the TUN. Learned routes select the outgoing
ESP peer after the kernel has routed a packet to the TUN.

IPv4 announcements use the control link's IPv6 link-local next hop (AE 4).
The BIRD peer needs Babel's `extended next hop` support, enabled by default
in BIRD 3. Both ordinary IPv4 updates and AE 4 updates are accepted on receive.

On Linux, ranet-lite opens one multiqueue TUN lane per Go execution context
and keeps inner flows on a stable lane. When more than one execution context
is available, an existing named TUN must therefore be created with
`IFF_MULTI_QUEUE` (for a systemd-networkd `.netdev`, set `MultiQueue=yes` in
its `[Tun]` section). Single-core processes can also attach to a legacy
single-queue TUN. TUN readers hand bounded batches to shared encryption workers;
sequence reservation and queue submission preserve packet order across workers.

The TUN backend uses a pinned revision of the
[Tailscale wireguard-go fork](https://github.com/tailscale/wireguard-go/tree/tailscale).
Its native multiqueue API owns the descriptors and offload state. TUN readers
retain packet views inside reusable 128 KiB slabs until encryption finishes,
and Linux GRO writes gather packet fragments with `writev`. The inbound packet
pool retains its original 64 KiB capacity. Repeated NixOS VM comparisons with
matching inbound buffers showed near parity.

The Babel control state and forwarding publication share one mutex. A stub
selects the cheapest live candidate without a feasibility/source table, as
permitted by [RFC 8966 Appendix E](https://www.rfc-editor.org/rfc/rfc8966.html#appendix-E).
Local prefixes take precedence even after a router-ID change. Remote Hello,
IHU, and Update expiration is scheduled independently of local send intervals.

Packet lookups read an immutable SADR trie snapshot without locking. Route
changes copy the affected path and publish it atomically; diagnostics iterate
the same snapshot. ESP batches similarly capture an immutable set of installed
SAs, retaining keys for work already in flight during a rekey. One-core receive
processing runs inline; multicore receive workers authenticate concurrently and
commit replay state in intake order before delivering TUN batches.
Linux UDP receive reads a full 128-message vector and returns excess GRO
segments before reusing its buffers. Replay checks and nonce storage are
amortized across ESP batches, and already-completed send/receive batches are
combined without waiting for additional traffic.
Encryption workers reuse packed ciphertext buffers only after the ordered
sender finishes its UDP call, retaining separate storage for work in flight.
Replaced inbound SAs remain usable for five seconds after their Delete
acknowledgement so queued and reordered packets can drain during a rekey.

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

IKE rekeys retain the negotiated PRF. This avoids differing key expansion
behavior between [strongSwan](https://github.com/strongswan/strongswan/blob/master/src/libcharon/sa/ikev2/keymat_v2.c)
and [RFC 7296 section 2.18](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.18)
when the PRF changes, while allowing
fresh DH keys and a different encryption algorithm. Peer Child-SA rekeys can
use X25519, P-256, or P-384 for PFS; locally initiated Child rekeys derive keys
from the IKE SA without an additional DH exchange.

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
ip route add 10.66.0.0/16 dev ranet0
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

# Optional anti-replay window. Omit for the high-speed default of 4096
# packets; RFC 4303 section 3.4.3 recommends increasing it for high-speed
# environments. Set it to 0 only to explicitly disable replay checking.
# replay_window: 4096

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
- `internal/client` — runtime ownership, peer reconnection, and the ESP pipeline.
- `esp` — userspace ESP AEAD encap/decap and anti-replay.
- `internal/transport` — the shared UDP socket mux (IKE vs. ESP framing).
- `internal/netstack` — the TUN device and the `(source, destination)`
  route table.
- `internal/babel` — the embedded Babel speaker.
- `internal/packet` — shared validation of TUN and decrypted IP packets.
- `sadr` — immutable source/destination routing trie and snapshot iteration.
- `internal/registry` — ranet-compatible `registry.json` and Ed25519 key
  loading.
- `internal/config` — ranet-lite's own config format.
- `cmd/ranet-lite` — the production binary.
- `cmd/*test` — standalone interop/smoke-test binaries used during
  development (IKE, ESP, babel tests).

## Testing

```sh
nix build .#checks.x86_64-linux.unit --no-link -L
```

The full race-test suite runs inside a sandboxed Nix builder. Protocol-level
interoperability is covered by the NixOS VM test exposed by `flake.nix`. It
boots separate client and gateway VMs; the client runs the packaged,
user-facing `ranet-lite` binary with a real TUN device, while the gateway runs
`charon-systemd`/`swanctl`, BIRD, and iperf3. The test verifies an
Ed25519-authenticated IKEv2 and Child SA negotiation across asymmetric local
and remote UDP ports, checks Babel route exchange in both directions, and
measures TCP bandwidth through the negotiated ESP tunnel:

```sh
nix build .#checks.x86_64-linux.integration -L
nix build .#checks.x86_64-linux.integration-multicore -L
```

These checks exercise one-core and four-core clients, IPv4 and IPv6 routes,
locally scheduled and peer-initiated rekeys, BIRD withdrawal/recovery, and a clean
stop/restart with an idle TUN read. The integration test also accepts
`profile = true` when imported from Nix to capture Go and kernel CPU profiles
during longer throughput runs, including simultaneous traffic in both directions:

```sh
nix build .#integration-profile --no-link -L
```

The kernel profiler runs as root inside the disposable VM. It does not require
host root or changes to the host's profiling permissions. Profiles are copied
into the test result.

`nix build .#namespace-profile --no-link -L` runs the namespace harness
inside one six-core VM and captures a system-wide kernel profile. Its private
veth topology avoids the virtual switch between integration-test VMs; the
guest's CPU and clock still affect results. Run project binaries, tests,
benchmarks, and profilers inside Nix builders or NixOS test VMs.

For comparisons between versions, [nixos-throughput.nix](integration/nixos-throughput.nix)
accepts two Nix-built client packages and runs them sequentially in one VM,
alternating their order across trials. It disables profilers and reports
received TCP throughput, including simultaneous traffic in both directions,
alongside a plain veth control. Each run and the summary remain in the Nix
test result.

Inside the VM, the harness creates private client/gateway network namespaces,
a private `/run`, strongSwan, BIRD, and a real TUN/XFRM tunnel using the synthetic
test keys. It
records binary identity, CPU affinity, iperf3 JSON, CPU profiles, socket drops,
TCP state, TUN queue statistics, and key-free XFRM counters in a new output
directory. Each `*-cpu.json` records user/system CPU seconds and average cores
used by the client and gateway processes, plus VM CPU counters including
softirq time. These counters include other activity in the VM; process
accounting and sampled profiles provide separate views of CPU use. All processes
and interfaces are removed when the namespaces exit.

`--cores` sets GOMAXPROCS; `--affinity` restricts the client to actual CPUs.
Use `--cores 1 --affinity 0` for a pinned single-core comparison. Keep flow
ports, stream counts, affinity, MTU, and replay windows identical between
versions. The default gateway replay window is strongSwan's 32 packets;
`--replay-window 4096` can distinguish replay drops from processing limits.
`--protocol udp --rate 10` offers an aggregate 10 Gbit/s per direction with
UDP GSO/GRO and 4 MiB iperf socket buffers; inspect received throughput and loss,
not just the offered rate. The NixOS performance VM uses the
`iperf3-benchmark` package, which changes
[iperf 3.21's GRO receive call](https://github.com/esnet/iperf/blob/3.21/src/net.c#L521-L595) to block
instead of busy-polling. With the upstream receive loop, eight bidirectional
streams can occupy every CPU even when waiting for packets, starving the
tunnel on a shared host. The harness records the exact iperf executable and
version along with the client binary identity. TCP behavior is unchanged.

Raw ESP encryption and decryption have separate benchmarks in
[benchmark_test.go](esp/benchmark_test.go). These include ESP framing, AEAD,
sequence reservation or replay commits, and reusable batch buffers. Decryption
also includes copying the input
ciphertext into reusable buffers. They exclude UDP, TUN, and the client queues;
cipher throughput cannot establish full-duplex tunnel throughput. Namespace
measurements share CPU resources with the Linux gateway and traffic generators
and do not establish performance on a physical NIC.

Routing and packet classification also have microbenchmarks. Lookup
throughput, route-update cost, and full-tunnel TCP bandwidth measure different
work; VM throughput also includes
the gateway's kernel IPsec and virtual networking overhead.

Immutable snapshots favor packet lookups over route-write latency. Each changed
route allocates the copied trie path; this costs more than an in-place update,
but readers never contend with other readers or wait for a route writer.

The VM console, systemd, strongSwan, BIRD, ranet-lite, and iperf3 output is
streamed by the Nix test driver. The test also prints strongSwan SA state and
BIRD neighbors and routes on exit, including after a failed check.

## License

MIT — see [LICENSE](LICENSE).
