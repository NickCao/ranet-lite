// Command ranet-lite is a slim client for a ranet mesh: a minimal IKEv2
// initiator, userspace ESP, a real TUN device, and an embedded Babel
// speaker, all in a single binary. It reads the same registry.json and
// Ed25519 key files as ranet itself, but has its own local configuration
// format (see internal/config) suited to dialing out to one or a few
// existing mesh nodes rather than participating in ranet's full N-to-N
// reconciliation.
//
// This binary never touches the TUN device's address or route
// configuration — creating the device (which needs CAP_NET_ADMIN) and
// bringing it up is all it does. Assigning it an address, adding routes
// (e.g. a default route), and running any local routing daemon that wants
// to peer with the embedded babel speaker are entirely up to whoever runs
// it.
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof" // registered on DefaultServeMux only if -pprof is set, see below
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/NickCao/ranet-lite/internal/babel"
	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/esp"
	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/internal/registry"
)

const reconnectDelay = 10 * time.Second

// inboundWorkers bounds how many goroutines decrypt a single peer's
// inbound ESP traffic concurrently — see connectPeer's doc comment for
// why this needs to be parallel at all. orderBufferSize bounds how many
// packets can be mid-decrypt (reserved a delivery slot but not yet
// resolved) at once; it doesn't need to match any particular buffer
// elsewhere, just be comfortably larger than inboundWorkers so a slow
// packet doesn't immediately stall new reads.
var inboundWorkers = min(runtime.NumCPU(), 16)

const orderBufferSize = 4096

func main() {
	configPath := flag.String("config", "/etc/ranet-lite/config.yaml", "path to the ranet-lite config file")
	pprofAddr := flag.String("pprof", "", "if set, serve net/http/pprof on this address (e.g. 127.0.0.1:6060) for profiling — CPU: /debug/pprof/profile, flamegraph: go tool pprof -http=:8081 'http://<addr>/debug/pprof/profile?seconds=30'")
	flag.Parse()

	if *pprofAddr != "" {
		// Mutex/block contention profiling is directly relevant to a
		// concurrent packet-processing pipeline like this one and cheap
		// enough to leave on whenever profiling is requested at all.
		runtime.SetMutexProfileFraction(1)
		runtime.SetBlockProfileRate(1)
		go func() {
			log.Printf("pprof listening on http://%s/debug/pprof/", *pprofAddr)
			if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
				log.Printf("pprof: %v", err)
			}
		}()
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	priv, err := registry.LoadPrivateKey(cfg.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	reg, err := registry.Load(cfg.Registry)
	if err != nil {
		log.Fatal(err)
	}

	mesh, err := netstack.New(0)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("tun device %s created; assign it an address and add routes yourself before traffic will flow", mesh.Name)

	speaker, err := babel.New(babel.Config{
		HelloInterval:  cfg.Babel.HelloInterval,
		UpdateInterval: cfg.Babel.UpdateInterval,
	}, mesh)
	if err != nil {
		log.Fatal(err)
	}
	for _, p := range cfg.Originate {
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			log.Fatalf("config: originate %q: %v", p, err)
		}
		speaker.Originate(prefix)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// SIGUSR1 dumps the current mesh route table to the log — the fastest
	// way to see what babel has actually installed without wiring up a
	// separate debug endpoint. Route installs/retractions and neighbor
	// up/down transitions are also logged as they happen (see
	// internal/babel/speaker.go's installRoute/neighborDown/TLVHello).
	dumpRoutes := make(chan os.Signal, 1)
	signal.Notify(dumpRoutes, syscall.SIGUSR1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-dumpRoutes:
				routes := mesh.Routes.Debug()
				if len(routes) == 0 {
					log.Printf("routes: (none installed)")
					continue
				}
				log.Printf("routes:")
				for _, r := range routes {
					log.Printf("  %s", r)
				}
			}
		}
	}()

	for _, p := range cfg.Peers {
		go runPeer(ctx, priv, cfg, p, reg, mesh, speaker)
	}
	if err := speaker.Run(ctx); err != nil && ctx.Err() == nil {
		log.Printf("babel: %v", err)
	}
}

// runPeer maintains one peer connection for the client's lifetime,
// reconnecting on any failure (network blip, peer restart, etc.) rather
// than requiring a manual restart.
func runPeer(ctx context.Context, priv ed25519.PrivateKey, cfg *config.Config, p config.Peer, reg registry.Registry, mesh *netstack.Mesh, speaker *babel.Speaker) {
	name := fmt.Sprintf("%s/%s", p.Organization, p.CommonName)
	for {
		if ctx.Err() != nil {
			return
		}
		if err := connectPeer(ctx, priv, cfg, p, reg, mesh, speaker, name); err != nil {
			log.Printf("peer %s: %v; reconnecting in %s", name, err, reconnectDelay)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(reconnectDelay):
		}
	}
}

// resolveEndpoint picks which of a node's endpoints to dial: the
// config-specified serial if given, otherwise the first one whose address
// actually resolves (a node commonly has endpoints for address families or
// links that aren't currently usable, e.g. address: null).
func resolveEndpoint(node registry.Node, serial string) (registry.Endpoint, error) {
	if serial != "" {
		ep, ok := node.FindEndpoint(serial)
		if !ok {
			return registry.Endpoint{}, fmt.Errorf("no endpoint with serial %q", serial)
		}
		return ep, nil
	}
	for _, ep := range node.Endpoints {
		if _, err := ep.ResolveRemote(); err == nil {
			return ep, nil
		}
	}
	return registry.Endpoint{}, fmt.Errorf("no endpoint currently resolves to an address")
}

// connectPeer runs one IKE session against a peer end to end: handshake,
// ESP setup, mesh/babel registration, and servicing the connection until
// it dies (network failure, peer restart, DPD timeout). Returning means
// the connection is gone; runPeer decides whether/when to retry.
func connectPeer(ctx context.Context, priv ed25519.PrivateKey, cfg *config.Config, p config.Peer, reg registry.Registry, mesh *netstack.Mesh, speaker *babel.Speaker, name string) error {
	org, ok := reg.FindOrganization(p.Organization)
	if !ok {
		return fmt.Errorf("organization %q not found in registry", p.Organization)
	}
	node, ok := org.FindNode(p.CommonName)
	if !ok {
		return fmt.Errorf("node %q not found in organization %q", p.CommonName, p.Organization)
	}
	ep, err := resolveEndpoint(node, p.SerialNumber)
	if err != nil {
		return err
	}
	remoteIP, err := ep.ResolveRemote()
	if err != nil {
		return err
	}
	remotePub, err := org.ParsePublicKey()
	if err != nil {
		return err
	}
	log.Printf("peer %s: dialing %s:%d (serial %s)", name, remoteIP, ep.Port, ep.SerialNumber)

	ikeCfg := ike.PeerConfig{
		Organization:     cfg.Organization,
		LocalCommonName:  cfg.CommonName,
		LocalSerial:      cfg.SerialNumber,
		LocalPrivateKey:  priv,
		RemoteCommonName: node.CommonName,
		RemoteSerial:     ep.SerialNumber,
		RemotePublicKey:  remotePub,
		RemoteAddr:       remoteIP,
		RemotePort:       int(ep.Port),
	}
	sess, err := ike.Initiate(ikeCfg)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	defer sess.Mux().Close()
	log.Printf("peer %s: connected (SPI %08x/%08x)", name, sess.Child.LocalSPI, sess.Child.RemoteSPI)

	out, err := esp.NewOutbound(sess.Child)
	if err != nil {
		return err
	}
	in, err := esp.NewInbound(sess.Child)
	if err != nil {
		return err
	}

	peer := netstack.NewPeer(name, func(raw []byte, nh byte) error {
		sealed, err := out.Seal(raw, nh)
		if err != nil {
			return err
		}
		return sess.Mux().SendESP(sealed)
	})
	speaker.AddPeer(peer)

	go sess.Run() // answers the peer's DPD liveness checks

	// Decryption is fanned out across up to inboundWorkers goroutines —
	// one packet at a time on a single goroutine couldn't keep up with a
	// fast enough real sender once reads were batched (transport.Mux.
	// readLoop), backing up and overflowing Mux's internal ESP channel:
	// real, permanent packet loss, confirmed live via the "espCh full,
	// dropping ESP packet" log. But delivery to mesh.DeliverInbound/
	// speaker.Receive must still happen in the *original* arrival order:
	// unlike outbound (see netstack.Mesh.outboundLoop's flow hashing),
	// there's no way to know a still-encrypted packet's flow to hash on,
	// so preserving order here means preserving *all* of it, not just
	// per-flow — confirmed live too, as retransmits from delivery-order
	// scrambling even after the channel-overflow fix. Each packet gets a
	// reserved slot (a 1-buffered result channel) in its original
	// position *before* decryption starts; a single emitter goroutine
	// drains slots in that same order, blocking on each one only as long
	// as it takes that specific decrypt to finish, so slow and fast
	// packets can still complete out of order without ever being
	// *delivered* out of order.
	type decrypted struct {
		plain []byte
		nh    byte
		err   error
	}
	order := make(chan chan decrypted, orderBufferSize)
	sem := make(chan struct{}, inboundWorkers)
	emitterDone := make(chan struct{})
	go func() {
		defer close(emitterDone)
		for slot := range order {
			r := <-slot
			if r.err != nil {
				log.Printf("peer %s: dropping undecryptable ESP packet: %v", name, r.err)
				continue
			}
			if speaker.Receive(peer, r.plain) {
				log.Printf("peer %s: received babel packet (%d bytes)", name, len(r.plain))
			} else {
				mesh.DeliverInbound(r.plain, r.nh)
			}
		}
	}()

	for {
		pkt, err := sess.Mux().RecvESP()
		if err != nil {
			close(order)
			<-emitterDone
			return err
		}
		slot := make(chan decrypted, 1)
		order <- slot
		sem <- struct{}{}
		go func(pkt []byte, slot chan decrypted) {
			defer func() { <-sem }()
			plain, nh, err := in.Open(pkt)
			slot <- decrypted{plain, nh, err}
		}(pkt, slot)
	}
}
