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
	"log/slog"
	"net/http"
	_ "net/http/pprof" // registered on DefaultServeMux only if -pprof is set, see below
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/babel"
	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/internal/registry"
	"github.com/NickCao/ranet-lite/internal/transport"
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
	contentionProfiles := flag.Bool("contention-profiles", false, "record every mutex and blocking event while pprof is enabled (high overhead)")
	logLevel := flag.String("log-level", "info", "minimum log level: debug, info, warn, or error")
	flag.Parse()
	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		log.Fatalf("invalid -log-level %q: %v", *logLevel, err)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	if *pprofAddr != "" {
		if *contentionProfiles {
			runtime.SetMutexProfileFraction(1)
			runtime.SetBlockProfileRate(1)
		}
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

	mesh, err := netstack.NewNamed(0, cfg.TUN)
	if err != nil {
		log.Fatal(err)
	}
	if cfg.TUN == "" {
		log.Printf("tun device %s created; assign it an address and add routes yourself before traffic will flow", mesh.Name)
	} else {
		log.Printf("using tun device %s", mesh.Name)
	}

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

	hub, err := transport.NewHub(fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		log.Fatal(err)
	}
	defer hub.Close()
	for _, local := range cfg.Endpoints {
		for _, p := range cfg.Peers {
			go runPeer(ctx, priv, cfg, local, p, reg, mesh, speaker, hub)
		}
	}
	if err := speaker.Run(ctx); err != nil && ctx.Err() == nil {
		log.Printf("babel: %v", err)
	}
}

// runPeer maintains one peer connection for the client's lifetime,
// reconnecting on any failure (network blip, peer restart, etc.) rather
// than requiring a manual restart.
func runPeer(ctx context.Context, priv ed25519.PrivateKey, cfg *config.Config, local config.Endpoint, p config.Peer, reg registry.Registry, mesh *netstack.Mesh, speaker *babel.Speaker, hub *transport.Hub) {
	name := fmt.Sprintf("%s/%s@%s", p.Organization, p.CommonName, local.SerialNumber)
	if p.SerialNumber != "" {
		org, ok := reg.FindOrganization(p.Organization)
		if !ok {
			log.Printf("peer %s: organization %q not found", name, p.Organization)
			return
		}
		node, ok := org.FindNode(p.CommonName)
		if !ok {
			log.Printf("peer %s: node not found", name)
			return
		}
		ep, ok := node.FindEndpoint(p.SerialNumber)
		if !ok {
			log.Printf("peer %s: endpoint serial %q not found", name, p.SerialNumber)
			return
		}
		if ep.AddressFamily != local.AddressFamily {
			return
		}
	}
	for {
		if ctx.Err() != nil {
			return
		}
		if err := connectPeer(ctx, priv, cfg, local, p, reg, mesh, speaker, name, hub); err != nil {
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
func resolveEndpoint(node registry.Node, serial, family string) (registry.Endpoint, error) {
	if serial != "" {
		ep, ok := node.FindEndpoint(serial)
		if !ok {
			return registry.Endpoint{}, fmt.Errorf("no endpoint with serial %q", serial)
		}
		if ep.AddressFamily != family {
			return registry.Endpoint{}, fmt.Errorf("endpoint %q is %s, want %s", serial, ep.AddressFamily, family)
		}
		return ep, nil
	}
	for _, ep := range node.Endpoints {
		if ep.AddressFamily == family {
			if _, err := ep.ResolveRemote(); err == nil {
				return ep, nil
			}
		}
	}
	return registry.Endpoint{}, fmt.Errorf("no endpoint currently resolves to an address")
}

// connectPeer runs one IKE session against a peer end to end: handshake,
// ESP setup, mesh/babel registration, and servicing the connection until
// it dies (network failure, peer restart, DPD timeout). Returning means
// the connection is gone; runPeer decides whether/when to retry.
func connectPeer(ctx context.Context, priv ed25519.PrivateKey, cfg *config.Config, local config.Endpoint, p config.Peer, reg registry.Registry, mesh *netstack.Mesh, speaker *babel.Speaker, name string, hub *transport.Hub) error {
	org, ok := reg.FindOrganization(p.Organization)
	if !ok {
		return fmt.Errorf("organization %q not found in registry", p.Organization)
	}
	node, ok := org.FindNode(p.CommonName)
	if !ok {
		return fmt.Errorf("node %q not found in organization %q", p.CommonName, p.Organization)
	}
	ep, err := resolveEndpoint(node, p.SerialNumber, local.AddressFamily)
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
	sessionName := fmt.Sprintf("%s/%s/%s@%s", p.Organization, p.CommonName, ep.SerialNumber, local.SerialNumber)
	log.Printf("peer %s: dialing %s:%d", sessionName, remoteIP, ep.Port)

	ikeCfg := ike.PeerConfig{
		Organization:       cfg.Organization,
		LocalCommonName:    cfg.CommonName,
		LocalSerial:        local.SerialNumber,
		LocalPrivateKey:    priv,
		RemoteCommonName:   node.CommonName,
		RemoteSerial:       ep.SerialNumber,
		RemotePublicKey:    remotePub,
		RemoteAddr:         remoteIP,
		RemotePort:         int(ep.Port),
		Hub:                hub,
		ChildRekeyInterval: cfg.ChildRekeyIntervalValue(),
		IKERekeyInterval:   cfg.IKERekeyIntervalValue(),
		RekeyMargin:        cfg.RekeyMarginValue(),
		RekeyJitter:        cfg.RekeyJitterValue(),
		RekeyRetryInitial:  cfg.RekeyRetryInitialValue(),
		RekeyRetryMax:      cfg.RekeyRetryMaxValue(),
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
	in, err := esp.NewInbound(sess.Child, esp.WithReplayWindow(cfg.ReplayWindowSize()))
	if err != nil {
		return err
	}

	// A peer-initiated rekey installs its new SAs before its IKE response is
	// sent. Retain the immediately preceding inbound SA for packets already
	// in flight on the replaced SPI (RFC 7296 section 2.8 overlap).
	var saMu sync.RWMutex
	type inboundSA struct {
		spi uint32
		sa  *esp.InboundSA
	}
	inbound := []inboundSA{{spi: sess.Child.LocalSPI, sa: in}}
	sess.SetChildHandler(func(child ike.ChildSA) error {
		newOut, err := esp.NewOutbound(child)
		if err != nil {
			return err
		}
		newIn, err := esp.NewInbound(child, esp.WithReplayWindow(cfg.ReplayWindowSize()))
		if err != nil {
			return err
		}
		saMu.Lock()
		out, in = newOut, newIn
		inbound = append([]inboundSA{{spi: child.LocalSPI, sa: in}}, inbound...)
		saMu.Unlock()
		return nil
	})
	sess.SetChildRetireHandler(func(localSPI uint32) error {
		saMu.Lock()
		defer saMu.Unlock()
		for i := range inbound {
			if inbound[i].spi == localSPI {
				inbound = append(inbound[:i], inbound[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("retiring inbound ESP SPI %08x was not installed", localSPI)
	})
	peer := netstack.NewPeerBatched(sessionName, func(raw []byte, nextHeader byte) ([]byte, error) {
		saMu.RLock()
		sa := out
		saMu.RUnlock()
		sealed, err := sa.Seal(raw, nextHeader)
		if err != nil {
			// A non-ESN SA cannot safely keep transmitting after sequence
			// exhaustion. Tear it down so runPeer establishes fresh SAs.
			sess.Mux().Close()
		}
		return sealed, err
	}, sess.Mux().SendESPBatch)
	peerHandle := speaker.AddPeer(peer)
	defer peerHandle.Close()

	// Decrypt in parallel, but reserve result slots before dispatch so the
	// emitter delivers packets in their original arrival order.
	type decrypted struct {
		plain []byte
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
			if !speaker.Receive(peer, r.plain) {
				mesh.DeliverInbound(r.plain)
			}
		}
	}()

	runESP := func() error {
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
				saMu.RLock()
				candidates := append([]inboundSA(nil), inbound...)
				saMu.RUnlock()
				var plain []byte
				var err error
				for _, candidate := range candidates {
					plain, _, err = candidate.sa.Open(pkt)
					if err == nil {
						break
					}
				}
				if err == nil {
					sess.NoteTraffic()
				}
				slot <- decrypted{plain: plain, err: err}
			}(pkt, slot)
		}
	}
	type sessionResult struct {
		component string
		err       error
	}
	results := make(chan sessionResult, 2)
	go func() { results <- sessionResult{"IKE control", sess.Run(ctx)} }()
	go func() { results <- sessionResult{"ESP receive", runESP()} }()
	first := <-results
	_ = sess.Mux().Close()
	<-results
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("%s session ended: %w", first.component, first.err)
}
