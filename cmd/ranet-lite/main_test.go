package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/registry"
)

func TestInboundBatchOrderDeliversCompletedBatchesInReceiveOrder(t *testing.T) {
	const first, second = 0, 1

	firstResult := inboundDecrypted{authenticated: new(esp.AuthenticatedPacket)}
	secondResult := inboundDecrypted{authenticated: new(esp.AuthenticatedPacket)}
	completed := make(chan *inboundBatch, 2)
	recycled := make(chan *inboundBatch, 2)
	delivered := make(chan byte, 2)
	emitterDone := make(chan struct{})
	go func() {
		emitInboundBatches(completed, recycled, func(results []inboundDecrypted) {
			if results[0].authenticated == firstResult.authenticated {
				delivered <- 1
			} else {
				delivered <- 2
			}
		})
		close(emitterDone)
	}()
	completed <- &inboundBatch{ticket: second, results: []inboundDecrypted{secondResult}}
	select {
	case got := <-delivered:
		t.Fatalf("later batch %d delivered before the first batch", got)
	default:
	}
	completed <- &inboundBatch{ticket: first, results: []inboundDecrypted{firstResult}}
	close(completed)
	<-emitterDone
	close(delivered)

	var got []byte
	for value := range delivered {
		got = append(got, value)
	}
	if !bytes.Equal(got, []byte{1, 2}) {
		t.Fatalf("delivery order = %v, want [1 2]", got)
	}
}

func runtimeFixture(t *testing.T) (*config.Config, ed25519.PrivateKey, registry.Registry) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	reg := registry.Registry{{
		Organization: "example", PublicKey: publicPEM,
		Nodes: []registry.Node{
			{CommonName: "local", Endpoints: []registry.Endpoint{{SerialNumber: "0", AddressFamily: "ip4", Port: 13000}}},
			{CommonName: "gateway", Endpoints: []registry.Endpoint{{SerialNumber: "1", AddressFamily: "ip4", Port: 13000}}},
		},
	}}
	cfg := &config.Config{
		Organization: "example", CommonName: "local",
		Endpoints: []config.Endpoint{{SerialNumber: "0", AddressFamily: "ip4"}},
		Peers:     []config.Peer{{Organization: "example", CommonName: "gateway", SerialNumber: "1"}},
	}
	return cfg, privateKey, reg
}

func TestValidateRuntimeConfig(t *testing.T) {
	cfg, privateKey, reg := runtimeFixture(t)
	if err := validateRuntimeConfig(cfg, privateKey, reg); err != nil {
		t.Fatal(err)
	}
	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRuntimeConfig(cfg, wrongKey, reg); err == nil {
		t.Fatal("accepted a private key from another organization")
	}
	cfg.Peers[0].SerialNumber = "missing"
	if err := validateRuntimeConfig(cfg, privateKey, reg); err == nil {
		t.Fatal("accepted a peer endpoint missing from the registry")
	}
}

func TestValidateESPTunnelPayload(t *testing.T) {
	ipv4 := make([]byte, 20)
	ipv4[0], ipv4[3] = 0x45, 20
	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60
	for _, test := range []struct {
		name    string
		plain   []byte
		nh      byte
		deliver bool
		wantErr bool
	}{
		{name: "IPv4", plain: ipv4, nh: esp.NextHeaderIPv4, deliver: true},
		{name: "IPv6", plain: ipv6, nh: esp.NextHeaderIPv6, deliver: true},
		{name: "dummy", plain: ipv6, nh: esp.NextHeaderNone},
		{name: "version mismatch", plain: ipv6, nh: esp.NextHeaderIPv4, wantErr: true},
		{name: "unsupported", plain: ipv4, nh: 6, wantErr: true},
		{name: "IPv4 trailing data", plain: append(append([]byte(nil), ipv4...), 0), nh: esp.NextHeaderIPv4, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			deliver, err := validateESPTunnelPayload(test.plain, test.nh)
			if (err != nil) != test.wantErr || deliver != test.deliver {
				t.Fatalf("got deliver=%v err=%v; want deliver=%v err=%v", deliver, err, test.deliver, test.wantErr)
			}
		})
	}
}
