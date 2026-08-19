package registry

import "testing"

// TestLoadRegistry exercises the real-world edge cases a production ranet
// registry actually contains (verified against one during development,
// which is not checked in here since registries list real deployments'
// public keys and addresses): null addresses, empty-string addresses
// (distinct from null), hostnames, literal IPv4/IPv6 addresses, and
// non-sequential serial numbers.
func TestLoadRegistry(t *testing.T) {
	reg, err := Load("testdata/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(reg) == 0 {
		t.Fatal("no organizations parsed")
	}

	org, ok := reg.FindOrganization("example")
	if !ok {
		t.Fatal("organization \"example\" not found")
	}
	if _, err := org.ParsePublicKey(); err != nil {
		t.Fatalf("parse example public key: %v", err)
	}

	// A node with address: null — no known address yet. ResolveRemote
	// must fail gracefully, not panic.
	noAddr, ok := org.FindNode("no-address-yet")
	if !ok {
		t.Fatal("node \"no-address-yet\" not found")
	}
	ep, ok := noAddr.FindEndpoint("0")
	if !ok {
		t.Fatal("endpoint serial 0 not found")
	}
	if ep.Address != nil {
		t.Fatalf("expected nil address, got %v", *ep.Address)
	}
	if _, err := ep.ResolveRemote(); err == nil {
		t.Fatal("expected ResolveRemote to fail for a nil address")
	}

	// address: "" (empty string, distinct from null) must also fail
	// gracefully rather than being treated as a valid target.
	emptyAddr, ok := org.FindNode("empty-address")
	if !ok {
		t.Fatal("node \"empty-address\" not found")
	}
	ep, ok = emptyAddr.FindEndpoint("0")
	if !ok {
		t.Fatal("endpoint serial 0 not found")
	}
	if ep.Address == nil || *ep.Address != "" {
		t.Fatalf("expected empty-string address, got %v", ep.Address)
	}
	if _, err := ep.ResolveRemote(); err == nil {
		t.Fatal("expected ResolveRemote to fail for an empty-string address")
	}

	// A hostname address; just confirm the field parsed correctly — DNS
	// resolution success/failure is environment-dependent and not what
	// this parser test should assert on.
	gw, ok := org.FindNode("gateway")
	if !ok {
		t.Fatal("node \"gateway\" not found")
	}
	ep, ok = gw.FindEndpoint("0")
	if !ok {
		t.Fatal("endpoint serial 0 not found")
	}
	if ep.Address == nil || *ep.Address != "gateway.example.invalid" {
		t.Fatalf("unexpected address: %v", ep.Address)
	}
	if ep.AddressFamily != "ip4" || ep.Port != 13000 {
		t.Fatalf("unexpected endpoint: %+v", ep)
	}

	// Non-sequential serial numbers (e.g. "4"/"6" instead of "0"/"1") are
	// used by some real deployments — confirm lookup isn't assuming 0/1.
	nonSeq, ok := org.FindNode("non-sequential-serials")
	if !ok {
		t.Fatal("node \"non-sequential-serials\" not found")
	}
	if _, ok := nonSeq.FindEndpoint("4"); !ok {
		t.Fatal("endpoint serial 4 not found")
	}
	if _, ok := nonSeq.FindEndpoint("6"); !ok {
		t.Fatal("endpoint serial 6 not found")
	}

	// A literal (non-hostname) address should resolve directly without DNS.
	other, ok := reg.FindOrganization("other-org")
	if !ok {
		t.Fatal("organization \"other-org\" not found")
	}
	lit, ok := other.FindNode("literal-address")
	if !ok {
		t.Fatal("node \"literal-address\" not found")
	}
	ep, ok = lit.FindEndpoint("0")
	if !ok {
		t.Fatal("endpoint serial 0 not found")
	}
	ip, err := ep.ResolveRemote()
	if err != nil {
		t.Fatalf("ResolveRemote: %v", err)
	}
	if ip.String() != "192.0.2.1" {
		t.Fatalf("got %v, want 192.0.2.1", ip)
	}
}

func TestRegistryValidationRejectsDuplicateIdentities(t *testing.T) {
	reg, err := Load("testdata/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	reg = append(reg, reg[0])
	if err := reg.Validate(); err == nil {
		t.Fatal("Validate accepted duplicate organizations")
	}
}
