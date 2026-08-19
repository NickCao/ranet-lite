// Package registry reads ranet's own registry and key file formats
// unchanged, so a ranet-lite deployment can point at the exact same
// registry.json and Ed25519 keys an existing ranet mesh already uses.
// Schema mirrors github.com/NickCao/ranet's src/registry.rs field for
// field (verified against its own test fixture, not guessed).
package registry

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
)

type Registry []Organization

type Organization struct {
	PublicKey    string `json:"public_key"` // PEM SubjectPublicKeyInfo, one Ed25519 key shared by every node in the org
	Organization string `json:"organization"`
	Nodes        []Node `json:"nodes"`
}

type Node struct {
	CommonName string          `json:"common_name"`
	Endpoints  []Endpoint      `json:"endpoints"`
	Remarks    json.RawMessage `json:"remarks"`
}

type Endpoint struct {
	SerialNumber  string  `json:"serial_number"`
	AddressFamily string  `json:"address_family"` // "ip4" or "ip6"
	Address       *string `json:"address"`        // literal IP, hostname, or absent (wildcard)
	Port          uint16  `json:"port"`
}

func Load(path string) (Registry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("registry: read %s: %w", path, err)
	}
	var r Registry
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&r); err != nil {
		return nil, fmt.Errorf("registry: parse %s: %w", path, err)
	}
	return r, r.Validate()
}

func (r Registry) Validate() error {
	organizations := make(map[string]struct{}, len(r))
	for _, organization := range r {
		if organization.Organization == "" {
			return fmt.Errorf("registry: organization name is required")
		}
		if _, exists := organizations[organization.Organization]; exists {
			return fmt.Errorf("registry: duplicate organization %q", organization.Organization)
		}
		organizations[organization.Organization] = struct{}{}
		if _, err := organization.ParsePublicKey(); err != nil {
			return err
		}
		nodes := make(map[string]struct{}, len(organization.Nodes))
		for _, node := range organization.Nodes {
			if node.CommonName == "" {
				return fmt.Errorf("registry: organization %q has a node without common_name", organization.Organization)
			}
			if _, exists := nodes[node.CommonName]; exists {
				return fmt.Errorf("registry: duplicate node %q in organization %q", node.CommonName, organization.Organization)
			}
			nodes[node.CommonName] = struct{}{}
			endpoints := make(map[string]struct{}, len(node.Endpoints))
			for _, endpoint := range node.Endpoints {
				if endpoint.SerialNumber == "" || endpoint.Port == 0 || (endpoint.AddressFamily != "ip4" && endpoint.AddressFamily != "ip6") {
					return fmt.Errorf("registry: node %q has an invalid endpoint", node.CommonName)
				}
				if _, exists := endpoints[endpoint.SerialNumber]; exists {
					return fmt.Errorf("registry: duplicate endpoint %q on node %q", endpoint.SerialNumber, node.CommonName)
				}
				endpoints[endpoint.SerialNumber] = struct{}{}
			}
		}
	}
	return nil
}

// ParsePublicKey parses the organization's shared Ed25519 SubjectPublicKeyInfo PEM.
func (o Organization) ParsePublicKey() (ed25519.PublicKey, error) {
	blk, _ := pem.Decode([]byte(o.PublicKey))
	if blk == nil {
		return nil, fmt.Errorf("registry: organization %q: no PEM block in public_key", o.Organization)
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("registry: organization %q: parse public key: %w", o.Organization, err)
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("registry: organization %q: public key is not Ed25519", o.Organization)
	}
	return ed, nil
}

// FindOrganization returns the named organization, if present.
func (r Registry) FindOrganization(name string) (Organization, bool) {
	for _, o := range r {
		if o.Organization == name {
			return o, true
		}
	}
	return Organization{}, false
}

// FindNode returns the named node within organization, if present.
func (o Organization) FindNode(commonName string) (Node, bool) {
	for _, n := range o.Nodes {
		if n.CommonName == commonName {
			return n, true
		}
	}
	return Node{}, false
}

// FindEndpoint returns the endpoint with the given serial number, if present.
func (n Node) FindEndpoint(serial string) (Endpoint, bool) {
	for _, e := range n.Endpoints {
		if e.SerialNumber == serial {
			return e, true
		}
	}
	return Endpoint{}, false
}

// ResolveRemote resolves an endpoint's address for dialing, mirroring
// ranet's src/address.rs `remote`: a literal IP is used directly; a
// hostname is resolved via DNS and filtered to the endpoint's declared
// address family; if that fails, ranet falls back to the address family's
// wildcard, which isn't a dialable address — callers must treat a failure
// here as "endpoint not currently reachable", not retry with a wildcard.
func (e Endpoint) ResolveRemote() (net.IP, error) {
	if e.Address == nil {
		return nil, fmt.Errorf("registry: endpoint %s has no address", e.SerialNumber)
	}
	if ip := net.ParseIP(*e.Address); ip != nil {
		if !addressFamilyMatches(e.AddressFamily, ip) {
			return nil, fmt.Errorf("registry: endpoint %s address %s does not match declared family %s", e.SerialNumber, *e.Address, e.AddressFamily)
		}
		return ip, nil
	}
	ips, err := net.LookupIP(*e.Address)
	if err != nil {
		return nil, fmt.Errorf("registry: resolve %s: %w", *e.Address, err)
	}
	for _, ip := range ips {
		if addressFamilyMatches(e.AddressFamily, ip) {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("registry: %s has no %s address", *e.Address, e.AddressFamily)
}

func addressFamilyMatches(family string, ip net.IP) bool {
	switch family {
	case "ip4":
		return ip.To4() != nil
	case "ip6":
		return ip.To4() == nil
	default:
		return false
	}
}
