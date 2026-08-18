// Package config defines ranet-lite's own local configuration format.
// Unlike internal/registry (which mirrors ranet's registry.json and key
// files byte-for-byte so a deployment can reuse them unchanged), this file
// format is specific to ranet-lite: a slim client dialing out to one or a
// few existing mesh nodes rather than participating in ranet's full N-to-N
// reconciliation, so its config only needs "who am I" and "who do I dial".
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Identity: must match an entry in Registry's Nodes for Organization,
	// and PrivateKey must be that organization's shared Ed25519 key.
	Organization string `yaml:"organization"`
	CommonName   string `yaml:"common_name"`
	SerialNumber string `yaml:"serial_number"`

	PrivateKey string `yaml:"private_key"` // path to a PKCS8 PEM Ed25519 key
	Registry   string `yaml:"registry"`    // path to a ranet registry.json

	Originate []string `yaml:"originate"` // CIDR prefixes this node announces via babel
	// TUN names an existing TUN device to attach to, or the device to create
	// when it does not exist. Empty creates an automatically named ranet%d.
	TUN string `yaml:"tun"`

	Peers []Peer `yaml:"peers"`
	Babel Babel  `yaml:"babel"`
}

type Peer struct {
	// Organization defaults to the top-level Organization if empty —
	// almost always what you want, since ranet shares one keypair across
	// an entire organization; only cross-organization deployments need to
	// override it per peer.
	Organization string `yaml:"organization"`
	CommonName   string `yaml:"common_name"`
	// SerialNumber selects a specific endpoint; if empty, the first
	// endpoint of a matching address family is used.
	SerialNumber string `yaml:"serial_number"`
}

type Babel struct {
	HelloInterval  time.Duration `yaml:"hello_interval"`
	UpdateInterval time.Duration `yaml:"update_interval"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	c.setDefaults()
	return &c, c.validate()
}

func (c *Config) setDefaults() {
	for i := range c.Peers {
		if c.Peers[i].Organization == "" {
			c.Peers[i].Organization = c.Organization
		}
	}
}

func (c *Config) validate() error {
	switch {
	case c.Organization == "":
		return fmt.Errorf("config: organization is required")
	case c.CommonName == "":
		return fmt.Errorf("config: common_name is required")
	case c.SerialNumber == "":
		return fmt.Errorf("config: serial_number is required")
	case c.PrivateKey == "":
		return fmt.Errorf("config: private_key is required")
	case c.Registry == "":
		return fmt.Errorf("config: registry is required")
	case len(c.Peers) == 0:
		return fmt.Errorf("config: at least one peer is required")
	}
	return nil
}
