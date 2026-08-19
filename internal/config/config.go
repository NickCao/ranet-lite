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
	Organization string     `yaml:"organization"`
	CommonName   string     `yaml:"common_name"`
	Port         uint16     `yaml:"port"`
	Endpoints    []Endpoint `yaml:"endpoints"`

	PrivateKey string `yaml:"private_key"` // path to a PKCS8 PEM Ed25519 key
	Registry   string `yaml:"registry"`    // path to a ranet registry.json

	Originate []string `yaml:"originate"` // CIDR prefixes this node announces via babel
	// TUN names an existing TUN device to attach to, or the device to create
	// when it does not exist. Empty creates an automatically named ranet%d.
	TUN string `yaml:"tun"`
	// ReplayWindow matches strongSwan's child replay_window: omitted uses 32,
	// while an explicit 0 disables replay checking.
	ReplayWindow *uint32 `yaml:"replay_window"`
	// Rekey intervals default to one hour for Child SAs and three hours for
	// IKE SAs. An explicit zero disables the corresponding proactive rekey.
	ChildRekeyInterval *Duration `yaml:"child_rekey_interval"`
	IKERekeyInterval   *Duration `yaml:"ike_rekey_interval"`

	Peers []Peer `yaml:"peers"`
	Babel Babel  `yaml:"babel"`
}

// Duration accepts standard Go duration strings and a bare YAML zero.
// The latter keeps `child_rekey_interval: 0` concise when disabling rekeys.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode && value.Tag == "!!int" && value.Value == "0" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(value.Value)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (c *Config) ReplayWindowSize() uint32 {
	if c.ReplayWindow == nil {
		return 32
	}
	return *c.ReplayWindow
}

func (c *Config) ChildRekeyIntervalValue() time.Duration {
	if c.ChildRekeyInterval == nil {
		return time.Hour
	}
	return time.Duration(*c.ChildRekeyInterval)
}

func (c *Config) IKERekeyIntervalValue() time.Duration {
	if c.IKERekeyInterval == nil {
		return 3 * time.Hour
	}
	return time.Duration(*c.IKERekeyInterval)
}

// Endpoint mirrors the identity portion of ranet's endpoint configuration.
// Socket address selection is global: StdNetBind owns one dual-stack socket
// on Config.Port and the kernel selects the source address by route.
type Endpoint struct {
	SerialNumber  string `yaml:"serial_number"`
	AddressFamily string `yaml:"address_family"`
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
	case c.Port == 0:
		return fmt.Errorf("config: port is required")
	case len(c.Endpoints) == 0:
		return fmt.Errorf("config: at least one endpoint is required")
	case c.PrivateKey == "":
		return fmt.Errorf("config: private_key is required")
	case c.Registry == "":
		return fmt.Errorf("config: registry is required")
	case len(c.Peers) == 0:
		return fmt.Errorf("config: at least one peer is required")
	case c.ChildRekeyInterval != nil && time.Duration(*c.ChildRekeyInterval) < 0:
		return fmt.Errorf("config: child_rekey_interval must be positive when set")
	case c.IKERekeyInterval != nil && time.Duration(*c.IKERekeyInterval) < 0:
		return fmt.Errorf("config: ike_rekey_interval must be positive when set")
	}
	for _, ep := range c.Endpoints {
		if ep.SerialNumber == "" || (ep.AddressFamily != "ip4" && ep.AddressFamily != "ip6") {
			return fmt.Errorf("config: endpoints require serial_number and address_family (ip4 or ip6)")
		}
	}
	return nil
}
