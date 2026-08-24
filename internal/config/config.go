// Package config defines ranet-lite's own local configuration format.
// Unlike internal/registry (which mirrors ranet's registry.json and key
// files byte-for-byte so a deployment can reuse them unchanged), this file
// format is specific to ranet-lite: a slim client dialing out to one or a
// few existing mesh nodes rather than participating in ranet's full N-to-N
// reconciliation, so its config only needs "who am I" and "who do I dial".
package config

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
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
	// ReplayWindow controls the ESP receive window: omitted uses 4096 for
	// high-speed multicore senders, while an explicit 0 disables checking.
	ReplayWindow *uint32 `yaml:"replay_window"`
	// Rekey intervals default to one hour for Child SAs and three hours for
	// IKE SAs. An explicit zero disables the corresponding proactive rekey.
	ChildRekeyInterval *Duration `yaml:"child_rekey_interval"`
	IKERekeyInterval   *Duration `yaml:"ike_rekey_interval"`
	// Rekeys run before their interval expires: margin is always subtracted
	// and jitter is independently randomized from zero through its value.
	RekeyMargin *Duration `yaml:"rekey_margin"`
	RekeyJitter *Duration `yaml:"rekey_jitter"`
	// A failed scheduled rekey is retried with capped exponential backoff.
	RekeyRetryInitial *Duration `yaml:"rekey_retry_initial"`
	RekeyRetryMax     *Duration `yaml:"rekey_retry_max"`

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
		return 4096
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

func (c *Config) RekeyMarginValue() time.Duration {
	if c.RekeyMargin == nil {
		return 5 * time.Minute
	}
	return time.Duration(*c.RekeyMargin)
}

func (c *Config) RekeyJitterValue() time.Duration {
	if c.RekeyJitter == nil {
		return time.Minute
	}
	return time.Duration(*c.RekeyJitter)
}

func (c *Config) RekeyRetryInitialValue() time.Duration {
	if c.RekeyRetryInitial == nil {
		return 5 * time.Second
	}
	return time.Duration(*c.RekeyRetryInitial)
}

func (c *Config) RekeyRetryMaxValue() time.Duration {
	if c.RekeyRetryMax == nil {
		return 5 * time.Minute
	}
	return time.Duration(*c.RekeyRetryMax)
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
	decoder := yaml.NewDecoder(strings.NewReader(string(b)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&c); err != nil {
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
	case c.ReplayWindow != nil && *c.ReplayWindow > 1<<20:
		return fmt.Errorf("config: replay_window must not exceed %d", uint32(1<<20))
	case c.Babel.HelloInterval < 0 || c.Babel.UpdateInterval < 0:
		return fmt.Errorf("config: babel intervals must be nonnegative")
	case c.Babel.HelloInterval > 0 && c.Babel.HelloInterval < 10*time.Millisecond:
		return fmt.Errorf("config: babel hello_interval must be at least 10ms")
	case c.Babel.UpdateInterval > 0 && c.Babel.UpdateInterval < 10*time.Millisecond:
		return fmt.Errorf("config: babel update_interval must be at least 10ms")
	case c.Babel.HelloInterval > 655350*time.Millisecond || c.Babel.UpdateInterval > 655350*time.Millisecond:
		return fmt.Errorf("config: babel intervals must fit the protocol's 16-bit centisecond field")
	case c.ChildRekeyInterval != nil && time.Duration(*c.ChildRekeyInterval) < 0:
		return fmt.Errorf("config: child_rekey_interval must be nonnegative when set")
	case c.IKERekeyInterval != nil && time.Duration(*c.IKERekeyInterval) < 0:
		return fmt.Errorf("config: ike_rekey_interval must be nonnegative when set")
	case c.RekeyMargin != nil && time.Duration(*c.RekeyMargin) < 0:
		return fmt.Errorf("config: rekey_margin must be nonnegative when set")
	case c.RekeyJitter != nil && time.Duration(*c.RekeyJitter) < 0:
		return fmt.Errorf("config: rekey_jitter must be nonnegative when set")
	case c.RekeyRetryInitial != nil && time.Duration(*c.RekeyRetryInitial) <= 0:
		return fmt.Errorf("config: rekey_retry_initial must be positive when set")
	case c.RekeyRetryMax != nil && time.Duration(*c.RekeyRetryMax) <= 0:
		return fmt.Errorf("config: rekey_retry_max must be positive when set")
	case c.RekeyRetryInitialValue() > c.RekeyRetryMaxValue():
		return fmt.Errorf("config: rekey_retry_initial must not exceed rekey_retry_max")
	case !validRekeyTiming(c.ChildRekeyIntervalValue(), c.RekeyMarginValue(), c.RekeyJitterValue()):
		return fmt.Errorf("config: rekey_margin plus rekey_jitter must be less than child_rekey_interval")
	case !validRekeyTiming(c.IKERekeyIntervalValue(), c.RekeyMarginValue(), c.RekeyJitterValue()):
		return fmt.Errorf("config: rekey_margin plus rekey_jitter must be less than ike_rekey_interval")
	}
	endpointSerials := make(map[string]struct{}, len(c.Endpoints))
	for _, ep := range c.Endpoints {
		if ep.SerialNumber == "" || (ep.AddressFamily != "ip4" && ep.AddressFamily != "ip6") {
			return fmt.Errorf("config: endpoints require serial_number and address_family (ip4 or ip6)")
		}
		if _, exists := endpointSerials[ep.SerialNumber]; exists {
			return fmt.Errorf("config: duplicate endpoint serial_number %q", ep.SerialNumber)
		}
		endpointSerials[ep.SerialNumber] = struct{}{}
	}
	peers := make(map[string]struct{}, len(c.Peers))
	for _, peer := range c.Peers {
		if peer.Organization == "" || peer.CommonName == "" {
			return fmt.Errorf("config: peers require organization and common_name")
		}
		key := peer.Organization + "\x00" + peer.CommonName + "\x00" + peer.SerialNumber
		if _, exists := peers[key]; exists {
			return fmt.Errorf("config: duplicate peer %s/%s endpoint %q", peer.Organization, peer.CommonName, peer.SerialNumber)
		}
		peers[key] = struct{}{}
	}
	for _, raw := range c.Originate {
		if _, err := netip.ParsePrefix(raw); err != nil {
			return fmt.Errorf("config: originate %q: %w", raw, err)
		}
	}
	return nil
}

func validRekeyTiming(interval, margin, jitter time.Duration) bool {
	return interval == 0 || (margin < interval && jitter < interval-margin)
}
