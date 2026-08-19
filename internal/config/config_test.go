package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testConfig = `
organization: example
common_name: laptop
port: 13000
endpoints:
  - serial_number: "0"
    address_family: ip4
private_key: key.pem
registry: registry.json
peers:
  - common_name: gateway
`

func TestRekeyIntervals(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantChild time.Duration
		wantIKE   time.Duration
		wantErr   bool
	}{
		{name: "defaults", yaml: testConfig, wantChild: time.Hour, wantIKE: 3 * time.Hour},
		{name: "explicitly disabled", yaml: testConfig + "child_rekey_interval: 0\nike_rekey_interval: 0\n"},
		{name: "configured", yaml: testConfig + "child_rekey_interval: 2h\nike_rekey_interval: 8h\n", wantChild: 2 * time.Hour, wantIKE: 8 * time.Hour},
		{name: "negative child", yaml: testConfig + "child_rekey_interval: -1s\n", wantErr: true},
		{name: "negative IKE", yaml: testConfig + "ike_rekey_interval: -1s\n", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(test.yaml), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if test.wantErr {
				if err == nil {
					t.Fatal("Load succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ChildRekeyIntervalValue() != test.wantChild || cfg.IKERekeyIntervalValue() != test.wantIKE {
				t.Fatalf("rekey intervals = %s, %s; want %s, %s", cfg.ChildRekeyIntervalValue(), cfg.IKERekeyIntervalValue(), test.wantChild, test.wantIKE)
			}
		})
	}
}
