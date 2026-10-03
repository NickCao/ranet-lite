//go:build !linux

package netstack

import "github.com/tailscale/wireguard-go/tun"

// Keep the platform TUN backend's existing behavior outside Linux.
func bringTUNUp(string) error { return nil }

func createTUN(name string, mtu, _ int) (tun.Device, error) {
	device, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, err
	}
	return device, nil
}
