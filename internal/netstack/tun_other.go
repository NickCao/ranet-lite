//go:build !linux

package netstack

import "golang.zx2c4.com/wireguard/tun"

func createTUNQueues(name string, mtu, _ int) ([]tun.Device, string, error) {
	device, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, "", err
	}
	actualName, err := device.Name()
	if err != nil {
		_ = device.Close()
		return nil, "", err
	}
	return []tun.Device{device}, actualName, nil
}
