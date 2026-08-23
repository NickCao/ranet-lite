//go:build linux

package netstack

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

const cloneDevicePath = "/dev/net/tun"

// createTUNQueues opens one file descriptor per Linux multiqueue TUN lane.
// Each descriptor is wrapped in its own wireguard-go Device, which gives every
// data-plane worker independent read buffers, GRO tables, and I/O locks.
func createTUNQueues(name string, mtu, queueCount int) ([]tun.Device, string, error) {
	devices := make([]tun.Device, 0, queueCount)
	closeDevices := func() {
		for _, device := range devices {
			_ = device.Close()
		}
	}

	actualName := name
	for i := 0; i < queueCount; i++ {
		fd, err := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			closeDevices()
			return nil, "", fmt.Errorf("open %s for queue %d: %w", cloneDevicePath, i, err)
		}

		requestName := actualName
		if i == 0 {
			requestName = name
		}
		ifr, err := unix.NewIfreq(requestName)
		if err == nil {
			ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR | unix.IFF_MULTI_QUEUE)
			err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
		}
		if err != nil {
			_ = unix.Close(fd)
			closeDevices()
			return nil, "", fmt.Errorf("attach multiqueue tun %q queue %d: %w", requestName, i, err)
		}
		if i == 0 {
			actualName = ifr.Name()
		}

		var device tun.Device
		if i == 0 {
			file := os.NewFile(uintptr(fd), cloneDevicePath)
			device, err = tun.CreateTUNFromFile(file, mtu)
			if err != nil {
				_ = file.Close()
			}
		} else {
			device, _, err = tun.CreateUnmonitoredTUNFromFD(fd)
		}
		if err != nil {
			closeDevices()
			return nil, "", fmt.Errorf("initialize tun %q queue %d: %w", actualName, i, err)
		}
		devices = append(devices, device)
	}
	return devices, actualName, nil
}
