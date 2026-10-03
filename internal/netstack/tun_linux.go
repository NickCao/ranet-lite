//go:build linux

package netstack

import (
	"errors"
	"fmt"
	"os"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
)

const cloneDevicePath = "/dev/net/tun"

func bringTUNUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// createTUN uses wireguard-go's multiqueue device ownership and offload setup.
// CreateTUN omits IFF_MULTI_QUEUE when only one queue is requested. Preserve
// single-core attachment to an existing multiqueue interface in that case.
func createTUN(name string, mtu, queueCount int) (tun.Device, error) {
	device, err := tun.CreateTUN(name, mtu, tun.WithQueues(queueCount))
	if err == nil || queueCount != 1 || !errors.Is(err, unix.EINVAL) {
		return device, err
	}
	fd, err := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(name)
	if err == nil {
		ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR | unix.IFF_MULTI_QUEUE)
		err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
	}
	if err == nil {
		err = unix.SetNonblock(fd, true)
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("attach multiqueue tun %q: %w", name, err)
	}
	return tun.CreateTUNFromFile(os.NewFile(uintptr(fd), cloneDevicePath), mtu)
}
