//go:build linux
// +build linux

// Package wgctrl enables control of WireGuard devices on multiple platforms.
//
// For more information on WireGuard, please see https://www.wireguard.com/.
//
// This package implements WireGuard configuration protocol operations, enabling
// the configuration of existing WireGuard devices. Operations such as creating
// WireGuard devices, or applying IP addresses to those devices, are out of scope
// for this package.
package wgctrl

import (
	"errors"
	"os"

	"golang.zx2c4.com/wireguard/wgctrl/internal/wginternal"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wglinux"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wguser"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Expose an identical interface to the underlying packages.
var _ wginternal.Client = &Client{}

// A Client provides access to WireGuard device information.
type Client struct {
	// Seamlessly use different wginternal.Client implementations to provide an
	// interface similar to wg(8).
	cs []wginternal.Client
}

// New creates a new Client.
func New() (*Client, error) {
	cs, err := newClients()
	if err != nil {
		return nil, err
	}

	return &Client{
		cs: cs,
	}, nil
}

// newClients configures wginternal.Clients for Linux systems.
func newClients() ([]wginternal.Client, error) {
	var clients []wginternal.Client

	// Linux has an in-kernel WireGuard implementation. Determine if it is
	// available and make use of it if so.
	kc, ok, err := wglinux.New()
	if err != nil {
		return nil, err
	}
	if ok {
		clients = append(clients, kc)
	}

	// Although it isn't recommended to use userspace implementations on Linux,
	// it can be used. We make use of it in integration tests as well.
	uc, err := wguser.New()
	if err != nil {
		return nil, err
	}

	// Kernel devices seem to appear first in wg(8).
	clients = append(clients, uc)
	return clients, nil
}

// Close releases resources used by a Client.
func (c *Client) Close() error {
	for _, wgc := range c.cs {
		if err := wgc.Close(); err != nil {
			return err
		}
	}

	return nil
}

// Devices retrieves all WireGuard devices on this system.
func (c *Client) Devices() ([]*wgtypes.Device, error) {
	var out []*wgtypes.Device
	for _, wgc := range c.cs {
		devs, err := wgc.Devices()
		if err != nil {
			return nil, err
		}

		out = append(out, devs...)
	}

	return out, nil
}

// Device retrieves a WireGuard device by its interface name.
//
// If the device specified by name does not exist or is not a WireGuard device,
// an error is returned which can be checked using `errors.Is(err, os.ErrNotExist)`.
func (c *Client) Device(name string) (*wgtypes.Device, error) {
	for _, wgc := range c.cs {
		d, err := wgc.Device(name)
		switch {
		case err == nil:
			return d, nil
		case errors.Is(err, os.ErrNotExist):
			continue
		default:
			return nil, err
		}
	}

	return nil, os.ErrNotExist
}

// ConfigureDevice configures a WireGuard device by its interface name.
//
// Because the zero value of some Go types may be significant to WireGuard for
// Config fields, only fields which are not nil will be applied when
// configuring a device.
//
// If the device specified by name does not exist or is not a WireGuard device,
// an error is returned which can be checked using `errors.Is(err, os.ErrNotExist)`.
func (c *Client) ConfigureDevice(name string, cfg wgtypes.Config) error {
	for _, wgc := range c.cs {
		err := wgc.ConfigureDevice(name, cfg)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, os.ErrNotExist):
			continue
		default:
			return err
		}
	}

	return os.ErrNotExist
}
