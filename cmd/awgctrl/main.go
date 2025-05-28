//go:build linux
// +build linux

// Command awgctrl is a testing utility for interacting with amneziawg via package
// awgctrl.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/karalef/awgctrl"
)

func main() {
	flag.Parse()

	c, _, err := awgctrl.New()
	if err != nil {
		log.Fatalf("failed to open awgctrl: %v", err)
	}
	defer c.Close()

	var devices []*awgctrl.Device
	if device := flag.Arg(0); device != "" {
		d, err := c.Device(device)
		if err != nil {
			log.Fatalf("failed to get device %q: %v", device, err)
		}

		devices = append(devices, d)
	} else {
		devices, err = c.Devices()
		if err != nil {
			log.Fatalf("failed to get devices: %v", err)
		}
	}

	for _, d := range devices {
		printDevice(d)

		for _, p := range d.Peers {
			printPeer(p)
		}
	}
}

func printDevice(d *awgctrl.Device) {
	const f = `interface: %s (%s)
  public key: %s
  private key: (hidden)
  listening port: %d

`

	fmt.Printf(
		f,
		d.Name,
		d.PublicKey.String(),
		d.ListenPort)
}

func printPeer(p awgctrl.Peer) {
	const f = `peer: %s
  endpoint: %s
  allowed ips: %s
  latest handshake: %s
  transfer: %d B received, %d B sent

`

	fmt.Printf(
		f,
		p.PublicKey.String(),
		// TODO(mdlayher): get right endpoint with getnameinfo.
		p.Endpoint.String(),
		ipsString(p.AllowedIPs),
		p.LastHandshakeTime.String(),
		p.ReceiveBytes,
		p.TransmitBytes,
	)
}

func ipsString(ipns []net.IPNet) string {
	ss := make([]string, 0, len(ipns))
	for _, ipn := range ipns {
		ss = append(ss, ipn.String())
	}

	return strings.Join(ss, ", ")
}
