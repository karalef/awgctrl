package awgctrl

import (
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Device is a WireGuard device.
type Device struct {
	// Name is the name of the device.
	Name string

	// PrivateKey is the device's private key.
	PrivateKey Key

	// PublicKey is the device's public key, computed from its PrivateKey.
	PublicKey Key

	// ListenPort is the device's network listening port.
	ListenPort uint16

	// FirewallMark is the device's current firewall mark.
	//
	// The firewall mark can be used in conjunction with firewall software to
	// take action on outgoing WireGuard packets.
	FirewallMark uint32

	// JunkCount sets the number of junk packets.
	JunkCount uint16

	// JunkMin and JunkMax specify the minimum and maximum size of junk packets.
	JunkMin, JunkMax uint16

	S1, S2 uint16

	H1, H2, H3, H4 uint32

	// Peers is the list of network peers associated with this device.
	Peers []Peer
}

// parseDevice parses a Device from a slice of generic netlink messages,
// automatically merging peer lists from subsequent messages into the Device
// from the first message.
func parseDevice(msgs []genetlink.Message) (*Device, error) {
	var first Device
	knownPeers := make(map[Key]int)

	for i, m := range msgs {
		d, err := parseDeviceLoop(m)
		if err != nil {
			return nil, err
		}

		if i == 0 {
			// First message contains our target device.
			first = *d

			// Gather the known peers so that we can merge
			// them later if needed
			for i := range first.Peers {
				knownPeers[first.Peers[i].PublicKey] = i
			}

			continue
		}

		// Any subsequent messages have their peer contents merged into the
		// first "target" message.
		mergeDevices(&first, d, knownPeers)
	}

	return &first, nil
}

// mergeDevices merges Peer information from d into target.  mergeDevices is
// used to deal with multiple incoming netlink messages for the same device.
func mergeDevices(target, d *Device, knownPeers map[Key]int) {
	for i := range d.Peers {
		// Peer is already known, append to it's allowed IP networks
		if peerIndex, ok := knownPeers[d.Peers[i].PublicKey]; ok {
			target.Peers[peerIndex].AllowedIPs = append(target.Peers[peerIndex].AllowedIPs, d.Peers[i].AllowedIPs...)
		} else { // New peer, add it to the target peers.
			target.Peers = append(target.Peers, d.Peers[i])
			knownPeers[d.Peers[i].PublicKey] = len(target.Peers) - 1
		}
	}
}

// Decode decodes a Device from a single generic netlink message under the
// attribute decoder.
func (d *Device) Decode(ad *netlink.AttributeDecoder) {
	for ad.Next() {
		switch ad.Type() {
		case unix.WGDEVICE_A_IFINDEX:
			// Ignored; interface index isn't exposed at all in the userspace
			// configuration protocol, and name is more friendly anyway.
		case unix.WGDEVICE_A_IFNAME:
			d.Name = ad.String()
		case unix.WGDEVICE_A_PRIVATE_KEY:
			ad.Do(d.PrivateKey.Decode)
		case unix.WGDEVICE_A_PUBLIC_KEY:
			ad.Do(d.PublicKey.Decode)
		case unix.WGDEVICE_A_LISTEN_PORT:
			d.ListenPort = ad.Uint16()
		case unix.WGDEVICE_A_FWMARK:
			d.FirewallMark = ad.Uint32()

			// amneziawg
		case WGDEVICE_A_JC:
			d.JunkCount = ad.Uint16()
		case WGDEVICE_A_JMIN:
			d.JunkMin = ad.Uint16()
		case WGDEVICE_A_JMAX:
			d.JunkMax = ad.Uint16()
		case WGDEVICE_A_S1:
			d.S1 = ad.Uint16()
		case WGDEVICE_A_S2:
			d.S2 = ad.Uint16()
		case WGDEVICE_A_H1:
			d.H1 = ad.Uint32()
		case WGDEVICE_A_H2:
			d.H2 = ad.Uint32()
		case WGDEVICE_A_H3:
			d.H3 = ad.Uint32()
		case WGDEVICE_A_H4:
			d.H4 = ad.Uint32()

		case unix.WGDEVICE_A_PEERS:
			// Netlink array of peers.
			//
			// Errors while parsing are propagated up to top-level ad.Err check.
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				// Initialize to the number of peers in this decoder and begin
				// handling nested Peer attributes.
				d.Peers = make([]Peer, nad.Len())
				for i := 0; nad.Next(); i++ {
					nad.Nested(func(nnad *netlink.AttributeDecoder) error {
						d.Peers[i].Decode(nnad)
						return nil
					})
				}

				return nil
			})
		}
	}
}

// parseDeviceLoop parses a Device from a single generic netlink message.
func parseDeviceLoop(m genetlink.Message) (*Device, error) {
	ad, err := netlink.NewAttributeDecoder(m.Data)
	if err != nil {
		return nil, err
	}

	d := new(Device)
	d.Decode(ad)

	if err = ad.Err(); err != nil {
		return nil, err
	}

	return d, nil
}
