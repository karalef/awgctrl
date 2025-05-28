package awgctrl

import (
	"net"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Additional attribute types added in amneziawg.
const (
	WGDEVICE_A_JC   = iota + 1 + unix.WGDEVICE_A_PEERS // uint16
	WGDEVICE_A_JMIN                                    // uint16
	WGDEVICE_A_JMAX                                    // uint16
	WGDEVICE_A_S1                                      // uint16
	WGDEVICE_A_S2                                      // uint16
	WGDEVICE_A_H1                                      // uint32
	WGDEVICE_A_H2                                      // uint32
	WGDEVICE_A_H3                                      // uint32
	WGDEVICE_A_H4                                      // uint32
)

// A Config is a WireGuard device configuration.
//
// Because the zero value of some Go types may be significant to WireGuard for
// Config fields, pointer types are used for some of these fields. Only
// pointer fields which are not nil will be applied when configuring a device.
type Config struct {
	// PrivateKey specifies a private key configuration, if not nil.
	//
	// A non-nil, zero-value Key will clear the private key.
	PrivateKey *Key

	// ListenPort specifies a device's listening port, if not nil.
	ListenPort *uint16

	// FirewallMark specifies a device's firewall mark, if not nil.
	//
	// If non-nil and set to 0, the firewall mark will be cleared.
	FirewallMark *uint32

	// JunkCount sets the number of junk packets.
	JunkCount *uint16

	// JunkMin specifies the minimum size of junk packets.
	JunkMin *uint16

	// JunkMax specifies the maximum size of junk packets.
	JunkMax *uint16

	S1, S2 *uint16

	H1, H2, H3, H4 *uint32

	// ReplacePeers specifies if the Peers in this configuration should replace
	// the existing peer list, instead of appending them to the existing list.
	ReplacePeers bool

	// Peers specifies a list of peer configurations to apply to a device.
	Peers []PeerConfig
}

// ipBatchChunk is a tunable allowed IP batch limit per peer.
//
// Because we don't necessarily know how much space a given peer will occupy,
// we play it safe and use a reasonably small value.  Note that this constant
// is used both in this package and tests, so be aware when making changes.
const ipBatchChunk = 256

// peerBatchChunk specifies the number of peers that can appear in a
// configuration before we start splitting it into chunks.
const peerBatchChunk = 32

// shouldBatch determines if a configuration is sufficiently complex that it
// should be split into batches.
func (cfg Config) shouldBatch() bool {
	if len(cfg.Peers) > peerBatchChunk {
		return true
	}

	var ips int
	for _, p := range cfg.Peers {
		ips += len(p.AllowedIPs)
	}

	return ips > ipBatchChunk
}

// buildBatches produces a batch of configs from a single config, if needed.
func (cfg Config) buildBatches() []Config {
	// Is this a small configuration; no need to batch?
	if !cfg.shouldBatch() {
		return []Config{cfg}
	}

	// Use most fields of cfg for our "base" configuration, and only differ
	// peers in each batch.
	base := cfg
	base.Peers = nil

	// Track the known peers so that peer IPs are not replaced if a single
	// peer has its allowed IPs split into multiple batches.
	knownPeers := make(map[Key]struct{})

	batches := make([]Config, 0)
	for _, p := range cfg.Peers {
		batch := base

		// Iterate until no more allowed IPs.
		var done bool
		for !done {
			var tmp []net.IPNet
			if len(p.AllowedIPs) < ipBatchChunk {
				// IPs all fit within a batch; we are done.
				tmp = make([]net.IPNet, len(p.AllowedIPs))
				copy(tmp, p.AllowedIPs)
				done = true
			} else {
				// IPs are larger than a single batch, copy a batch out and
				// advance the cursor.
				tmp = make([]net.IPNet, ipBatchChunk)
				copy(tmp, p.AllowedIPs[:ipBatchChunk])

				p.AllowedIPs = p.AllowedIPs[ipBatchChunk:]

				if len(p.AllowedIPs) == 0 {
					// IPs ended on a batch boundary; no more IPs left so end
					// iteration after this loop.
					done = true
				}
			}

			pcfg := PeerConfig{
				// PublicKey denotes the peer and must be present.
				PublicKey: p.PublicKey,

				// Apply the update only flag to every chunk to ensure
				// consistency between batches when the kernel module processes
				// them.
				UpdateOnly: p.UpdateOnly,

				// It'd be a bit weird to have a remove peer message with many
				// IPs, but just in case, add this to every peer's message.
				Remove: p.Remove,

				// The IPs for this chunk.
				AllowedIPs: tmp,
			}

			// Only pass certain fields on the first occurrence of a peer, so
			// that subsequent IPs won't be wiped out and space isn't wasted.
			if _, ok := knownPeers[p.PublicKey]; !ok {
				knownPeers[p.PublicKey] = struct{}{}

				pcfg.PresharedKey = p.PresharedKey
				pcfg.Endpoint = p.Endpoint
				pcfg.PersistentKeepaliveInterval = p.PersistentKeepaliveInterval

				// Important: do not move or appending peers won't work.
				pcfg.ReplaceAllowedIPs = p.ReplaceAllowedIPs
			}

			// Add a peer configuration to this batch and keep going.
			batch.Peers = []PeerConfig{pcfg}
			batches = append(batches, batch)
		}
	}

	// Do not allow peer replacement beyond the first message in a batch,
	// so we don't overwrite our previous batch work.
	for i := range batches {
		if i > 0 {
			batches[i].ReplacePeers = false
		}
	}

	return batches
}

// configAttrs creates the required encoded netlink attributes to configure
// the device specified by name using the non-nil fields in cfg.
func (cfg Config) attrs(name string) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.WGDEVICE_A_IFNAME, name)

	if cfg.PrivateKey != nil {
		ae.Bytes(unix.WGDEVICE_A_PRIVATE_KEY, cfg.PrivateKey[:])
	}
	eUint16(ae, unix.WGDEVICE_A_LISTEN_PORT, cfg.ListenPort)
	eUint32(ae, unix.WGDEVICE_A_FWMARK, cfg.FirewallMark)

	// amneziawg
	eUint16(ae, WGDEVICE_A_JC, cfg.JunkCount)
	eUint16(ae, WGDEVICE_A_JMIN, cfg.JunkMin)
	eUint16(ae, WGDEVICE_A_JMAX, cfg.JunkMax)
	eUint16(ae, WGDEVICE_A_S1, cfg.S1)
	eUint16(ae, WGDEVICE_A_S2, cfg.S2)
	eUint32(ae, WGDEVICE_A_H1, cfg.H1)
	eUint32(ae, WGDEVICE_A_H2, cfg.H2)
	eUint32(ae, WGDEVICE_A_H3, cfg.H3)
	eUint32(ae, WGDEVICE_A_H4, cfg.H4)

	if cfg.ReplacePeers {
		ae.Uint32(unix.WGDEVICE_A_FLAGS, unix.WGDEVICE_F_REPLACE_PEERS)
	}

	// Only apply peer attributes if necessary.
	if len(cfg.Peers) > 0 {
		ae.Nested(unix.WGDEVICE_A_PEERS, func(nae *netlink.AttributeEncoder) error {
			// Netlink arrays use type as an array index.
			for i, p := range cfg.Peers {
				nae.Nested(uint16(i), p.Encode)
			}

			return nil
		})
	}

	return ae.Encode()
}

func eUint16(ae *netlink.AttributeEncoder, typ uint16, v *uint16) {
	if v != nil {
		ae.Uint16(typ, *v)
	}
}

func eUint32(ae *netlink.AttributeEncoder, typ uint16, v *uint32) {
	if v != nil {
		ae.Uint32(typ, *v)
	}
}
