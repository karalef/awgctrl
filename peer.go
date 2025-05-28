package awgctrl

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

// A Peer is a WireGuard peer to a Device.
type Peer struct {
	// PublicKey is the public key of a peer, computed from its private key.
	//
	// PublicKey is always present in a Peer.
	PublicKey Key

	// PresharedKey is an optional preshared key which may be used as an
	// additional layer of security for peer communications.
	//
	// A zero-value Key means no preshared key is configured.
	PresharedKey Key

	// Endpoint is the most recent source address used for communication by
	// this Peer.
	Endpoint *net.UDPAddr

	// PersistentKeepaliveInterval specifies how often an "empty" packet is sent
	// to a peer to keep a connection alive.
	//
	// A value of 0 indicates that persistent keepalives are disabled.
	PersistentKeepaliveInterval time.Duration

	// LastHandshakeTime indicates the most recent time a handshake was performed
	// with this peer.
	//
	// A zero-value time.Time indicates that no handshake has taken place with
	// this peer.
	LastHandshakeTime time.Time

	// ReceiveBytes indicates the number of bytes received from this peer.
	ReceiveBytes int64

	// TransmitBytes indicates the number of bytes transmitted to this peer.
	TransmitBytes int64

	// AllowedIPs specifies which IPv4 and IPv6 addresses this peer is allowed
	// to communicate on.
	//
	// 0.0.0.0/0 indicates that all IPv4 addresses are allowed, and ::/0
	// indicates that all IPv6 addresses are allowed.
	AllowedIPs []net.IPNet

	// ProtocolVersion specifies which version of the WireGuard protocol is used
	// for this Peer.
	//
	// A value of 0 indicates that the most recent protocol version will be used.
	ProtocolVersion int
}

// Decode decodes a Peer from a netlink attribute payload.
func (p *Peer) Decode(ad *netlink.AttributeDecoder) {
	for ad.Next() {
		switch ad.Type() {
		case unix.WGPEER_A_PUBLIC_KEY:
			ad.Do(p.PublicKey.Decode)
		case unix.WGPEER_A_PRESHARED_KEY:
			ad.Do(p.PresharedKey.Decode)
		case unix.WGPEER_A_ENDPOINT:
			p.Endpoint = &net.UDPAddr{}
			ad.Do(parseSockaddr(p.Endpoint))
		case unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL:
			p.PersistentKeepaliveInterval = time.Duration(ad.Uint16()) * time.Second
		case unix.WGPEER_A_LAST_HANDSHAKE_TIME:
			ad.Do(parseTimespec(&p.LastHandshakeTime))
		case unix.WGPEER_A_RX_BYTES:
			p.ReceiveBytes = int64(ad.Uint64())
		case unix.WGPEER_A_TX_BYTES:
			p.TransmitBytes = int64(ad.Uint64())
		case unix.WGPEER_A_ALLOWEDIPS:
			ad.Nested(parseAllowedIPs(&p.AllowedIPs))
		case unix.WGPEER_A_PROTOCOL_VERSION:
			p.ProtocolVersion = int(ad.Uint32())
		}
	}
}

// A PeerConfig is a WireGuard device peer configuration.
//
// Because the zero value of some Go types may be significant to WireGuard for
// PeerConfig fields, pointer types are used for some of these fields. Only
// pointer fields which are not nil will be applied when configuring a peer.
type PeerConfig struct {
	// PublicKey specifies the public key of this peer.  PublicKey is a
	// mandatory field for all PeerConfigs.
	PublicKey Key

	// Remove specifies if the peer with this public key should be removed
	// from a device's peer list.
	Remove bool

	// UpdateOnly specifies that an operation will only occur on this peer
	// if the peer already exists as part of the interface.
	UpdateOnly bool

	// PresharedKey specifies a peer's preshared key configuration, if not nil.
	//
	// A non-nil, zero-value Key will clear the preshared key.
	PresharedKey *Key

	// Endpoint specifies the endpoint of this peer entry, if not nil.
	Endpoint *net.UDPAddr

	// PersistentKeepaliveInterval specifies the persistent keepalive interval
	// for this peer, if not nil.
	//
	// A non-nil value of 0 will clear the persistent keepalive interval.
	PersistentKeepaliveInterval *time.Duration

	// ReplaceAllowedIPs specifies if the allowed IPs specified in this peer
	// configuration should replace any existing ones, instead of appending them
	// to the allowed IPs list.
	ReplaceAllowedIPs bool

	// AllowedIPs specifies a list of allowed IP addresses in CIDR notation
	// for this peer.
	AllowedIPs []net.IPNet
}

// Encode encodes the PeerConfig into a netlink format.
func (p PeerConfig) Encode(ae *netlink.AttributeEncoder) error {
	ae.Bytes(unix.WGPEER_A_PUBLIC_KEY, p.PublicKey[:])

	// Flags are stored in a single attribute.
	var flags uint32
	if p.Remove {
		flags |= unix.WGPEER_F_REMOVE_ME
	}
	if p.ReplaceAllowedIPs {
		flags |= unix.WGPEER_F_REPLACE_ALLOWEDIPS
	}
	if p.UpdateOnly {
		flags |= unix.WGPEER_F_UPDATE_ONLY
	}
	if flags != 0 {
		ae.Uint32(unix.WGPEER_A_FLAGS, flags)
	}

	if p.PresharedKey != nil {
		ae.Bytes(unix.WGPEER_A_PRESHARED_KEY, (*p.PresharedKey)[:])
	}

	if p.Endpoint != nil {
		ae.Do(unix.WGPEER_A_ENDPOINT, encodeSockaddr(*p.Endpoint))
	}

	if p.PersistentKeepaliveInterval != nil {
		ae.Uint16(unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, uint16(p.PersistentKeepaliveInterval.Seconds()))
	}

	// Only apply allowed IPs if necessary.
	if len(p.AllowedIPs) > 0 {
		ae.Nested(unix.WGPEER_A_ALLOWEDIPS, encodeAllowedIPs(p.AllowedIPs))
	}

	return nil
}

// encodeSockaddr returns a function which encodes a net.UDPAddr as raw
// sockaddr_in or sockaddr_in6 bytes.
func encodeSockaddr(endpoint net.UDPAddr) func() ([]byte, error) {
	return func() ([]byte, error) {
		if !isValidIP(endpoint.IP) {
			return nil, fmt.Errorf("wglinux: invalid endpoint IP: %s", endpoint.IP.String())
		}

		// Is this an IPv6 address?
		if isIPv6(endpoint.IP) {
			var addr [16]byte
			copy(addr[:], endpoint.IP.To16())

			sa := unix.RawSockaddrInet6{
				Family: unix.AF_INET6,
				Port:   sockaddrPort(endpoint.Port),
				Addr:   addr,
			}

			return (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&sa)))[:], nil
		}

		// IPv4 address handling.
		var addr [4]byte
		copy(addr[:], endpoint.IP.To4())

		sa := unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Port:   sockaddrPort(endpoint.Port),
			Addr:   addr,
		}

		return (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&sa)))[:], nil
	}
}

// encodeAllowedIPs returns a function to encode allowed IP nested attributes.
func encodeAllowedIPs(ipns []net.IPNet) func(ae *netlink.AttributeEncoder) error {
	return func(ae *netlink.AttributeEncoder) error {
		for i, ipn := range ipns {
			if !isValidIP(ipn.IP) {
				return fmt.Errorf("wglinux: invalid allowed IP: %s", ipn.IP.String())
			}

			family := uint16(unix.AF_INET6)
			if !isIPv6(ipn.IP) {
				// Make sure address is 4 bytes if IPv4.
				family = unix.AF_INET
				ipn.IP = ipn.IP.To4()
			}

			// Netlink arrays use type as an array index.
			ae.Nested(uint16(i), func(nae *netlink.AttributeEncoder) error {
				nae.Uint16(unix.WGALLOWEDIP_A_FAMILY, family)
				nae.Bytes(unix.WGALLOWEDIP_A_IPADDR, ipn.IP)

				ones, _ := ipn.Mask.Size()
				nae.Uint8(unix.WGALLOWEDIP_A_CIDR_MASK, uint8(ones))
				return nil
			})
		}

		return nil
	}
}

// isValidIP determines if IP is a valid IPv4 or IPv6 address.
func isValidIP(ip net.IP) bool {
	return ip.To16() != nil
}

// isIPv6 determines if IP is a valid IPv6 address.
func isIPv6(ip net.IP) bool {
	return isValidIP(ip) && ip.To4() == nil
}

// parseAllowedIPs parses a slice of net.IPNet from a netlink attribute payload.
func parseAllowedIPs(ipns *[]net.IPNet) func(ad *netlink.AttributeDecoder) error {
	return func(ad *netlink.AttributeDecoder) error {
		// Initialize to the number of allowed IPs and begin iterating through
		// the netlink array to decode each one.
		*ipns = make([]net.IPNet, 0, ad.Len())
		for ad.Next() {
			// Allowed IP nested attributes.
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				var (
					ipn    net.IPNet
					mask   int
					family int
				)

				for nad.Next() {
					switch nad.Type() {
					case unix.WGALLOWEDIP_A_IPADDR:
						nad.Do(parseAddr(&ipn.IP))
					case unix.WGALLOWEDIP_A_CIDR_MASK:
						mask = int(nad.Uint8())
					case unix.WGALLOWEDIP_A_FAMILY:
						family = int(nad.Uint16())
					}
				}

				if err := nad.Err(); err != nil {
					return err
				}

				// The address family determines the correct number of bits in
				// the mask.
				switch family {
				case unix.AF_INET:
					ipn.Mask = net.CIDRMask(mask, 32)
				case unix.AF_INET6:
					ipn.Mask = net.CIDRMask(mask, 128)
				}

				*ipns = append(*ipns, ipn)
				return nil
			})
		}

		return nil
	}
}

// parseAddr parses a net.IP from raw in_addr or in6_addr struct bytes.
func parseAddr(ip *net.IP) func(b []byte) error {
	return func(b []byte) error {
		switch len(b) {
		case net.IPv4len, net.IPv6len:
			// Okay to convert directly to net.IP; memory layout is identical.
			*ip = make(net.IP, len(b))
			copy(*ip, b)
			return nil
		default:
			return fmt.Errorf("wglinux: unexpected IP address size: %d", len(b))
		}
	}
}

// parseSockaddr parses a *net.UDPAddr from raw sockaddr_in or sockaddr_in6 bytes.
func parseSockaddr(endpoint *net.UDPAddr) func(b []byte) error {
	return func(b []byte) error {
		switch len(b) {
		case unix.SizeofSockaddrInet4:
			// IPv4 address parsing.
			sa := *(*unix.RawSockaddrInet4)(unsafe.Pointer(&b[0]))

			*endpoint = net.UDPAddr{
				IP:   net.IP(sa.Addr[:]).To4(),
				Port: int(sockaddrPort(int(sa.Port))),
			}

			return nil
		case unix.SizeofSockaddrInet6:
			// IPv6 address parsing.
			sa := *(*unix.RawSockaddrInet6)(unsafe.Pointer(&b[0]))

			*endpoint = net.UDPAddr{
				IP:   net.IP(sa.Addr[:]),
				Port: int(sockaddrPort(int(sa.Port))),
			}

			return nil
		default:
			return fmt.Errorf("wglinux: unexpected sockaddr size: %d", len(b))
		}
	}
}

// sockaddrPort interprets port as a big endian uint16 for use passing sockaddr
// structures to the kernel.
func sockaddrPort(port int) uint16 {
	return binary.BigEndian.Uint16(nlenc.Uint16Bytes(uint16(port)))
}

// timespec32 is a unix.Timespec with 32-bit integers.
type timespec32 struct {
	Sec  int32
	Nsec int32
}

// timespec64 is a unix.Timespec with 64-bit integers.
type timespec64 struct {
	Sec  int64
	Nsec int64
}

const (
	sizeofTimespec32 = int(unsafe.Sizeof(timespec32{}))
	sizeofTimespec64 = int(unsafe.Sizeof(timespec64{}))
)

// parseTimespec parses a time.Time from raw timespec bytes.
func parseTimespec(t *time.Time) func(b []byte) error {
	return func(b []byte) error {
		// It would appear that WireGuard can return a __kernel_timespec which
		// uses 64-bit integers, even on 32-bit platforms. Clarification of this
		// behavior is being sought in:
		// https://lists.zx2c4.com/pipermail/wireguard/2019-April/004088.html.
		//
		// In the mean time, be liberal and accept 32-bit and 64-bit variants.
		var sec, nsec int64

		switch len(b) {
		case sizeofTimespec32:
			ts := *(*timespec32)(unsafe.Pointer(&b[0]))

			sec = int64(ts.Sec)
			nsec = int64(ts.Nsec)
		case sizeofTimespec64:
			ts := *(*timespec64)(unsafe.Pointer(&b[0]))

			sec = ts.Sec
			nsec = ts.Nsec
		default:
			return fmt.Errorf("wglinux: unexpected timespec size: %d bytes, expected 8 or 16 bytes", len(b))
		}

		// Only set fields if UNIX timestamp value is greater than 0, so the
		// caller will see a zero-value time.Time otherwise.
		if sec > 0 || nsec > 0 {
			*t = time.Unix(sec, nsec)
		}

		return nil
	}
}
