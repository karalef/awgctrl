//go:build linux
// +build linux

package awgctrl

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/genetlink/genltest"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/mdlayher/netlink/nltest"
	"github.com/mikioh/ipaddr"
	"golang.org/x/sys/unix"
)

const (
	okIndex = 1
	okName  = "wg0"
)

func TestLinuxClientDevicesEmpty(t *testing.T) {
	tests := []struct {
		name string
		fn   func() ([]string, error)
	}{
		{
			name: "no interfaces",
			fn: func() ([]string, error) {
				return nil, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
				panic("no devices; shouldn't call genetlink")
			})
			defer c.Close()

			c.interfaces = tt.fn

			ds, err := c.Devices()
			if err != nil {
				t.Fatalf("failed to get devices: %v", err)
			}

			if diff := cmp.Diff(0, len(ds)); diff != "" {
				t.Fatalf("unexpected number of devices (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLinuxClientIsNotExist(t *testing.T) {
	// TODO(mdlayher): not ideal but this test is not particularly load-bearing
	// and the entire *nltest ecosystem needs to be reworked.
	t.Skipf("skipping, genltest needs to be reworked")

	device := func(c *Client) error {
		_, err := c.Device("wg0")
		return err
	}

	configure := func(c *Client) error {
		return c.ConfigureDevice("wg0", Config{})
	}

	tests := []struct {
		name  string
		fn    func(c *Client) error
		msgs  []genetlink.Message
		errno unix.Errno
	}{
		{
			name: "name: empty",
			fn: func(c *Client) error {
				_, err := c.Device("")
				return err
			},
		},
		{
			name:  "name: ENODEV",
			fn:    device,
			errno: unix.ENODEV,
		},
		{
			name:  "name: ENOTSUP",
			fn:    device,
			errno: unix.ENOTSUP,
		},
		{
			name:  "configure: ENODEV",
			fn:    configure,
			errno: unix.ENODEV,
		},
		{
			name:  "configure: ENOTSUP",
			fn:    configure,
			errno: unix.ENOTSUP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
				// We aren't creating a system call error; we are creating a
				// netlink error inside a message.
				return tt.msgs, genltest.Error(int(tt.errno))
			})
			defer c.Close()

			if err := tt.fn(c); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected is not exist, but got: %v", err)
			}
		})
	}
}

func TestLinuxClientIsPermission(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Fatalf("failed to get current user: %v", err)
	}
	if u.Uid == "0" {
		t.Skip("skipping, test must be run without elevated privileges")
	}

	c, ok, err := New()
	if err != nil {
		t.Fatalf("failed to create Client: %v", err)
	}
	if !ok {
		t.Skip("skipping, the WireGuard generic netlink API is not available")
	}

	defer c.Close()

	// Check for permission denied as unprivileged user.
	if _, err := c.Device("wgnotexist0"); !os.IsPermission(err) {
		t.Fatalf("expected permission denied, but got: %v", err)
	}
}

func Test_initClientNotExist(t *testing.T) {
	conn := genltest.Dial(func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		// Simulate genetlink family not found.
		return nil, genltest.Error(int(unix.ENOENT))
	})

	_, ok, err := initClient(conn)
	if err != nil {
		t.Fatalf("failed to open Client: %v", err)
	}
	if ok {
		t.Fatal("the generic netlink API should not be available from genltest")
	}
}

func Test_parseRTNLInterfaces(t *testing.T) {
	// marshalAttrs creates packed netlink attributes with a prepended ifinfomsg
	// structure, as returned by rtnetlink.
	marshalAttrs := func(attrs []netlink.Attribute) []byte {
		ifinfomsg := make([]byte, syscall.SizeofIfInfomsg)

		return append(ifinfomsg, nltest.MustMarshalAttributes(attrs)...)
	}

	tests := []struct {
		name string
		msgs []syscall.NetlinkMessage
		ifis []string
		ok   bool
	}{
		{
			name: "short ifinfomsg",
			msgs: []syscall.NetlinkMessage{{
				Header: syscall.NlMsghdr{
					Type: unix.RTM_NEWLINK,
				},
				Data: []byte{0xff},
			}},
		},
		{
			name: "empty",
			ok:   true,
		},
		{
			name: "immediate done",
			msgs: []syscall.NetlinkMessage{{
				Header: syscall.NlMsghdr{
					Type: unix.NLMSG_DONE,
				},
			}},
			ok: true,
		},
		{
			name: "ok",
			msgs: []syscall.NetlinkMessage{
				// Bridge device.
				{
					Header: syscall.NlMsghdr{
						Type: unix.RTM_NEWLINK,
					},
					Data: marshalAttrs([]netlink.Attribute{
						{
							Type: unix.IFLA_IFNAME,
							Data: nlenc.Bytes("br0"),
						},
						{
							Type: unix.IFLA_LINKINFO,
							Data: m(netlink.Attribute{
								Type: unix.IFLA_INFO_KIND,
								Data: nlenc.Bytes("bridge"),
							}),
						},
					}),
				},
				// WireGuard device.
				{
					Header: syscall.NlMsghdr{
						Type: unix.RTM_NEWLINK,
					},
					Data: marshalAttrs([]netlink.Attribute{
						{
							Type: unix.IFLA_IFNAME,
							Data: nlenc.Bytes(okName),
						},
						{
							Type: unix.IFLA_LINKINFO,
							Data: m([]netlink.Attribute{
								// Random junk to skip.
								{
									Type: 255,
									Data: nlenc.Uint16Bytes(0xff),
								},
								{
									Type: unix.IFLA_INFO_KIND,
									Data: nlenc.Bytes(wgKind),
								},
							}...),
						},
					}),
				},
			},
			ifis: []string{okName},
			ok:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ifis, err := parseRTNLInterfaces(tt.msgs)

			if tt.ok && err != nil {
				t.Fatalf("failed to parse interfaces: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, but none occurred")
			}
			if err != nil {
				return
			}

			if diff := cmp.Diff(tt.ifis, ifis); diff != "" {
				t.Fatalf("unexpected interfaces (-want +got):\n%s", diff)
			}
		})
	}
}

const familyID = 20

func testClient(t *testing.T, fn genltest.Func) *Client {
	family := genetlink.Family{
		ID:      familyID,
		Version: unix.WG_GENL_VERSION,
		Name:    unix.WG_GENL_NAME,
	}

	conn := genltest.Dial(genltest.ServeFamily(family, fn))

	c, ok, err := initClient(conn)
	if err != nil {
		t.Fatalf("failed to open Client: %v", err)
	}
	if !ok {
		t.Fatal("the generic netlink API was not available from genltest")
	}

	c.interfaces = func() ([]string, error) {
		return []string{okName}, nil
	}

	return c
}

func diffAttrs(x, y []netlink.Attribute) string {
	// Make copies to avoid a race and then zero out length values
	// for comparison.
	xPrime := make([]netlink.Attribute, len(x))
	copy(xPrime, x)

	for i := 0; i < len(xPrime); i++ {
		xPrime[i].Length = 0
	}

	yPrime := make([]netlink.Attribute, len(y))
	copy(yPrime, y)

	for i := 0; i < len(yPrime); i++ {
		yPrime[i].Length = 0
	}

	return cmp.Diff(xPrime, yPrime)
}

func TestLinuxClientDevicesError(t *testing.T) {
	tests := []struct {
		name string
		msgs []genetlink.Message
	}{
		{
			name: "bad peer endpoint",
			msgs: []genetlink.Message{{
				Data: m(netlink.Attribute{
					Type: unix.WGDEVICE_A_PEERS,
					Data: m(netlink.Attribute{
						Type: 0,
						Data: m(netlink.Attribute{
							Type: unix.WGPEER_A_ENDPOINT,
							Data: []byte{0xff},
						}),
					}),
				}),
			}},
		},
		{
			name: "bad peer last handshake time",
			msgs: []genetlink.Message{{
				Data: m(netlink.Attribute{
					Type: unix.WGDEVICE_A_PEERS,
					Data: m(netlink.Attribute{
						Type: 0,
						Data: m(netlink.Attribute{
							Type: unix.WGPEER_A_LAST_HANDSHAKE_TIME,
							Data: []byte{0xff},
						}),
					}),
				}),
			}},
		},
		{
			name: "bad peer allowed IPs IP",
			msgs: []genetlink.Message{{
				Data: m(netlink.Attribute{
					Type: unix.WGDEVICE_A_PEERS,
					Data: m(netlink.Attribute{
						Type: 0,
						Data: m(netlink.Attribute{
							Type: unix.WGPEER_A_ALLOWEDIPS,
							Data: m(netlink.Attribute{
								Type: 0,
								Data: m(netlink.Attribute{
									Type: unix.WGALLOWEDIP_A_IPADDR,
									Data: []byte{0xff},
								}),
							}),
						}),
					}),
				}),
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
				return tt.msgs, nil
			})
			defer c.Close()

			c.interfaces = func() ([]string, error) {
				return []string{okName}, nil
			}

			if _, err := c.Devices(); err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

func TestLinuxClientDevicesOK(t *testing.T) {
	const (
		testIndex = 2
		testName  = "wg1"
	)

	var (
		testKey Key
		keyA    = GeneratePrivateKey().PublicKey()
		keyB    = GeneratePrivateKey().PublicKey()
		keyC    = GeneratePrivateKey().PublicKey()
	)

	testKey[0] = 0xff

	tests := []struct {
		name       string
		interfaces func() ([]string, error)
		msgs       [][]genetlink.Message
		devices    []*Device
	}{
		{
			name: "basic",
			interfaces: func() ([]string, error) {
				return []string{okName, "wg1"}, nil
			},
			msgs: [][]genetlink.Message{
				{{
					Data: m([]netlink.Attribute{
						{
							Type: unix.WGDEVICE_A_IFINDEX,
							Data: nlenc.Uint32Bytes(okIndex),
						},
						{
							Type: unix.WGDEVICE_A_IFNAME,
							Data: nlenc.Bytes(okName),
						},
					}...),
				}},
				{{
					Data: m([]netlink.Attribute{
						{
							Type: unix.WGDEVICE_A_IFINDEX,
							Data: nlenc.Uint32Bytes(testIndex),
						},
						{
							Type: unix.WGDEVICE_A_IFNAME,
							Data: nlenc.Bytes(testName),
						},
					}...),
				}},
			},
			devices: []*Device{
				{
					Name: okName,
				},
				{
					Name: "wg1",
				},
			},
		},
		{
			name: "complete",
			msgs: [][]genetlink.Message{{{
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGDEVICE_A_IFINDEX,
						Data: nlenc.Uint32Bytes(okIndex),
					},
					{
						Type: unix.WGDEVICE_A_IFNAME,
						Data: nlenc.Bytes(okName),
					},
					{
						Type: unix.WGDEVICE_A_PRIVATE_KEY,
						Data: testKey[:],
					},
					{
						Type: unix.WGDEVICE_A_PUBLIC_KEY,
						Data: testKey[:],
					},
					{
						Type: unix.WGDEVICE_A_LISTEN_PORT,
						Data: nlenc.Uint16Bytes(5555),
					},
					{
						Type: unix.WGDEVICE_A_FWMARK,
						Data: nlenc.Uint32Bytes(0xff),
					},
					{
						Type: unix.WGDEVICE_A_PEERS,
						Data: m([]netlink.Attribute{
							{
								Type: 0,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: testKey[:],
									},
									{
										Type: unix.WGPEER_A_PRESHARED_KEY,
										Data: testKey[:],
									},
									{
										Type: unix.WGPEER_A_ENDPOINT,
										Data: (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&unix.RawSockaddrInet4{
											Addr: [4]byte{192, 168, 1, 1},
											Port: sockaddrPort(1111),
										})))[:],
									},
									{
										Type: unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
										Data: nlenc.Uint16Bytes(10),
									},
									{
										Type: unix.WGPEER_A_LAST_HANDSHAKE_TIME,
										Data: (*(*[sizeofTimespec64]byte)(unsafe.Pointer(&timespec64{
											Sec:  10,
											Nsec: 20,
										})))[:],
									},
									{
										Type: unix.WGPEER_A_RX_BYTES,
										Data: nlenc.Uint64Bytes(100),
									},
									{
										Type: unix.WGPEER_A_TX_BYTES,
										Data: nlenc.Uint64Bytes(200),
									},
									{
										Type: unix.WGPEER_A_ALLOWEDIPS,
										Data: mustAllowedIPs([]net.IPNet{
											mustCIDR("192.168.1.10/32"),
											mustCIDR("fd00::1/128"),
										}),
									},
									{
										Type: unix.WGPEER_A_PROTOCOL_VERSION,
										Data: nlenc.Uint32Bytes(1),
									},
								}...),
							},
							// "dummy" peer with only some necessary fields.
							{
								Type: 1,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: testKey[:],
									},
									{
										Type: unix.WGPEER_A_ENDPOINT,
										Data: (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&unix.RawSockaddrInet6{
											Addr: [16]byte{
												0xfe, 0x80, 0x00, 0x00,
												0x00, 0x00, 0x00, 0x00,
												0x00, 0x00, 0x00, 0x00,
												0x00, 0x00, 0x00, 0x01,
											},
											Port: sockaddrPort(2222),
										})))[:],
									},
								}...),
							},
						}...),
					},
				}...),
			}}},
			devices: []*Device{
				{
					Name:         okName,
					PrivateKey:   testKey,
					PublicKey:    testKey,
					ListenPort:   5555,
					FirewallMark: 0xff,
					Peers: []Peer{
						{
							PublicKey:    testKey,
							PresharedKey: testKey,
							Endpoint: &net.UDPAddr{
								IP:   net.IPv4(192, 168, 1, 1),
								Port: 1111,
							},
							PersistentKeepaliveInterval: 10 * time.Second,
							LastHandshakeTime:           time.Unix(10, 20),
							ReceiveBytes:                100,
							TransmitBytes:               200,
							AllowedIPs: []net.IPNet{
								mustCIDR("192.168.1.10/32"),
								mustCIDR("fd00::1/128"),
							},
							ProtocolVersion: 1,
						},
						{
							PublicKey: testKey,
							Endpoint: &net.UDPAddr{
								IP:   net.ParseIP("fe80::1"),
								Port: 2222,
							},
						},
					},
				},
			},
		},
		{
			name: "merge devices",
			msgs: [][]genetlink.Message{{
				// The "target" device.
				{
					Data: m([]netlink.Attribute{
						{
							Type: unix.WGDEVICE_A_IFNAME,
							Data: nlenc.Bytes(okName),
						},
						{
							Type: unix.WGDEVICE_A_PRIVATE_KEY,
							Data: testKey[:],
						},
						{
							Type: unix.WGDEVICE_A_PEERS,
							Data: m(netlink.Attribute{
								Type: 0,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: keyA[:],
									},
									{
										Type: unix.WGPEER_A_ALLOWEDIPS,
										Data: mustAllowedIPs([]net.IPNet{
											mustCIDR("192.168.1.10/32"),
											mustCIDR("192.168.1.11/32"),
										}),
									},
								}...),
							}),
						},
					}...),
				},
				// Continuation of first peer list, new peer list.
				{
					Data: m(netlink.Attribute{
						Type: unix.WGDEVICE_A_PEERS,
						Data: m([]netlink.Attribute{
							{
								Type: 0,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: keyA[:],
									},
									{
										Type: unix.WGPEER_A_ALLOWEDIPS,
										Data: mustAllowedIPs([]net.IPNet{
											mustCIDR("fd00:dead:beef:dead::/64"),
											mustCIDR("fd00:dead:beef:ffff::/64"),
										}),
									},
								}...),
							},
							{
								Type: 1,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: keyB[:],
									},
									{
										Type: unix.WGPEER_A_ALLOWEDIPS,
										Data: mustAllowedIPs([]net.IPNet{
											mustCIDR("10.10.10.0/24"),
											mustCIDR("10.10.11.0/24"),
										}),
									},
								}...),
							},
						}...),
					}),
				},
				// Continuation of previous peer list, new peer list.
				{
					Data: m(netlink.Attribute{
						Type: unix.WGDEVICE_A_PEERS,
						Data: m([]netlink.Attribute{
							{
								Type: 0,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: keyB[:],
									},
									{
										Type: unix.WGPEER_A_ALLOWEDIPS,
										Data: mustAllowedIPs([]net.IPNet{
											mustCIDR("10.10.12.0/24"),
											mustCIDR("10.10.13.0/24"),
										}),
									},
								}...),
							},
							{
								Type: 1,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: keyC[:],
									},
									{
										Type: unix.WGPEER_A_ALLOWEDIPS,
										Data: mustAllowedIPs([]net.IPNet{
											mustCIDR("fd00:1234::/32"),
											mustCIDR("fd00:4567::/32"),
										}),
									},
								}...),
							},
						}...),
					}),
				},
			}},
			devices: []*Device{
				{
					Name:       okName,
					PrivateKey: testKey,
					Peers: []Peer{
						{
							PublicKey: keyA,
							AllowedIPs: []net.IPNet{
								mustCIDR("192.168.1.10/32"),
								mustCIDR("192.168.1.11/32"),
								mustCIDR("fd00:dead:beef:dead::/64"),
								mustCIDR("fd00:dead:beef:ffff::/64"),
							},
						},
						{
							PublicKey: keyB,
							AllowedIPs: []net.IPNet{
								mustCIDR("10.10.10.0/24"),
								mustCIDR("10.10.11.0/24"),
								mustCIDR("10.10.12.0/24"),
								mustCIDR("10.10.13.0/24"),
							},
						},
						{
							PublicKey: keyC,
							AllowedIPs: []net.IPNet{
								mustCIDR("fd00:1234::/32"),
								mustCIDR("fd00:4567::/32"),
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const (
				cmd   = unix.WG_CMD_GET_DEVICE
				flags = netlink.Request | netlink.Dump
			)

			// Advance through the test messages on subsequent calls.
			var i int
			fn := func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
				defer func() { i++ }()

				return tt.msgs[i], nil
			}

			c := testClient(t, genltest.CheckRequest(familyID, cmd, flags, fn))
			defer c.Close()

			// Replace interfaces if necessary.
			if tt.interfaces != nil {
				c.interfaces = tt.interfaces
			}

			devices, err := c.Devices()
			if err != nil {
				t.Fatalf("failed to get devices: %v", err)
			}

			if diff := cmp.Diff(tt.devices, devices); diff != "" {
				t.Fatalf("unexpected devices (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLinuxClientConfigureDevice(t *testing.T) {
	nameAttr := netlink.Attribute{
		Type: unix.WGDEVICE_A_IFNAME,
		Data: nlenc.Bytes(okName),
	}

	tests := []struct {
		name  string
		cfg   Config
		attrs []netlink.Attribute
		ok    bool
	}{
		{
			name: "bad peer endpoint",
			cfg: Config{
				Peers: []PeerConfig{{
					Endpoint: &net.UDPAddr{
						IP: net.IP{0xff},
					},
				}},
			},
		},
		{
			name: "bad peer allowed IP",
			cfg: Config{
				Peers: []PeerConfig{{
					AllowedIPs: []net.IPNet{{
						IP: net.IP{0xff},
					}},
				}},
			},
		},
		{
			name: "ok, none",
			attrs: []netlink.Attribute{
				nameAttr,
			},
			ok: true,
		},
		{
			name: "ok, all",
			cfg: Config{
				PrivateKey:   ptr(mustHexKey("e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a")),
				ListenPort:   ptr[uint16](12912),
				FirewallMark: ptr[uint32](0),
				ReplacePeers: true,
				Peers: []PeerConfig{
					{
						PublicKey:         mustHexKey("b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33"),
						PresharedKey:      ptr(mustHexKey("188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52")),
						Endpoint:          mustUDPAddr("[abcd:23::33%2]:51820"),
						ReplaceAllowedIPs: true,
						AllowedIPs: []net.IPNet{
							mustCIDR("192.168.4.4/32"),
						},
					},
					{
						PublicKey:                   mustHexKey("58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376"),
						UpdateOnly:                  true,
						Endpoint:                    mustUDPAddr("182.122.22.19:3233"),
						PersistentKeepaliveInterval: ptr(111 * time.Second),
						ReplaceAllowedIPs:           true,
						AllowedIPs: []net.IPNet{
							mustCIDR("192.168.4.6/32"),
						},
					},
					{
						PublicKey:         mustHexKey("662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58"),
						Endpoint:          mustUDPAddr("5.152.198.39:51820"),
						ReplaceAllowedIPs: true,
						AllowedIPs: []net.IPNet{
							mustCIDR("192.168.4.10/32"),
							mustCIDR("192.168.4.11/32"),
						},
					},
					{
						PublicKey: mustHexKey("e818b58db5274087fcc1be5dc728cf53d3b5726b4cef6b9bab8f8f8c2452c25c"),
						Remove:    true,
					},
				},
			},
			attrs: []netlink.Attribute{
				nameAttr,
				{
					Type: unix.WGDEVICE_A_PRIVATE_KEY,
					Data: keyBytes("e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"),
				},
				{
					Type: unix.WGDEVICE_A_LISTEN_PORT,
					Data: nlenc.Uint16Bytes(12912),
				},
				{
					Type: unix.WGDEVICE_A_FWMARK,
					Data: nlenc.Uint32Bytes(0),
				},
				{
					Type: unix.WGDEVICE_A_FLAGS,
					Data: nlenc.Uint32Bytes(unix.WGDEVICE_F_REPLACE_PEERS),
				},
				{
					Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
					Data: m([]netlink.Attribute{
						{
							Type: netlink.Nested,
							Data: m([]netlink.Attribute{
								{
									Type: unix.WGPEER_A_PUBLIC_KEY,
									Data: keyBytes("b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33"),
								},
								{
									Type: unix.WGPEER_A_FLAGS,
									Data: nlenc.Uint32Bytes(unix.WGPEER_F_REPLACE_ALLOWEDIPS),
								},
								{
									Type: unix.WGPEER_A_PRESHARED_KEY,
									Data: keyBytes("188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52"),
								},
								{
									Type: unix.WGPEER_A_ENDPOINT,
									Data: (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&unix.RawSockaddrInet6{
										Family: unix.AF_INET6,
										Addr: [16]byte{
											0xab, 0xcd, 0x00, 0x23,
											0x00, 0x00, 0x00, 0x00,
											0x00, 0x00, 0x00, 0x00,
											0x00, 0x00, 0x00, 0x33,
										},
										Port: sockaddrPort(51820),
									})))[:],
								},
								{
									Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
									Data: mustAllowedIPs([]net.IPNet{
										mustCIDR("192.168.4.4/32"),
									}),
								},
							}...),
						},
						{
							Type: netlink.Nested | 1,
							Data: m([]netlink.Attribute{
								{
									Type: unix.WGPEER_A_PUBLIC_KEY,
									Data: keyBytes("58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376"),
								},
								{
									Type: unix.WGPEER_A_FLAGS,
									Data: nlenc.Uint32Bytes(unix.WGPEER_F_REPLACE_ALLOWEDIPS | unix.WGPEER_F_UPDATE_ONLY),
								},
								{
									Type: unix.WGPEER_A_ENDPOINT,
									Data: (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&unix.RawSockaddrInet4{
										Family: unix.AF_INET,
										Addr:   [4]byte{182, 122, 22, 19},
										Port:   sockaddrPort(3233),
									})))[:],
								},
								{
									Type: unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
									Data: nlenc.Uint16Bytes(111),
								},
								{
									Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
									Data: mustAllowedIPs([]net.IPNet{
										mustCIDR("192.168.4.6/32"),
									}),
								},
							}...),
						},
						{
							Type: netlink.Nested | 2,
							Data: m([]netlink.Attribute{
								{
									Type: unix.WGPEER_A_PUBLIC_KEY,
									Data: keyBytes("662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58"),
								},
								{
									Type: unix.WGPEER_A_FLAGS,
									Data: nlenc.Uint32Bytes(unix.WGPEER_F_REPLACE_ALLOWEDIPS),
								},
								{
									Type: unix.WGPEER_A_ENDPOINT,
									Data: (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&unix.RawSockaddrInet4{
										Family: unix.AF_INET,
										Addr:   [4]byte{5, 152, 198, 39},
										Port:   sockaddrPort(51820),
									})))[:],
								},
								{
									Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
									Data: mustAllowedIPs([]net.IPNet{
										mustCIDR("192.168.4.10/32"),
										mustCIDR("192.168.4.11/32"),
									}),
								},
							}...),
						},
						{
							Type: netlink.Nested | 3,
							Data: m([]netlink.Attribute{
								{
									Type: unix.WGPEER_A_PUBLIC_KEY,
									Data: keyBytes("e818b58db5274087fcc1be5dc728cf53d3b5726b4cef6b9bab8f8f8c2452c25c"),
								},
								{
									Type: unix.WGPEER_A_FLAGS,
									Data: nlenc.Uint32Bytes(unix.WGPEER_F_REMOVE_ME),
								},
							}...),
						},
					}...),
				},
			},
			ok: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const (
				cmd   = unix.WG_CMD_SET_DEVICE
				flags = netlink.Request | netlink.Acknowledge
			)

			fn := func(greq genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
				attrs, err := netlink.UnmarshalAttributes(greq.Data)
				if err != nil {
					return nil, err
				}

				if diff := diffAttrs(tt.attrs, attrs); diff != "" {
					t.Fatalf("unexpected request attributes (-want +got):\n%s", diff)
				}

				// Data currently unused; send a message to acknowledge request.
				return []genetlink.Message{{}}, nil
			}

			c := testClient(t, genltest.CheckRequest(familyID, cmd, flags, fn))
			defer c.Close()

			err := c.ConfigureDevice(okName, tt.cfg)

			if tt.ok && err != nil {
				t.Fatalf("failed to configure device: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

func TestLinuxClientConfigureDeviceLargePeerIPChunks(t *testing.T) {
	nameAttr := netlink.Attribute{
		Type: unix.WGDEVICE_A_IFNAME,
		Data: nlenc.Bytes(okName),
	}

	var (
		peerA    = GeneratePrivateKey().PublicKey()
		peerAIPs = generateIPs(ipBatchChunk + 1)

		peerB    = GeneratePrivateKey().PublicKey()
		peerBIPs = generateIPs(ipBatchChunk / 2)

		peerC    = GeneratePrivateKey().PublicKey()
		peerCIPs = generateIPs(ipBatchChunk * 3)

		peerD = GeneratePrivateKey().PublicKey()
	)

	cfg := Config{
		ReplacePeers: true,
		Peers: []PeerConfig{
			{
				PublicKey:         peerA,
				UpdateOnly:        true,
				ReplaceAllowedIPs: true,

				AllowedIPs: peerAIPs,
			},
			{
				PublicKey:         peerB,
				UpdateOnly:        true,
				ReplaceAllowedIPs: true,
				AllowedIPs:        peerBIPs,
			},
			{
				PublicKey:         peerC,
				UpdateOnly:        true,
				ReplaceAllowedIPs: true,
				AllowedIPs:        peerCIPs,
			},
			{
				PublicKey: peerD,
				Remove:    true,
			},
		},
	}

	var allAttrs []netlink.Attribute
	fn := func(greq genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		attrs, err := netlink.UnmarshalAttributes(greq.Data)
		if err != nil {
			return nil, err
		}

		allAttrs = append(allAttrs, attrs...)

		// Data currently unused; send a message to acknowledge request.
		return []genetlink.Message{{}}, nil
	}

	c := testClient(t, fn)
	defer c.Close()

	if err := c.ConfigureDevice(okName, cfg); err != nil {
		t.Fatalf("failed to configure: %v", err)
	}

	want := []netlink.Attribute{
		// First peer, first chunk.
		nameAttr,
		{
			Type: unix.WGDEVICE_A_FLAGS,
			Data: nlenc.Uint32Bytes(unix.WGDEVICE_F_REPLACE_PEERS),
		},
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerA[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_REPLACE_ALLOWEDIPS | unix.WGPEER_F_UPDATE_ONLY),
					},
					{
						Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
						Data: mustAllowedIPs(peerAIPs[:ipBatchChunk]),
					},
				}...),
			}),
		},
		// First peer, final chunk.
		nameAttr,
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerA[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_UPDATE_ONLY),
					},
					// Not first chunk; don't replace IPs.
					{
						Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
						Data: mustAllowedIPs(peerAIPs[ipBatchChunk:]),
					},
				}...),
			}),
		},
		// Second peer, only chunk.
		nameAttr,
		// This is not the first peer; don't replace existing peers.
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerB[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_REPLACE_ALLOWEDIPS | unix.WGPEER_F_UPDATE_ONLY),
					},
					{
						Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
						Data: mustAllowedIPs(peerBIPs),
					},
				}...),
			}),
		},
		// Third peer, first chunk.
		nameAttr,
		// This is not the first peer; don't replace existing peers.
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerC[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_REPLACE_ALLOWEDIPS | unix.WGPEER_F_UPDATE_ONLY),
					},
					{
						Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
						Data: mustAllowedIPs(peerCIPs[:ipBatchChunk]),
					},
				}...),
			}),
		},
		// Third peer, second chunk.
		nameAttr,
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerC[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_UPDATE_ONLY),
					},
					// Not first chunk; don't replace IPs.
					{
						Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
						Data: mustAllowedIPs(peerCIPs[ipBatchChunk : ipBatchChunk*2]),
					},
				}...),
			}),
		},
		// Third peer, final chunk.
		nameAttr,
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerC[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_UPDATE_ONLY),
					},
					// Not first chunk; don't replace IPs.
					{
						Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
						Data: mustAllowedIPs(peerCIPs[ipBatchChunk*2:]),
					},
				}...),
			}),
		},
		// Fourth peer, only chunk.
		nameAttr,
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerD[:],
					},
					// Not first chunk; don't replace IPs.
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_REMOVE_ME),
					},
				}...),
			}),
		},
	}

	if diff := diffAttrs(want, allAttrs); diff != "" {
		t.Fatalf("unexpected final attributes (-want +got):\n%s", diff)
	}
}

func m(attrs ...netlink.Attribute) []byte { return nltest.MustMarshalAttributes(attrs) }

func ptr[t any](v t) *t { return &v }

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}

func keyBytes(s string) []byte {
	k := mustHexKey(s)
	return k[:]
}

func mustAllowedIPs(ipns []net.IPNet) []byte {
	ae := netlink.NewAttributeEncoder()
	if err := encodeAllowedIPs(ae, ipns); err != nil {
		panicf("failed to create allowed IP attributes: %v", err)
	}

	b, err := ae.Encode()
	if err != nil {
		panicf("failed to encode allowed IP attributes: %v", err)
	}

	return b
}

// mustHexKey decodes a hex string s as a key or panics.
func mustHexKey(s string) Key {
	b, err := hex.DecodeString(s)
	if err != nil {
		panicf("wgtest: failed to decode hex key: %v", err)
	}

	k, err := NewKey(b)
	if err != nil {
		panicf("wgtest: failed to create key: %v", err)
	}

	return k
}

func generateIPs(n int) []net.IPNet {
	cur, err := ipaddr.Parse("2001:db8::/64")
	if err != nil {
		panicf("failed to create cursor: %v", err)
	}

	ips := make([]net.IPNet, 0, n)
	for i := 0; i < n; i++ {
		pos := cur.Next()
		if pos == nil {
			panic("hit nil IP during IP generation")
		}

		ips = append(ips, net.IPNet{
			IP:   pos.IP,
			Mask: net.CIDRMask(128, 128),
		})
	}

	return ips
}

func mustCIDR(s string) net.IPNet {
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		panicf("awgctrl: failed to parse CIDR: %v", err)
	}

	return *cidr
}

func mustUDPAddr(s string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		panicf("awgctrl: failed to resolve UDP address: %v", err)
	}

	return a
}
