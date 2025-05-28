//go:build linux
// +build linux

package awgctrl

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mikioh/ipaddr"
)

func TestIntegrationClient(t *testing.T) {
	c, done := integrationClient(t)
	defer done()

	devices, err := c.Devices()
	if err != nil {
		// It seems that not all errors returned by UNIX socket dialing
		// conform to os.IsPermission, so for now, be lenient and assume that
		// any error here means that permission was denied.
		t.Skipf("skipping, failed to get devices: %v", err)
	}

	tests := []struct {
		name string
		fn   func(t *testing.T, c *Client, d *Device)
	}{
		{
			name: "get",
			fn:   testGet,
		},
		{
			name: "configure",
			fn:   testConfigure,
		},
		{
			name: "configure many IPs",
			fn:   testConfigureManyIPs,
		},
		{
			name: "configure many peers",
			fn:   testConfigureManyPeers,
		},
		{
			name: "configure peers update only",
			fn:   testConfigurePeersUpdateOnly,
		},
		{
			name: "reset",
			fn: func(t *testing.T, c *Client, d *Device) {
				// Reset device several times; this used to cause a hang in
				// wireguard-go in late 2018.
				for i := 0; i < 10; i++ {
					resetDevice(t, c, d)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Panic if a specific test takes too long.
			timer := time.AfterFunc(5*time.Minute, func() {
				panic("test took too long")
			})
			defer timer.Stop()

			for _, d := range devices {
				// Break each device into another sub-test so that individual
				// drivers can be implemented as read-only and skip configuration
				// and reset in tests.
				t.Run(d.Name, func(t *testing.T) {
					tt.fn(t, c, d)

					// Start with a clean state after each test.
					resetDevice(t, c, d)
				})
			}
		})
	}
}

func TestIntegrationClientIsNotExist(t *testing.T) {
	c, done := integrationClient(t)
	defer done()

	if _, err := c.Device("wgnotexist0"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected is not exist error, but got: %v", err)
	}
}

func integrationClient(t *testing.T) (*Client, func()) {
	t.Helper()

	const (
		env     = "WGCTRL_INTEGRATION"
		confirm = "yesreallydoit"
	)

	if os.Getenv(env) != confirm {
		t.Skipf("skipping, set '%s=%s to run; DANGER: this will reset and reconfigure any detected WireGuard devices",
			env, confirm)
	}

	c, _, err := New()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skip("skipping, wgctrl is not available on this system")
		}

		t.Fatalf("failed to open client: %v", err)
	}

	return c, func() {
		if err := c.Close(); err != nil {
			t.Fatalf("failed to close client: %v", err)
		}
	}
}

func testGet(t *testing.T, c *Client, d *Device) {
	t.Logf("device: %s: %s", d.Name, d.PublicKey.String())

	dn, err := c.Device(d.Name)
	if err != nil {
		t.Fatalf("failed to get %q: %v", d.Name, err)
	}

	if diff := cmp.Diff(d, dn); diff != "" {
		t.Fatalf("unexpected Device (-want +got):\n%s", diff)
	}
}

func testConfigure(t *testing.T, c *Client, d *Device) {
	var (
		port = uint16(8888)
		ips  = []net.IPNet{
			mustCIDR("192.0.2.0/32"),
			mustCIDR("2001:db8::/128"),
		}

		priv    = GeneratePrivateKey()
		peerKey = GeneratePrivateKey().PublicKey()
	)

	t.Logf("before: %s: %s", d.Name, d.PublicKey.String())

	cfg := Config{
		PrivateKey:   &priv,
		ListenPort:   &port,
		ReplacePeers: true,
		Peers: []PeerConfig{{
			PublicKey:         peerKey,
			ReplaceAllowedIPs: true,
			AllowedIPs:        ips,
		}},
	}

	tryConfigure(t, c, d.Name, cfg)

	dn, err := c.Device(d.Name)
	if err != nil {
		t.Fatalf("failed to get %q by name: %v", d.Name, err)
	}

	// Now that a new configuration has been applied, update our initial
	// device for comparison.
	*d = Device{
		Name:       d.Name,
		PrivateKey: priv,
		PublicKey:  priv.PublicKey(),
		ListenPort: port,
		Peers: []Peer{{
			PublicKey:         peerKey,
			LastHandshakeTime: time.Time{},
			AllowedIPs:        ips,
			ProtocolVersion:   1,
		}},
	}

	// Sort AllowedIPs as different implementations might return
	// them in different order
	for i := range dn.Peers {
		ips := dn.Peers[i].AllowedIPs
		sort.Slice(ips, func(i, j int) bool {
			return bytes.Compare(ips[i].IP, ips[j].IP) > 0
		})
	}

	if diff := cmp.Diff(d, dn); diff != "" {
		t.Fatalf("unexpected Device from Device (-want +got):\n%s", diff)
	}

	// Leading space for alignment.
	out := fmt.Sprintf(" after: %s: %s\n", dn.Name, dn.PublicKey.String())
	for _, p := range dn.Peers {
		out += fmt.Sprintf("- peer: %s, IPs: %s\n", p.PublicKey.String(), ipsString(p.AllowedIPs))
	}

	t.Log(out)
}

func testConfigureManyIPs(t *testing.T, c *Client, d *Device) {
	// Apply 511 IPs per peer.
	var (
		countIPs int
		peers    []PeerConfig
	)

	for i := 0; i < 2; i++ {
		cidr := "2001:db8::/119"
		if i == 1 {
			cidr = "2001:db8:ffff::/119"
		}

		cur, err := ipaddr.Parse(cidr)
		if err != nil {
			t.Fatalf("failed to create cursor: %v", err)
		}

		var ips []net.IPNet
		for pos := cur.Next(); pos != nil; pos = cur.Next() {
			bits := 128
			if pos.IP.To4() != nil {
				bits = 32
			}

			ips = append(ips, net.IPNet{
				IP:   pos.IP,
				Mask: net.CIDRMask(bits, bits),
			})
		}

		peers = append(peers, PeerConfig{
			PublicKey:         GeneratePrivateKey().PublicKey(),
			ReplaceAllowedIPs: true,
			AllowedIPs:        ips,
		})

		countIPs += len(ips)
	}

	cfg := Config{
		ReplacePeers: true,
		Peers:        peers,
	}

	tryConfigure(t, c, d.Name, cfg)

	dn, err := c.Device(d.Name)
	if err != nil {
		t.Fatalf("failed to get %q by name: %v", d.Name, err)
	}

	peerIPs := countPeerIPs(dn)
	if diff := cmp.Diff(countIPs, peerIPs); diff != "" {
		t.Fatalf("unexpected number of configured peer IPs (-want +got):\n%s", diff)
	}

	t.Logf("device: %s: %d IPs", d.Name, peerIPs)
}

func testConfigureManyPeers(t *testing.T, c *Client, d *Device) {
	const (
		nPeers  = 256
		peerIPs = 512
	)

	var peers []PeerConfig
	for i := 0; i < nPeers; i++ {
		var (
			pk  = GenerateKey()
			dur = 10 * time.Second
		)

		ips := generateIPs((i + 1) * 2)

		peers = append(peers, PeerConfig{
			PublicKey:         GeneratePrivateKey().PublicKey(),
			PresharedKey:      &pk,
			ReplaceAllowedIPs: true,
			Endpoint: &net.UDPAddr{
				IP:   ips[0].IP,
				Port: 1111,
			},
			PersistentKeepaliveInterval: &dur,
			AllowedIPs:                  ips,
		})
	}

	priv := GeneratePrivateKey()

	cfg := Config{
		PrivateKey:   &priv,
		ListenPort:   new(uint16),
		FirewallMark: new(uint32),
		ReplacePeers: true,
		Peers:        peers,
	}

	tryConfigure(t, c, d.Name, cfg)

	dn, err := c.Device(d.Name)
	if err != nil {
		t.Fatalf("failed to get updated device: %v", err)
	}

	if diff := cmp.Diff(nPeers, len(dn.Peers)); diff != "" {
		t.Fatalf("unexpected number of peers (-want +got):\n%s", diff)
	}

	countIPs := countPeerIPs(dn)
	if diff := cmp.Diff(peerIPs, countIPs); diff != "" {
		t.Fatalf("unexpected number of peer IPs (-want +got):\n%s", diff)
	}

	t.Logf("device: %s: %d peers, %d IPs", d.Name, len(dn.Peers), countIPs)
}

func testConfigurePeersUpdateOnly(t *testing.T, c *Client, d *Device) {
	var (
		peerA = GeneratePrivateKey().PublicKey()
		peerB = GeneratePrivateKey().PublicKey()
		psk   = GenerateKey()
	)

	// Create an initial peer configuration.
	cfg := Config{
		Peers: []PeerConfig{{
			PublicKey: peerA,
		}},
	}

	tryConfigure(t, c, d.Name, cfg)

	// Create an updated configuration that should only apply to the existing
	// peer due to update only flags.
	cfg = Config{
		Peers: []PeerConfig{
			{
				PublicKey:    peerA,
				UpdateOnly:   true,
				PresharedKey: &psk,
			},
			{
				PublicKey:    peerB,
				UpdateOnly:   true,
				PresharedKey: &psk,
			},
		},
	}

	if err := c.ConfigureDevice(d.Name, cfg); err != nil {
		t.Fatalf("failed to configure second time on %q: %v", d.Name, err)
	}

	dn, err := c.Device(d.Name)
	if err != nil {
		t.Fatalf("failed to get updated device: %v", err)
	}

	want := []Peer{{
		PublicKey:       peerA,
		PresharedKey:    psk,
		ProtocolVersion: 1,
	}}

	if diff := cmp.Diff(want, dn.Peers); diff != "" {
		t.Fatalf("unexpected configured peers (-want +got):\n%s", diff)
	}
}

func resetDevice(t *testing.T, c *Client, d *Device) {
	t.Helper()

	cfg := Config{
		// Clear device config.
		PrivateKey:   &Key{},
		ListenPort:   new(uint16),
		FirewallMark: new(uint32),

		// Clear all peers.
		ReplacePeers: true,
	}

	tryConfigure(t, c, d.Name, cfg)
}

func tryConfigure(t *testing.T, c *Client, device string, cfg Config) {
	t.Helper()

	if err := c.ConfigureDevice(device, cfg); err != nil {
		t.Fatalf("failed to configure %q: %v", device, err)
	}
}

func countPeerIPs(d *Device) int {
	var count int
	for _, p := range d.Peers {
		count += len(p.AllowedIPs)
	}

	return count
}

func ipsString(ipns []net.IPNet) string {
	ss := make([]string, 0, len(ipns))
	for _, ipn := range ipns {
		ss = append(ss, ipn.String())
	}

	return strings.Join(ss, ", ")
}
