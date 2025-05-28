package awgctrl

import (
	"time"

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

// NewEncoder returns a new Encoder.
func NewEncoder() Encoder {
	return Encoder{netlink.NewAttributeEncoder()}
}

// Encoder is a netlink attribute encoder but encodes only not nil values.
type Encoder struct{ *netlink.AttributeEncoder }

func (e Encoder) Uint16(typ uint16, value *uint16) {
	if value != nil {
		e.AttributeEncoder.Uint16(typ, *value)
	}
}

func (e Encoder) Uint32(typ uint16, value *uint32) {
	if value != nil {
		e.AttributeEncoder.Uint32(typ, *value)
	}
}

func (e Encoder) Key(typ uint16, value *Key) {
	if value != nil {
		e.AttributeEncoder.Bytes(typ, value[:])
	}
}

func (e Encoder) Flag(typ uint16, cond bool, flag uint32) {
	if cond {
		e.AttributeEncoder.Uint32(typ, flag)
	}
}

func (e Encoder) Duration(typ uint16, d *time.Duration) {
	if d != nil {
		e.AttributeEncoder.Uint16(typ, uint16(d.Seconds()))
	}
}
