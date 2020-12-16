package types

import (
	"fmt"
	"net"
)

type NatMapKey struct {
	// Src is the Src ip:port from the host's point of view
	Src string
	// Dst is the Dst ip:port from the host's point of view
	Dst string
}

type NatTuple struct {
	SrcIP   net.IP
	SrcPort uint16
	DstIP   net.IP
	DstPort uint16
}

func (n *NatTuple) Key() NatMapKey {
	return NatMapKey{
		Src: fmt.Sprintf("%s:%d", n.SrcIP.String(), n.SrcPort),
		Dst: fmt.Sprintf("%s:%d", n.DstIP.String(), n.DstPort),
	}
}
