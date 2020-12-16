package tcp

import (
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/cheahjs/wintun-mitm/internal/mitm/types"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// tcpMitmConn handles the connection for a single tuple of (Src,Dst)
type tcpMitmConn struct {
	logger           *zap.SugaredLogger
	pcapHandle       *pcap.Handle
	oldSrcIP         net.IP
	oldSrcPort       uint16
	proxy            *TcpProxy
	lastActive       time.Time
	etherLayerFields types.EtherLayerFields
}

// SendPacket rewrites the packet from the TUN and places it into the real interface
func (c *tcpMitmConn) SendPacket(pcapHandle *pcap.Handle, packet gopacket.Packet) {
	c.lastActive = time.Now()
	// Make new eth layer
	ethLayer := &layers.Ethernet{
		SrcMAC:       c.etherLayerFields.DefaultMAC,
		DstMAC:       c.etherLayerFields.GatewayMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	// Remap source IP
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	ipv4Layer.SrcIP = c.etherLayerFields.DefaultIP
	// Configured TCP layer for checksum fixes
	tcpLayer := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	_ = tcpLayer.SetNetworkLayerForChecksum(ipv4Layer)

	newBuffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(newBuffer,
		gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		},
		ethLayer,
		ipv4Layer,
		tcpLayer,
		gopacket.Payload(tcpLayer.Payload),
	)
	if err != nil {
		c.logger.Errorf("Failed to serialize layer: %v", err)
		return
	}
	err = pcapHandle.WritePacketData(newBuffer.Bytes())
	if err != nil {
		c.logger.Errorf("Failed to call WritePacketData: %v", err)
	}
}

// ReceivePacket takes a packet from the real interface, rewrites the IP header and puts it back into the TUN interface
func (c *tcpMitmConn) ReceivePacket(packet gopacket.Packet) {
	c.lastActive = time.Now()
	// Remap destination IP
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	ipv4Layer.DstIP = c.oldSrcIP
	// Configured TCP layer for checksum fixes
	tcpLayer := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	_ = tcpLayer.SetNetworkLayerForChecksum(ipv4Layer)

	newBuffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(newBuffer,
		gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		},
		ipv4Layer,
		tcpLayer,
		gopacket.Payload(tcpLayer.Payload),
	)
	if err != nil {
		c.logger.Errorf("Failed to serialize layer: %v", err)
		return
	}
	c.proxy.OutgoingPackets <- newBuffer.Bytes()
}

func (c *tcpMitmConn) Expired() bool {
	return time.Since(c.lastActive) > 10*time.Minute
}
