package tcp

import (
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/cheahjs/wintun-mitm/internal/mitm/types"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type TcpProxy struct {
	PcapHandle      *pcap.Handle
	OutgoingPackets chan []byte

	transMutex          sync.Mutex
	outgoingTranslation map[types.NatMapKey]*tcpMitmConn
	incomingTranslation map[types.NatMapKey]*tcpMitmConn

	etherLayerFields types.EtherLayerFields

	logger *zap.SugaredLogger
}

func MakeNewTcpProxy(logger *zap.SugaredLogger, pcapHandle *pcap.Handle, outgoingPackets chan []byte, etherLayerFields types.EtherLayerFields) *TcpProxy {
	return &TcpProxy{
		PcapHandle:          pcapHandle,
		OutgoingPackets:     outgoingPackets,
		outgoingTranslation: make(map[types.NatMapKey]*tcpMitmConn),
		incomingTranslation: make(map[types.NatMapKey]*tcpMitmConn),
		etherLayerFields:    etherLayerFields,
		logger:              logger.With("proto", "tcp"),
	}
}

func (p *TcpProxy) CreateTCPConn(srcIP net.IP, srcPort uint16) *tcpMitmConn {
	conn := &tcpMitmConn{
		logger:           p.logger.With("src.ip", srcIP, "src.port", srcPort),
		pcapHandle:       p.PcapHandle,
		oldSrcIP:         srcIP,
		oldSrcPort:       srcPort,
		proxy:            p,
		lastActive:       time.Now(),
		etherLayerFields: p.etherLayerFields,
	}
	return conn
}

// ReceivePacketFromTun processes packets that were received from the tunnel interface and bound for the outside.
func (p *TcpProxy) ReceivePacketFromTun(packet gopacket.Packet) {
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

	outgoingNat := types.NatTuple{
		SrcIP:   ipv4Layer.SrcIP,
		SrcPort: uint16(tcpLayer.SrcPort),
		DstIP:   ipv4Layer.DstIP,
		DstPort: uint16(tcpLayer.DstPort),
	}

	incomingNat := types.NatTuple{
		SrcIP:   ipv4Layer.DstIP,
		SrcPort: uint16(tcpLayer.DstPort),
		DstIP:   p.etherLayerFields.DefaultIP,
		DstPort: uint16(tcpLayer.SrcPort),
	}

	p.transMutex.Lock()
	conn, alreadyExist := p.outgoingTranslation[outgoingNat.Key()]
	if !alreadyExist {
		p.logger.Infof("Created new mapping for %v:%v -> %v:%v",
			outgoingNat.SrcIP, outgoingNat.SrcPort, outgoingNat.DstIP, outgoingNat.DstPort)
		conn = p.CreateTCPConn(outgoingNat.SrcIP, outgoingNat.SrcPort)
		p.outgoingTranslation[outgoingNat.Key()] = conn
	}
	p.incomingTranslation[incomingNat.Key()] = conn
	p.transMutex.Unlock()
	conn.SendPacket(p.PcapHandle, packet)
}

// ReceivePacketFromTun processes packets that were received from an external interface and bound for the tunnel.
func (p *TcpProxy) ReceivePacketFromInterface(packet gopacket.Packet) {
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

	nat := types.NatTuple{
		SrcIP:   ipv4Layer.SrcIP,
		SrcPort: uint16(tcpLayer.SrcPort),
		DstIP:   ipv4Layer.DstIP,
		DstPort: uint16(tcpLayer.DstPort),
	}

	p.transMutex.Lock()
	defer p.transMutex.Unlock()
	if conn, exists := p.incomingTranslation[nat.Key()]; exists {
		conn.ReceivePacket(packet)
	}
}

// inactiveCheck runs a loop and checks if a tcpMitmConn's lastActive is greater than 10 minutes, if so closes the "connection"
func (p *TcpProxy) InactiveCheck() {
	for {
		<-time.Tick(10 * time.Second)
		p.transMutex.Lock()
		for key, conn := range p.incomingTranslation {
			if conn.Expired() {
				p.logger.Infof("Mapping for %v -> %v expired",
					key.Src, key.Dst)
				delete(p.incomingTranslation, key)
			}
		}
		for key, conn := range p.outgoingTranslation {
			if conn.Expired() {
				p.logger.Infof("Mapping for %v -> %v expired",
					key.Src, key.Dst)
				delete(p.outgoingTranslation, key)
			}
		}
		p.transMutex.Unlock()
	}
}
