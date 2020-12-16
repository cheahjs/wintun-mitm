package mitm

import (
	"fmt"
	"net"

	"go.uber.org/zap"

	"github.com/cheahjs/wintun-mitm/internal/mitm/udp"

	"github.com/cheahjs/wintun-mitm/internal/mitm/types"
	"github.com/cheahjs/wintun-mitm/internal/network"

	"github.com/cheahjs/wintun-mitm/internal/mitm/tcp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mostlygeek/arp"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun/wintun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type MitmTun struct {
	logger           *zap.SugaredLogger
	session          wintun.Session
	readWait         windows.Handle
	outgoingPackets  chan []byte
	tcpProxy         *tcp.TcpProxy
	udpProxy         *udp.UdpProxy
	pcapHandle       *pcap.Handle
	defaultLUID      winipcfg.LUID
	etherLayerFields types.EtherLayerFields
}

func NewMitmTun(logger *zap.SugaredLogger, session wintun.Session, luid winipcfg.LUID) *MitmTun {
	logger.Info("Looking for default route interface")
	defaultLUID, defaultInterfaceIndex, defaultGatewayIP, err := network.GetDefaultInterface(luid)
	if err != nil {
		logger.Fatalf("Failed to get default interface: %v", err)
	}
	if defaultLUID == 0 {
		logger.Fatal("Failed to get default interface")
	}
	if defaultGatewayIP == nil {
		logger.Fatal("Failed to get IP of default gateway")
	}
	defaultGUID, _ := defaultLUID.GUID()
	logger.Infof("Found default network interface with GUID %v index %v", defaultGUID, defaultInterfaceIndex)

	logger.Info("Fetching default interface IP and MAC")
	iface, err := net.InterfaceByIndex(int(defaultInterfaceIndex))
	if err != nil {
		logger.Fatalf("Failed to get default interface with index %v: %v", defaultInterfaceIndex, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		logger.Fatalf("Failed to get default interface unicast addresses: %v", err)
	}
	var ipv4Addr net.IP
	for _, addr := range addrs {
		if ipv4Addr = addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
			break
		}
	}
	if ipv4Addr == nil {
		logger.Fatal("Failed to find default interface IPv4 address")
	}
	logger.Infof("Found default interface with IP %v", ipv4Addr)

	logger.Info("Searching ARP cache for gateway")
	defaultGatewayMAC := arp.Search(defaultGatewayIP.String())
	if defaultGatewayMAC == "" {
		logger.Fatalf("Failed to find MAC address for gateway IP %v", defaultGatewayIP)
	}
	defaultGatewayMACParsed, err := net.ParseMAC(defaultGatewayMAC)
	if err != nil {
		logger.Fatalf("Failed to parse gateway MAC %v: %v", defaultGatewayMAC, err)
	}
	logger.Infof("Found default gateway MAC %v", defaultGatewayMAC)

	return &MitmTun{
		logger:          logger,
		session:         session,
		readWait:        session.ReadWaitEvent(),
		outgoingPackets: make(chan []byte, 100),
		defaultLUID:     defaultLUID,
		etherLayerFields: types.EtherLayerFields{
			DefaultIP:  ipv4Addr,
			DefaultMAC: iface.HardwareAddr,
			GatewayMAC: defaultGatewayMACParsed,
		},
	}
}

func (m *MitmTun) Start() {
	m.logger.Info("Starting pcap")
	defaultGUID, _ := m.defaultLUID.GUID()
	handle, err := pcap.OpenLive(fmt.Sprintf("\\Device\\NPF_%v", defaultGUID), 2700, true, pcap.BlockForever)
	if err != nil {
		m.logger.Fatalf("Failed to open pcap handle on outgoing interface: %v", err)
	}
	m.logger.Info("Opened pcap")
	m.pcapHandle = handle
	m.tcpProxy = tcp.MakeNewTcpProxy(m.logger, handle, m.outgoingPackets, m.etherLayerFields)
	m.udpProxy = udp.MakeNewUdpProxy(m.logger, handle, m.outgoingPackets, m.etherLayerFields)
	go m.tcpProxy.InactiveCheck()
	go m.udpProxy.InactiveCheck()
	go m.receivePackets()
	go m.sendPackets()
	go m.readPacketsFromRealInterface()
}

func (m *MitmTun) Close() {
	if m.pcapHandle != nil {
		m.pcapHandle.Close()
	}
}

func (m *MitmTun) receivePackets() {
	m.logger.Info("Starting to receive packets from TUN")
	for {
		var buffer [0xFFFF]byte
		packet, err := m.session.ReceivePacket()
		switch err {
		case nil:
			packetSize := len(packet)
			copy(buffer[:], packet)
			m.session.ReleaseReceivePacket(packet)
			m.handleReceivedPacket(buffer[:packetSize])
		case windows.ERROR_NO_MORE_ITEMS:
			windows.WaitForSingleObject(m.readWait, windows.INFINITE)
			continue
		case windows.ERROR_HANDLE_EOF:
			m.logger.Fatal("ReceivePacket returned EOF")
		case windows.ERROR_INVALID_DATA:
			m.logger.Fatal("ReceivePacket returned invalid data")
		default:
			m.logger.Errorf("ReceivePacket returned an error: %v", err)
		}
	}
}

func (m *MitmTun) handleReceivedPacket(buffer []byte) {
	packet := gopacket.NewPacket(buffer, layers.LayerTypeIPv4, gopacket.Default)
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		// Didn't get an IPv4 packet
		return
	}
	ipv4 := ipv4Layer.(*layers.IPv4)
	protocol := ipv4.Protocol
	switch protocol {
	case layers.IPProtocolTCP:
		m.tcpProxy.ReceivePacketFromTun(packet)
	case layers.IPProtocolUDP:
		m.udpProxy.ReceivePacketFromTun(packet)
	}
}

func (m *MitmTun) sendPackets() {
	for packetToSend := range m.outgoingPackets {
		packet, err := m.session.AllocateSendPacket(len(packetToSend))
		if err == nil {
			copy(packet, packetToSend)
			m.session.SendPacket(packet)
		} else {
			switch err {
			case windows.ERROR_HANDLE_EOF:
				m.logger.Fatal("AllocateSendPacket returned EOF")
			case windows.ERROR_BUFFER_OVERFLOW:
				// Ring full, drop packets
				continue
			default:
				m.logger.Errorf("AllocateSendPacket returned an error: %v", err)
			}
		}
	}
}

func (m *MitmTun) readPacketsFromRealInterface() {
	m.logger.Info("Starting to read packets from pcap")
	packetSource := gopacket.NewPacketSource(m.pcapHandle, m.pcapHandle.LinkType())
	for packetData := range packetSource.Packets() {
		if packetData.NetworkLayer() == nil {
			continue
		}
		if packetData.NetworkLayer().LayerType() != layers.LayerTypeIPv4 {
			continue
		}
		if packetData.TransportLayer() == nil {
			continue
		}
		switch packetData.TransportLayer().LayerType() {
		case layers.LayerTypeTCP:
			m.tcpProxy.ReceivePacketFromInterface(packetData)
		case layers.LayerTypeUDP:
			m.udpProxy.ReceivePacketFromInterface(packetData)
		}
	}
}
