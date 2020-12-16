package mitm

import (
	"fmt"
	"log"
	"net"

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
	session          wintun.Session
	readWait         windows.Handle
	outgoingPackets  chan []byte
	tcpProxy         *tcp.TcpProxy
	udpProxy         *udp.UdpProxy
	pcapHandle       *pcap.Handle
	defaultLUID      winipcfg.LUID
	etherLayerFields types.EtherLayerFields
}

func NewMitmTun(session wintun.Session, luid winipcfg.LUID) *MitmTun {
	log.Println("Looking for default route interface")
	defaultLUID, defaultInterfaceIndex, defaultGatewayIP, err := network.GetDefaultInterface(luid)
	if err != nil {
		log.Fatalf("Failed to get default interface: %v", err)
	}
	if defaultLUID == 0 {
		log.Fatal("Failed to get default interface")
	}
	if defaultGatewayIP == nil {
		log.Fatal("Failed to get IP of default gateway")
	}
	defaultGUID, _ := defaultLUID.GUID()
	log.Printf("Found default network interface with GUID %v index %v", defaultGUID, defaultInterfaceIndex)

	log.Println("Fetching default interface IP and MAC")
	iface, err := net.InterfaceByIndex(int(defaultInterfaceIndex))
	if err != nil {
		log.Fatalf("Failed to get default interface with index %v: %v", defaultInterfaceIndex, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		log.Fatalf("Failed to get default interface unicast addresses: %v", err)
	}
	var ipv4Addr net.IP
	for _, addr := range addrs {
		if ipv4Addr = addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
			break
		}
	}
	if ipv4Addr == nil {
		log.Fatal("Failed to find default interface IPv4 address")
	}

	log.Println("Searching ARP cache for gateway MAC")
	defaultGatewayMAC := arp.Search(defaultGatewayIP.String())
	if defaultGatewayMAC == "" {
		log.Fatalf("Failed to find MAC address for gateway IP %v", defaultGatewayIP)
	}
	defaultGatewayMACParsed, err := net.ParseMAC(defaultGatewayMAC)
	if err != nil {
		log.Fatalf("Failed to parse gateway MAC %v: %v", defaultGatewayMAC, err)
	}

	return &MitmTun{
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
	log.Println("Starting pcap")
	defaultGUID, _ := m.defaultLUID.GUID()
	handle, err := pcap.OpenLive(fmt.Sprintf("\\Device\\NPF_%v", defaultGUID), 2700, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open pcap handle on outgoing interface: %v", err)
	}
	log.Println("Opened pcap")
	m.pcapHandle = handle
	m.tcpProxy = tcp.MakeNewTcpProxy(handle, m.outgoingPackets, m.etherLayerFields)
	m.udpProxy = udp.MakeNewUdpProxy(handle, m.outgoingPackets, m.etherLayerFields)
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
	log.Println("Starting to receive packets from TUN")
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
			log.Fatalln("ReceivePacket returned EOF")
		case windows.ERROR_INVALID_DATA:
			log.Fatalln("ReceivePacket returned invalid data")
		default:
			log.Printf("ReceivePacket returned an error: %v", err)
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
				log.Fatalln("AllocateSendPacket returned EOF")
			case windows.ERROR_BUFFER_OVERFLOW:
				// Ring full, drop packets
				continue
			default:
				log.Printf("AllocateSendPacket returned an error: %v", err)
			}
		}
	}
}

func (m *MitmTun) readPacketsFromRealInterface() {
	log.Println("Starting to read packets from pcap")
	packetSource := gopacket.NewPacketSource(m.pcapHandle, m.pcapHandle.LinkType())
	for packetData := range packetSource.Packets() {
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
