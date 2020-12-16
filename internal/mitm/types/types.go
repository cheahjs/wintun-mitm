package types

import "net"

type EtherLayerFields struct {
	DefaultIP  net.IP
	DefaultMAC net.HardwareAddr
	GatewayMAC net.HardwareAddr
}
