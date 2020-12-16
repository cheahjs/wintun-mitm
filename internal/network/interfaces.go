package network

import (
	"net"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func GetDefaultInterface(ourLUID winipcfg.LUID) (winipcfg.LUID, uint32, net.IP, error) {
	r, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return 0, 0, nil, err
	}
	lowestMetric := ^uint32(0)
	index := uint32(0)
	luid := winipcfg.LUID(0)
	var gateway net.IP
	for i := range r {
		if r[i].DestinationPrefix.PrefixLength != 0 || r[i].InterfaceLUID == ourLUID {
			continue
		}
		ifrow, err := r[i].InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}

		iface, err := r[i].InterfaceLUID.IPInterface(windows.AF_INET)
		if err != nil {
			continue
		}

		if r[i].Metric+iface.Metric < lowestMetric {
			lowestMetric = r[i].Metric + iface.Metric
			index = r[i].InterfaceIndex
			luid = r[i].InterfaceLUID
			gateway = r[i].NextHop.IP().To4()
		}
	}
	return luid, index, gateway, nil
}
