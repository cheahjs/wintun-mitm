package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cheahjs/wintun-mitm/internal/mitm"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun/wintun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	interfaceName = "wintunmitm"
)

func main() {
	adapterIPFlag := flag.String("adapter-ip", "10.62.0.5", "IP address to assign to adapter")
	flag.Parse()

	wintunVersion, err := wintun.RunningVersion()
	if err != nil {
		log.Printf("Failed to get wintun version, might need to be installed: %v", err)
	} else {
		log.Printf("Using Wintun/%d.%d", (wintunVersion>>16)&0xffff, wintunVersion&0xffff)
	}

	log.Println("Creating pool")
	pool, err := wintun.MakePool(interfaceName)
	if err != nil {
		log.Fatalf("Failed to create pool: %v", err)
	}

	log.Println("Checking for existing adapter")
	adapter, err := pool.OpenAdapter(interfaceName)
	if err == nil {
		log.Println("Deleting existing adapter", adapter.LUID())
		_, err = adapter.Delete(true)
		if err != nil {
			log.Fatalf("Failed to delete existing adapter: %v", err)
		}
	}

	guid, err := windows.GUIDFromString("{66c85b4e-d6ec-4379-aa85-61f02f5b3559}")
	if err != nil {
		log.Fatalf("Failed to parse GUID: %v", err)
	}

	log.Println("Creating adapter")
	adapter, rebootRequired, err := pool.CreateAdapter(interfaceName, &guid)
	if err != nil {
		log.Fatalf("Failed to create adapter: %v", err)
	}
	if rebootRequired {
		log.Println("A reboot is required :sad:")
	}

	log.Println("Assigning IP address to adapter")
	if err = winipcfg.LUID(adapter.LUID()).AddIPAddress(net.IPNet{
		IP:   net.ParseIP(*adapterIPFlag),
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}); err != nil {
		log.Fatalf("Failed to set IP address for adapter")
	}

	log.Println("Starting wintun session")
	session, err := adapter.StartSession(0x800000)
	if err != nil {
		adapter.Delete(true)
		log.Fatalf("Failed to start session: %v", err)
	}
	defer adapter.Delete(true)

	tun := mitm.NewMitmTun(session, winipcfg.LUID(adapter.LUID()))
	defer tun.Close()

	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go tun.Start()

	for {
		select {
		case <-sigChan:
			log.Println("Terminating")
			return
		}
	}
}
