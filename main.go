package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rasulov-emirlan/infosec-project/set"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: executable.exe <pcap filename>")
	}

	for _, filename := range os.Args[1:] {
		if err := detect(filename); err != nil {
			log.Fatal(err)
		}
	}
}

type Result struct {
	Filename string
	half     set.Set
	Null     set.Set
	Xmas     set.Set
	ICMP     set.Set
	UDP      set.Set
}

func (r Result) String() string {
	return fmt.Sprintf(
		`%s:
		HALF: %d,	%s
		NULL: %d,	%s
		XMAS: %d,	%s
		ICMP: %d,	%s
		UDP:  %d,	%s
		`,
		r.Filename,
		r.half.Size(), r.half,
		r.Null.Size(), r.Null,
		r.Xmas.Size(), r.Xmas,
		r.ICMP.Size(), r.ICMP,
		r.UDP.Size(), r.UDP,
	)
}

func detect(filename string) error {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return err
	}
	defer handle.Close()

	source := gopacket.NewPacketSource(handle, handle.LinkType())

	res := Result{
		Filename: filename,
		half:     set.New(),
		Null:     set.New(),
		Xmas:     set.New(),
		ICMP:     set.New(),
		UDP:      set.New(),
	}

	for packet := range source.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		// get ip address
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}

		ip, ok := ipLayer.(*layers.IPv4)
		if !ok {
			panic("not ip ok")
		}

		tcp, _ := tcpLayer.(*layers.TCP)

		// check for NULL scan
		if !tcp.RST && !tcp.SYN && !tcp.FIN && !tcp.ACK && !tcp.PSH && !tcp.URG && !tcp.ECE && !tcp.CWR {
			res.Null.Add(ip.SrcIP.String())
		}

		// check for XMAS scan
		if tcp.URG && !tcp.ACK && tcp.PSH && !tcp.RST && !tcp.SYN && tcp.FIN {
			res.Xmas.Add(ip.SrcIP.String())
		}

		// check for half open scan
		if tcp.RST && tcp.Ack == 0 && tcp.SYN {
			res.half.Add(ip.SrcIP.String())
		}

		// check for icmp echo request
		icmpLayer := packet.Layer(layers.LayerTypeICMPv6Echo)
		if icmpLayer == nil {
			continue
		}
		icmp, ok := icmpLayer.(*layers.ICMPv6Echo)
		if ok {
			if icmp.LayerType() == layers.ICMPv6TypeEchoRequest {
				res.ICMP.Add(ip.SrcIP.String())
			}
		}

		// check for udp scan
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}

		udp, ok := udpLayer.(*layers.UDP)

		if !ok {
			panic("udp not ok")
		}
		if ok {
			if udp.SrcPort >= 32768 && udp.SrcPort <= 65535 {
				res.UDP.Add(ip.SrcIP.String())
			}
		}
	}

	fmt.Println(res)
	return nil
}
