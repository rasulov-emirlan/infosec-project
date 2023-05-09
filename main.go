package main

import (
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	dir, err := os.Open("pcap")
	if err != nil {
		log.Println(err)
	}
	defer dir.Close()

	fileInfos, err := dir.Readdir(-1)
	if err != nil {
		log.Println(err)
	}

	wg := sync.WaitGroup{}
	for _, fi := range fileInfos {
		if fi.IsDir() {
			continue
		}
		wg.Add(1)
		go detect(&wg, "pcap/"+fi.Name())
	}
	wg.Wait()
}

func detect(wg *sync.WaitGroup, filename string) error {
	defer wg.Done()
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return err
	}
	defer handle.Close()

	source := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range source.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		switch {
		case tcp.SYN && !tcp.ACK:
			fmt.Printf("scan for %s:\t SYN scan detected!\n", filename)
		case tcp.SYN && tcp.ACK:
			fmt.Printf("scan for %s:\t SYN/ACK scan detected!\n", filename)
		case tcp.RST && !tcp.ACK:
			fmt.Printf("scan for %s:\t NULL scan detected!\n", filename)
		case !tcp.SYN && !tcp.ACK:
			fmt.Printf("scan for %s:\t FIN/XMAS/NULL scan detected!\n", filename)
		}
	}
	return nil
}
