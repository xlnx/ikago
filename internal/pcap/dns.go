package pcap

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DNSIndicator indicates an DNS layer.
type DNSIndicator struct {
	layer *layers.DNS
}

// ParseDNSLayer parses an DNS layer and returns an DNS indicator.
func ParseDNSLayer(layer *layers.DNS) (*DNSIndicator, error) {
	return &DNSIndicator{layer: layer}, nil
}

// IsResponse returns if the DNS layer is a response.
func (indicator *DNSIndicator) IsResponse() bool {
	return indicator.layer.QR
}

func (indicator *DNSIndicator) OverwriteAnswer(ipv4 net.IP) {
	for i, _ := range indicator.layer.Answers {
		// type A
		if indicator.layer.Answers[i].IP != nil {
			fmt.Printf("forge dns rr %v -> %v\n",
				indicator.layer.Answers[i].IP, ipv4)
			indicator.layer.Answers[i].IP = ipv4
		}
	}
}

func (indicator *DNSIndicator) SerializeLayer() []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{} // See SerializeOptions for more details.
	var _ = indicator.layer.SerializeTo(buf, opts)
	return buf.Bytes()
}

// Answers returns recognizable answers in the DNS layer.
func (indicator *DNSIndicator) Answers() (string, []net.IP) {
	var (
		name string
		ips  []net.IP
	)

	ips = make([]net.IP, 0)

	for i, answer := range indicator.layer.Answers {
		if i == 0 {
			name = string(answer.Name)
		}
		if answer.IP != nil && answer.IP.To4() != nil {
			ips = append(ips, answer.IP)
		}
	}

	return name, ips
}
