package protobytes

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
)

var signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

type Header struct {
	Command           byte
	TransportProtocol byte
	SourceAddr        netip.AddrPort
	DestinationAddr   netip.AddrPort
}

const (
	LOCAL byte = 0x20
	PROXY byte = 0x21
)

const (
	UNSPEC       = 0x00
	TCPOverIPv4  = 0x11
	UDPOverIPv4  = 0x12
	TCPOverIPv6  = 0x21
	UDPOverIPv6  = 0x22
	UNIXStream   = 0x31
	UNIXDatagram = 0x32
)

const (
	lengthIPv4 uint16 = 12
	lengthIPv6 uint16 = 36
	lengthUnix uint16 = 216
)

func ExampleBytesReader() {
	hexStr := "0d0a0d0a000d0a515549540a20120c000c22384eac10000104d21f90"
	buf, _ := hex.DecodeString(hexStr)

	r := BytesReader(buf)

	if r.Len() < 16 {
		panic("short buffer")
	}

	sign, r := r.SplitAt(12)
	if !bytes.Equal(signature, sign) {
		panic("invalid signature")
	}

	header := &Header{}

	switch command := r.ReadUint8(); command {
	case LOCAL, PROXY:
		header.Command = command
	default:
		panic(fmt.Errorf("invalid command %x", command))
	}

	switch protocol := r.ReadUint8(); protocol {
	case UNSPEC, TCPOverIPv4, UDPOverIPv4, TCPOverIPv6, UDPOverIPv6, UNIXStream, UNIXDatagram:
		header.TransportProtocol = protocol
	default:
		panic(fmt.Errorf("invalid protocol %x", protocol))
	}

	length := r.ReadUint16le()
	switch length {
	case lengthIPv4, lengthIPv6, lengthUnix:
	default:
		panic(fmt.Errorf("invalid length %x", length))
	}

	if r.Len() < int(length) {
		panic("short buffer")
	}

	switch length {
	case lengthIPv4:
		srcAddr := r.ReadIPv4()
		dstAddr := r.ReadIPv4()
		srcPort := r.ReadUint16be()
		dstPort := r.ReadUint16be()

		header.SourceAddr = netip.AddrPortFrom(srcAddr, srcPort)
		header.DestinationAddr = netip.AddrPortFrom(dstAddr, dstPort)
	case lengthIPv6:
		srcAddr := r.ReadIPv6()
		dstAddr := r.ReadIPv6()
		srcPort := r.ReadUint16be()
		dstPort := r.ReadUint16be()

		header.SourceAddr = netip.AddrPortFrom(srcAddr, srcPort)
		header.DestinationAddr = netip.AddrPortFrom(dstAddr, dstPort)
	default:
		panic(fmt.Errorf("unsupported protocol %x", length))
	}

	fmt.Printf("%+v\n", header)
}
