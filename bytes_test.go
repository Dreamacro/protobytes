package protobytes

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBytesReader(t *testing.T) {
	var b BytesReader = []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}

	// test Len and IsEmpty
	assert.Equal(t, 8, b.Len())
	assert.Equal(t, 8, b.Cap())
	assert.False(t, b.IsEmpty())

	// test SplitAt
	b1, b2 := b.SplitAt(3)
	assert.Equal(t, []byte{0x12, 0x34, 0x56}, []byte(b1))
	assert.Equal(t, []byte{0x78, 0x9a, 0xbc, 0xde, 0xf0}, []byte(b2))

	b1, b2 = b.SplitAt(10)
	assert.Equal(t, []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}, []byte(b1))
	assert.Equal(t, []byte{}, []byte(b2))

	// test SplitBy
	b1, b2 = b.SplitBy(func(v byte) bool { return v == 0xbc })
	assert.Equal(t, []byte{0x12, 0x34, 0x56, 0x78, 0x9a}, []byte(b1))
	assert.Equal(t, []byte{0xbc, 0xde, 0xf0}, []byte(b2))

	b = []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde}

	// test ReadUint8
	assert.Equal(t, uint8(0x12), b.ReadUint8())
	assert.Equal(t, 14, b.Len())

	// test ReadUint16be
	assert.Equal(t, binary.BigEndian.Uint16([]byte{0x34, 0x56}), b.ReadUint16be())
	assert.Equal(t, 12, b.Len())

	// test ReadUint32be
	assert.Equal(t, binary.BigEndian.Uint32([]byte{0x78, 0x9a, 0xbc, 0xde}), b.ReadUint32be())
	assert.Equal(t, 8, b.Len())

	// test ReadUint64be
	assert.Equal(t, binary.BigEndian.Uint64([]byte{0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde}), b.ReadUint64be())
	assert.True(t, b.IsEmpty())

	// test ReadUint16le
	b = []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}
	assert.Equal(t, binary.LittleEndian.Uint16([]byte{0x12, 0x34}), b.ReadUint16le())
	assert.Equal(t, 12, b.Len())

	// test ReadUint32le
	assert.Equal(t, binary.LittleEndian.Uint32([]byte{0x56, 0x78, 0x9a, 0xbc}), b.ReadUint32le())
	assert.Equal(t, 8, b.Len())

	// test ReadUint64le
	assert.Equal(t, binary.LittleEndian.Uint64([]byte{0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}), b.ReadUint64le())
	assert.True(t, b.IsEmpty())

	// test Skip
	b = []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}
	b.Skip(3)
	assert.Equal(t, []byte{0x78, 0x9a, 0xbc}, []byte(b))

	// test Read
	buf := make([]byte, 4)
	n, _ := b.Read(buf)
	assert.Equal(t, 3, n)
	assert.Equal(t, []byte{0x78, 0x9a, 0xbc}, buf[:n])
	assert.True(t, b.IsEmpty())

	// test ReadIPv4
	b = []byte{192, 168, 0, 1}
	ip := b.ReadIPv4()
	assert.Equal(t, netip.MustParseAddr("192.168.0.1"), ip)
	assert.True(t, b.IsEmpty())

	// test ReadIPv6
	b = []byte{0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x82, 0x00, 0x90, 0x27, 0x73, 0x42}
	ip = b.ReadIPv6()
	assert.Equal(t, netip.MustParseAddr("2001:db8:85a3:8d3:1319:8200:9027:7342"), ip)
	assert.True(t, b.IsEmpty())
}

func TestBytesWriter(t *testing.T) {
	b := BytesWriter{}

	r := bytes.NewBuffer([]byte{0x12, 0x34, 0x56})
	err := b.ReadFull(r, 4)
	assert.Error(t, err)
	assert.Equal(t, 0, b.Len())

	r = bytes.NewBuffer([]byte{0x12, 0x34, 0x56})
	err = b.ReadFull(r, 2)
	assert.NoError(t, err)
	assert.Equal(t, 2, b.Len())

	assert.Equal(t, BytesWriter([]byte{0x12, 0x34}), b[:2])
	tmp := b.Slice(0, 2)
	tmp.PutSlice([]byte{0x78, 0x9a})
	assert.Equal(t, BytesWriter([]byte{0x78, 0x9a}), b[:2])
}

func readAddrStd(b []byte) (*Header, error) {
	if len(b) < 16 {
		return nil, errors.New("short buffer")
	}

	sign, r := b[:12], b[12:]
	if !bytes.Equal(signature, sign) {
		return nil, errors.New("invalid signature")
	}

	header := &Header{}

	switch command := r[0]; command {
	case LOCAL, PROXY:
		header.Command = command
	default:
		return nil, fmt.Errorf("invalid command %x", command)
	}

	switch protocol := r[1]; protocol {
	case UNSPEC, TCPOverIPv4, UDPOverIPv4, TCPOverIPv6, UDPOverIPv6, UNIXStream, UNIXDatagram:
		header.TransportProtocol = protocol
	default:
		return nil, fmt.Errorf("invalid protocol %x", protocol)
	}

	length := binary.LittleEndian.Uint16(r[2:4])
	switch length {
	case lengthIPv4, lengthIPv6, lengthUnix:
	default:
		return nil, fmt.Errorf("invalid length %x", length)
	}

	r = r[4:]
	if len(r) < int(length) {
		return nil, errors.New("short buffer")
	}

	switch length {
	case lengthIPv4:
		srcAddr := netip.AddrFrom4([4]byte(r[:4]))
		dstAddr := netip.AddrFrom4([4]byte(r[4:8]))
		srcPort := binary.BigEndian.Uint16(r[8:10])
		dstPort := binary.BigEndian.Uint16(r[10:12])

		header.SourceAddr = netip.AddrPortFrom(srcAddr, srcPort)
		header.DestinationAddr = netip.AddrPortFrom(dstAddr, dstPort)
	case lengthIPv6:
		srcAddr := netip.AddrFrom16([16]byte(r[:16]))
		dstAddr := netip.AddrFrom16([16]byte(r[16:32]))
		srcPort := binary.BigEndian.Uint16(r[32:34])
		dstPort := binary.BigEndian.Uint16(r[34:36])

		header.SourceAddr = netip.AddrPortFrom(srcAddr, srcPort)
		header.DestinationAddr = netip.AddrPortFrom(dstAddr, dstPort)
	default:
		return nil, fmt.Errorf("unsupported protocol %x", length)
	}

	return header, nil
}

func readAddrBytesReader(buf []byte) (*Header, error) {
	r := BytesReader(buf)

	if r.Len() < 16 {
		return nil, errors.New("short buffer")
	}

	sign, r := r.SplitAt(12)
	if !bytes.Equal(signature, sign) {
		return nil, errors.New("invalid signature")
	}

	header := &Header{}

	switch command := r.ReadUint8(); command {
	case LOCAL, PROXY:
		header.Command = command
	default:
		return nil, fmt.Errorf("invalid command %x", command)
	}

	switch protocol := r.ReadUint8(); protocol {
	case UNSPEC, TCPOverIPv4, UDPOverIPv4, TCPOverIPv6, UDPOverIPv6, UNIXStream, UNIXDatagram:
		header.TransportProtocol = protocol
	default:
		return nil, fmt.Errorf("invalid protocol %x", protocol)
	}

	length := r.ReadUint16le()
	switch length {
	case lengthIPv4, lengthIPv6, lengthUnix:
	default:
		return nil, fmt.Errorf("invalid length %x", length)
	}

	if r.Len() < int(length) {
		return nil, errors.New("short buffer")
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
		return nil, fmt.Errorf("unsupported protocol %x", length)
	}

	return header, nil
}

func writeAddrStd(header Header) []byte {
	buf := bytes.Buffer{}

	buf.Write(signature)
	buf.WriteByte(header.Command)
	buf.WriteByte(header.TransportProtocol)

	switch header.TransportProtocol {
	case TCPOverIPv4, UDPOverIPv4:
		binary.Write(&buf, binary.LittleEndian, lengthIPv4)
	case TCPOverIPv6, UDPOverIPv6:
		binary.Write(&buf, binary.LittleEndian, lengthIPv6)
	default:
		return nil
	}

	buf.Write(header.SourceAddr.Addr().AsSlice())
	buf.Write(header.DestinationAddr.Addr().AsSlice())
	binary.Write(&buf, binary.BigEndian, header.SourceAddr.Port())
	binary.Write(&buf, binary.BigEndian, header.DestinationAddr.Port())

	return buf.Bytes()
}

func writeAddrBytesWriter(header Header) []byte {
	buf := BytesWriter{}

	buf.PutSlice(signature)
	buf.PutUint8(header.Command)
	buf.PutUint8(header.TransportProtocol)

	switch header.TransportProtocol {
	case TCPOverIPv4, UDPOverIPv4:
		buf.PutUint16le(lengthIPv4)
	case TCPOverIPv6, UDPOverIPv6:
		buf.PutUint16le(lengthIPv6)
	default:
		return nil
	}

	buf.PutSlice(header.SourceAddr.Addr().AsSlice())
	buf.PutSlice(header.DestinationAddr.Addr().AsSlice())
	buf.PutUint16be(header.SourceAddr.Port())
	buf.PutUint16be(header.DestinationAddr.Port())

	return buf.Bytes()
}

func TestParseProtocolV2(t *testing.T) {
	hexStr := "0d0a0d0a000d0a515549540a20120c000c22384eac10000104d21f90"
	buf, _ := hex.DecodeString(hexStr)

	h1, err := readAddrBytesReader(buf)
	assert.NoError(t, err)

	h2, err := readAddrStd(buf)
	assert.NoError(t, err)

	assert.Equal(t, h1, h2)
}

func TestSerializationProtocolV2(t *testing.T) {
	header := Header{
		Command:           LOCAL,
		TransportProtocol: UDPOverIPv4,
		SourceAddr:        netip.MustParseAddrPort("12.34.56.78:1234"),
		DestinationAddr:   netip.MustParseAddrPort("172.16.0.1:8080"),
	}

	buf1 := writeAddrBytesWriter(header)
	buf2 := writeAddrStd(header)

	assert.Equal(t, buf1, buf2)
}

func BenchmarkParseProtocolV2Std(b *testing.B) {
	hexStr := "0d0a0d0a000d0a515549540a20120c000c22384eac10000104d21f90"
	buf, _ := hex.DecodeString(hexStr)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := readAddrStd(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseProxyProtocolV2BytesReader(b *testing.B) {
	hexStr := "0d0a0d0a000d0a515549540a20120c000c22384eac10000104d21f90"
	buf, _ := hex.DecodeString(hexStr)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := readAddrBytesReader(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSerializationProxyProtocolV2Std(b *testing.B) {
	header := Header{
		Command:           LOCAL,
		TransportProtocol: UDPOverIPv4,
		SourceAddr:        netip.MustParseAddrPort("12.34.56.78:1234"),
		DestinationAddr:   netip.MustParseAddrPort("172.16.0.1:8080"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writeAddrStd(header)
	}
}

func BenchmarkSerializationProxyProtocolV2kBytesWriter(b *testing.B) {
	header := Header{
		Command:           LOCAL,
		TransportProtocol: UDPOverIPv4,
		SourceAddr:        netip.MustParseAddrPort("12.34.56.78:1234"),
		DestinationAddr:   netip.MustParseAddrPort("172.16.0.1:8080"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writeAddrBytesWriter(header)
	}
}
