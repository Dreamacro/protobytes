package protobytes

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestReader(t *testing.T) {
	buf := BytesWriter{}
	buf.PutUint32be(777)
	buf.PutUint16le(888)
	text := []byte("foo bar baz")
	buf.PutSlice(text)

	unpacker := New(bytes.NewBuffer(buf.Bytes()))
	assert.Equal(t, uint32(777), unpacker.TryReadUint32be())
	assert.Equal(t, uint16(888), unpacker.TryReadUint16le())

	textBuf, err := unpacker.Next(len(text))
	assert.Nil(t, err)
	assert.Equal(t, text, []byte(textBuf))

	assert.Nil(t, unpacker.Error())
	unpacker.TryReadUint16be()
	assert.NotNil(t, unpacker.Error())
}

func getSocks5Addr(addr string) []byte {
	host, port, _ := net.SplitHostPort(addr)
	ip := netip.MustParseAddr(host)

	p, _ := strconv.Atoi(port)

	buf := BytesWriter(make([]byte, 0, 1+1+255+2))
	switch {
	case !ip.IsValid():
		buf.PutUint8(3)
		buf.PutUint8(byte(len(host)))
		buf.PutSlice([]byte(host))
		buf.PutUint16be(uint16(p))
	case ip.Is6():
		buf.PutUint8(4)
		buf.PutSlice(ip.AsSlice())
		buf.PutUint16be(uint16(p))
	default:
		buf.PutUint8(1)
		buf.PutSlice(ip.AsSlice())
		buf.PutUint16be(uint16(p))
	}

	return buf.Bytes()
}

func BenchmarkSock5AddrUnpacker(b *testing.B) {
	addr := getSocks5Addr("127.0.0.1:7777")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		unpacker := New(bytes.NewBuffer(addr))
		var (
			addr string
			port uint16
			r    BytesReader
		)

		tp := unpacker.TryByte()

		switch tp {
		case byte(1):
			r = unpacker.TryNext(6)
		case byte(3):
			l := unpacker.TryByte()
			r = unpacker.TryNext(int(l) + 2)
		case byte(4):
			r = unpacker.TryNext(18)
		default:
			assert.FailNow(b, "invalid", tp)
		}

		if unpacker.Error() != nil {
			assert.FailNow(b, "failed")
		}

		switch tp {
		case byte(1):
			addr = r.ReadIPv4().String()
			port = r.ReadUint16be()
		case byte(3):
			addrBuf, r := r.SplitAt(r.Len() - 2)
			addr = string(addrBuf)
			port = r.ReadUint16be()
		case byte(4):
			addr = r.ReadIPv6().String()
			port = r.ReadUint16be()
		default:
		}

		if addr != "127.0.0.1" || port != 7777 || unpacker.Error() != nil {
			assert.FailNow(b, "failed")
		}
	}
}

func BenchmarkSock5AddrStd(b *testing.B) {
	addr := getSocks5Addr("127.0.0.1:7777")
	buf := make([]byte, 1+1+255+2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := bufio.NewReader(bytes.NewBuffer(addr))
		code, _ := reader.ReadByte()
		var (
			addr string
			port uint16
			err  error
		)
		switch code {
		case byte(1):
			if _, err = io.ReadFull(reader, buf[:4]); err != nil {
				break
			}
			addr = net.IP(buf[:4]).String()
			err = binary.Read(reader, binary.BigEndian, &port)
		case byte(3):
			b, _ := reader.ReadByte()
			if _, err = io.ReadFull(reader, buf[:b]); err != nil {
				break
			}
			err = binary.Read(reader, binary.BigEndian, &port)
		case byte(4):
			if _, err = io.ReadFull(reader, buf[:16]); err != nil {
				break
			}
			addr = net.IP(buf[:16]).String()
			err = binary.Read(reader, binary.BigEndian, &port)
		default:
			assert.FailNow(b, "invalid", code)
		}

		if addr != "127.0.0.1" || port != 7777 || err != nil {
			assert.FailNow(b, "failed")
		}
	}
}

func packData(buf *bytes.Buffer, key []byte, data []byte) {
	// LittleEndian uint16 length
	// LittleEndian uint32 id
	// LittleEndian uint32 ts
	// LittleEndian uint16 dataLength
	// randData
	// data
	// hmac(key, id + dataLength + randData + data)[:4]

	// randData = data % 128

	length := 4 + 4 + 2 + len(data)%128 + len(data) + 4

	binary.Write(buf, binary.LittleEndian, uint16(length))
	binary.Write(buf, binary.LittleEndian, uint32(0xbeef))
	binary.Write(buf, binary.LittleEndian, uint32(time.Now().Unix()))
	binary.Write(buf, binary.LittleEndian, uint16(len(data)))
	buf.ReadFrom(io.LimitReader(rand.Reader, int64(len(data)%128)))
	buf.Write(data)

	hash := hmac.New(sha1.New, key)
	hash.Write(buf.Bytes())

	buf.Write(hash.Sum(nil)[:4])
}

func BenchmarkUnPackAndValidUnpacker(b *testing.B) {
	key := make([]byte, 16)
	buf := bytes.Buffer{}
	data := []byte("data")
	hash := hmac.New(sha1.New, key)
	packData(&buf, key, data)

	reuseBuf := bytes.Buffer{}
	reusePacket := New(nil)

	unpack := func(reader io.Reader, reuseBuf *bytes.Buffer) error {
		reusePacket.Reset(reader)
		unpacker := reusePacket
		length := unpacker.TryPeekUint16le()

		r, err := unpacker.Next(int(length) + 2)
		if err != nil {
			return err
		}

		r, checksum := r.SplitAt(r.Len() - 4)

		hash.Reset()
		hash.Write(r)

		r.Skip(2) // skip length

		id := r.ReadUint32le()
		ts := r.ReadUint32le()
		dataLength := r.ReadUint16le()
		r.Skip(int(dataLength) % 128) // skip randData

		data := r

		if !bytes.Equal(
			checksum,
			hash.Sum(nil)[:4],
		) {
			return errors.New("hmac")
		}

		if id != 0xbeef || time.Since(time.Unix(int64(ts), 0)) > time.Minute || len(data) == 0 {
			return errors.New("failed")
		}

		return nil
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reuseBuf.Reset()
		if err := unpack(New(bytes.NewBuffer(buf.Bytes())), &reuseBuf); err != nil {
			assert.FailNow(b, "failed", err.Error())
		}
	}
}

func BenchmarkUnPackAndValidStd(b *testing.B) {
	key := make([]byte, 16)
	buf := bytes.Buffer{}
	data := []byte("data")
	hash := hmac.New(sha1.New, key)
	packData(&buf, key, data)

	reuseBuf := bytes.Buffer{}

	unpack := func(reader *bufio.Reader, reuseBuf *bytes.Buffer) error {
		lengthBuf, err := reader.Peek(2)
		if err != nil {
			return err
		}

		length := binary.LittleEndian.Uint16(lengthBuf)
		if length < 14 {
			return io.ErrShortBuffer
		}

		if _, err := reuseBuf.ReadFrom(io.LimitReader(reader, int64(length)+2)); err != nil {
			return err
		}

		packet := reuseBuf.Bytes()[:reuseBuf.Len()-4]

		reuseBuf.Next(2)
		id := binary.LittleEndian.Uint32(reuseBuf.Next(4))
		ts := binary.LittleEndian.Uint32(reuseBuf.Next(4))
		dataLength := binary.LittleEndian.Uint16(reuseBuf.Next(2))
		reuseBuf.Next(int(dataLength) % 128)
		data := reuseBuf.Next(int(dataLength))

		hash.Reset()
		hash.Write(packet)

		if !bytes.Equal(
			reuseBuf.Next(4),
			hash.Sum(nil)[:4],
		) {
			return errors.New("hmac")
		}

		if id != 0xbeef || time.Since(time.Unix(int64(ts), 0)) > time.Minute || len(data) == 0 {
			return errors.New("failed")
		}

		return nil
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reuseBuf.Reset()
		if err := unpack(bufio.NewReader(bytes.NewBuffer(buf.Bytes())), &reuseBuf); err != nil {
			assert.FailNow(b, "failed", err.Error())
		}
	}
}
