package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/nyktios/sniroute/internal/probe"
)

const (
	SplitStandard  = "standard"
	SplitBeforeSNI = "before-sni"
	SplitInsideSNI = "inside-sni"
	SplitAfterSNI  = "after-sni"
)

// ResolveSplitPosition keeps the original boolean flag compatible while making
// every new position explicit. An explicit position enables the experiment.
func ResolveSplitPosition(enabled bool, position string) (string, error) {
	if position == "" {
		if enabled {
			return SplitInsideSNI, nil
		}
		return SplitStandard, nil
	}
	switch position {
	case SplitStandard:
		if enabled {
			return "", errors.New("-tls-record-split 与分片位置 standard 冲突，请只选择一种模式")
		}
	case SplitBeforeSNI, SplitInsideSNI, SplitAfterSNI:
	default:
		return "", fmt.Errorf("分片位置 %q 无效：可选 standard、before-sni、inside-sni、after-sni", position)
	}
	return position, nil
}

func splitVariant(position string) string {
	switch position {
	case SplitStandard:
		return "standard"
	case SplitInsideSNI:
		return "tls-record-sni-split" // retain the original experiment identifier
	default:
		return "tls-record-" + position
	}
}

// helloSplitConn changes only the record framing of the first ClientHello.
// The handshake bytes, including SNI, remain identical. Later records (including
// any second ClientHello after HelloRetryRequest) pass through unchanged.
// TCP packet boundaries are deliberately not controlled.
type helloSplitConn struct {
	net.Conn
	pending  []byte
	done     bool
	failed   error
	position string
}

func (c *helloSplitConn) Write(p []byte) (int, error) {
	if c.failed != nil {
		return 0, c.failed
	}
	if c.done {
		return c.Conn.Write(p)
	}
	if len(c.pending)+len(p) > maxRecorded {
		c.failed = probe.ErrTooLarge
		return 0, c.failed
	}
	c.pending = append(c.pending, p...)
	wire, err := splitHelloAt(c.pending, c.position)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return len(p), nil // wait for the rest of the first handshake message
	}
	if err != nil {
		c.failed = err
		return 0, err
	}
	for len(wire) > 0 {
		n, err := c.Conn.Write(wire)
		if n > 0 {
			wire = wire[n:]
		}
		if err != nil || n == 0 {
			if err == nil {
				err = io.ErrNoProgress
			}
			c.failed = err
			return 0, err
		}
	}
	c.pending = nil
	c.done = true
	return len(p), nil
}

func splitHelloSNI(raw []byte) ([]byte, error) {
	return splitHelloAt(raw, SplitInsideSNI)
}

func splitHelloAt(raw []byte, position string) ([]byte, error) {
	position, err := ResolveSplitPosition(true, position)
	if err != nil {
		return nil, err
	}
	ch, err := probe.ReadClientHello(bytes.NewReader(raw), 0)
	if err != nil {
		return nil, err
	}
	if ch.SNI == "" {
		return nil, errors.New("TLS record split requires a nonempty SNI")
	}
	var hello []byte
	for pos := 0; pos < len(ch.Raw); {
		n := int(binary.BigEndian.Uint16(ch.Raw[pos+3 : pos+5]))
		hello = append(hello, ch.Raw[pos+5:pos+5+n]...)
		pos += 5 + n
	}
	// ReadClientHello has validated these length-prefixed structures. Locate
	// the actual server_name extension, rather than searching arbitrary random
	// bytes for a substring that might also occur elsewhere in the message.
	pos := 4 + 2 + 32
	pos += 1 + int(hello[pos])                                // session ID
	pos += 2 + int(binary.BigEndian.Uint16(hello[pos:pos+2])) // cipher suites
	pos += 1 + int(hello[pos])                                // compression methods
	end := pos + 2 + int(binary.BigEndian.Uint16(hello[pos:pos+2]))
	pos += 2
	cut := -1
	for pos < end {
		extensionStart := pos
		typ := binary.BigEndian.Uint16(hello[pos : pos+2])
		n := int(binary.BigEndian.Uint16(hello[pos+2 : pos+4]))
		pos += 4
		if typ == 0 { // server_name
			if position == SplitBeforeSNI {
				cut = extensionStart
				break
			}
			if position == SplitAfterSNI {
				cut = pos + n
				break
			}
			for q := pos + 2; q < pos+n; {
				nameType := hello[q]
				length := int(binary.BigEndian.Uint16(hello[q+1 : q+3]))
				q += 3
				if nameType == 0 {
					cut = q + length/2
					break
				}
				q += length
			}
			break
		}
		pos += n
	}
	if cut < 0 {
		return nil, errors.New("cannot locate SNI record split")
	}
	helloEnd := 4 + (int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3]))
	if cut >= helloEnd {
		return nil, errors.New("SNI 扩展后没有可分片的握手字节，不能生成 after-sni 变体")
	}
	// Split the original record containing this handshake offset. Preserve
	// every other record and any bytes following the first ClientHello.
	offset := 0
	for pos = 0; pos < len(ch.Raw); {
		n := int(binary.BigEndian.Uint16(raw[pos+3 : pos+5]))
		if cut > offset && cut < offset+n {
			first := cut - offset
			wire := append([]byte(nil), raw[:pos]...)
			for _, part := range [][]byte{raw[pos+5 : pos+5+first], raw[pos+5+first : pos+5+n]} {
				wire = append(wire, raw[pos], raw[pos+1], raw[pos+2], byte(len(part)>>8), byte(len(part)))
				wire = append(wire, part...)
			}
			return append(wire, raw[pos+5+n:]...), nil
		}
		offset += n
		pos += 5 + n
	}
	return nil, errors.New("SNI split point is already a TLS record boundary")
}
