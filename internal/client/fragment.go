package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/nyktios/sniroute/internal/probe"
)

// helloSplitConn changes only the record framing of the first ClientHello.
// The handshake bytes, including SNI, remain identical. Later records (including
// any second ClientHello after HelloRetryRequest) pass through unchanged.
// TCP packet boundaries are deliberately not controlled.
type helloSplitConn struct {
	net.Conn
	pending []byte
	done    bool
	failed  error
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
	wire, err := splitHelloSNI(c.pending)
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
		typ := binary.BigEndian.Uint16(hello[pos : pos+2])
		n := int(binary.BigEndian.Uint16(hello[pos+2 : pos+4]))
		pos += 4
		if typ == 0 { // server_name
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
