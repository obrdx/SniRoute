package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/nyktios/sniroute/internal/probe"
)

// ValidateTCPWriteSplit prevents mixing two independent experiment variables.
func ValidateTCPWriteSplit(recordPosition, position string, delay time.Duration) error {
	if delay < 0 || delay > time.Second || delay%time.Millisecond != 0 {
		return errors.New("TCP 写入间隔必须为 0..1s 的整毫秒")
	}
	if position == "" {
		if delay != 0 {
			return errors.New("-tcp-write-delay 需要搭配 -tcp-write-split-at")
		}
		return nil
	}
	if position != SplitBeforeSNI && position != SplitInsideSNI && position != SplitAfterSNI {
		return errors.New("TCP 写入位置无效：可选 before-sni、inside-sni、after-sni")
	}
	if recordPosition != SplitStandard {
		return errors.New("TCP 分次写入与 TLS record 分片实验不能同时启用")
	}
	return nil
}

// helloTCPWriteConn preserves the entire TLS wire stream. Separate writes are
// not a guarantee of separate TCP packets; actual segmentation needs capture.
// Only the first ClientHello is affected, including when TLS supplies it in
// several writes or records. The recorder below this wrapper sees only bytes
// that were really written, even on cancellation between the two writes.
type helloTCPWriteConn struct {
	net.Conn
	ctx      context.Context
	position string
	delay    time.Duration
	pending  []byte
	done     bool
	failed   error
}

func (c *helloTCPWriteConn) Write(p []byte) (int, error) {
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
	cut, err := tcpHelloCut(c.pending, c.position)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return len(p), nil
	}
	if err != nil {
		c.failed = err
		return 0, err
	}
	if err = c.writeAll(c.pending[:cut]); err == nil && c.delay > 0 {
		timer := time.NewTimer(c.delay)
		select {
		case <-c.ctx.Done():
			err = c.ctx.Err()
		case <-timer.C:
		}
		timer.Stop()
	}
	if err == nil {
		err = c.writeAll(c.pending[cut:])
	}
	if err != nil {
		c.failed = err
		return 0, err
	}
	c.pending = nil
	c.done = true
	return len(p), nil
}

func (c *helloTCPWriteConn) writeAll(p []byte) error {
	for len(p) > 0 {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		n, err := c.Conn.Write(p)
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func tcpHelloCut(raw []byte, position string) (int, error) {
	ch, err := probe.ReadClientHello(bytes.NewReader(raw), 0)
	if err != nil {
		return 0, err
	}
	cut, err := helloCut(ch.Raw, ch.SNI, position)
	if err != nil {
		return 0, err
	}
	offset := 0
	for pos := 0; pos < len(ch.Raw); {
		n := int(binary.BigEndian.Uint16(ch.Raw[pos+3 : pos+5]))
		if cut >= offset && cut < offset+n {
			return pos + 5 + cut - offset, nil
		}
		offset += n
		pos += 5 + n
	}
	return 0, errors.New("无法定位首个 ClientHello 的 TCP 写入位置")
}
