// Package probe reads TLS ClientHello messages from untrusted peers and
// extracts the SNI and ALPN values. It never completes a TLS handshake.
package probe

import (
	"crypto/sha256"
	"errors"
	"io"
)

var (
	// ErrNotTLS means the first bytes are not a TLS handshake record.
	ErrNotTLS = errors.New("probe: not a TLS handshake record")
	// ErrNotClientHello means the handshake message is not a ClientHello.
	ErrNotClientHello = errors.New("probe: handshake message is not a ClientHello")
	// ErrTooLarge means the ClientHello exceeds the configured size limit.
	ErrTooLarge = errors.New("probe: ClientHello too large")
	// ErrMalformed means the ClientHello structure is invalid.
	ErrMalformed = errors.New("probe: malformed ClientHello")
	// ErrInvalidSNI means the server_name value is not a plausible host name.
	ErrInvalidSNI = errors.New("probe: invalid SNI")
)

const (
	recordTypeHandshake  = 0x16
	handshakeClientHello = 0x01
	maxRecordLen         = 1 << 14 // TLS plaintext record limit
	maxRecords           = 32      // guards against endless tiny fragments
	maxSNILen            = 255

	extServerName = 0
	extALPN       = 16
)

// DefaultMaxHello is the default upper bound for a ClientHello body.
// Real hellos (even with post-quantum key shares) stay well below this.
const DefaultMaxHello = 16 * 1024

// ClientHello holds the fields SniRoute cares about.
type ClientHello struct {
	// SNI is the first host_name in the server_name extension, exactly as
	// sent (not lowercased). Empty when the extension is absent.
	SNI string
	// ALPN is the protocol list from the ALPN extension, in order.
	ALPN []string
	// Digest is the SHA-256 of the complete ClientHello handshake message
	// (4-byte header + body, reassembled across records). Only set by
	// ReadClientHello.
	Digest [sha256.Size]byte
	// Raw is every byte consumed from the reader (record headers included),
	// so the connection can be replayed into a TLS stack. Only set by
	// ReadClientHello.
	Raw []byte
}

// ReadClientHello reads one ClientHello from r, reassembling it across TLS
// records if needed, and parses it. At most maxBytes of handshake body are
// accepted (DefaultMaxHello if maxBytes <= 0). The caller is responsible for
// setting read deadlines on the underlying connection.
func ReadClientHello(r io.Reader, maxBytes int) (*ClientHello, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxHello
	}
	var (
		buf     []byte // reassembled handshake message (header + body)
		raw     []byte // everything read from r
		bodyLen = -1
	)
	for i := 0; ; i++ {
		if i >= maxRecords {
			return nil, ErrMalformed
		}
		var hdr [5]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, err
		}
		if hdr[0] != recordTypeHandshake || hdr[1] != 3 {
			return nil, ErrNotTLS
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if n == 0 || n > maxRecordLen {
			return nil, ErrMalformed
		}
		frag := make([]byte, n)
		if _, err := io.ReadFull(r, frag); err != nil {
			return nil, err
		}
		buf = append(buf, frag...)
		raw = append(raw, hdr[:]...)
		raw = append(raw, frag...)

		if len(buf) >= 1 && buf[0] != handshakeClientHello {
			return nil, ErrNotClientHello
		}
		if bodyLen < 0 && len(buf) >= 4 {
			bodyLen = int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
			if bodyLen > maxBytes {
				return nil, ErrTooLarge
			}
		}
		if bodyLen >= 0 && len(buf) >= 4+bodyLen {
			ch, err := ParseClientHello(buf[4 : 4+bodyLen])
			if err != nil {
				return nil, err
			}
			ch.Digest = sha256.Sum256(buf[:4+bodyLen])
			ch.Raw = raw
			return ch, nil
		}
	}
}

// ParseClientHello parses a ClientHello handshake body (without the 4-byte
// handshake header).
func ParseClientHello(body []byte) (*ClientHello, error) {
	r := reader{b: body}
	r.skip(2 + 32)  // legacy_version, random
	r.skip(r.u8())  // legacy_session_id
	r.skip(r.u16()) // cipher_suites
	r.skip(r.u8())  // legacy_compression_methods
	if r.bad {
		return nil, ErrMalformed
	}

	ch := &ClientHello{}
	if len(r.b) == 0 { // no extensions at all
		return ch, nil
	}
	exts := r.sub(r.u16())
	if r.bad {
		return nil, ErrMalformed
	}

	var seenSNI, seenALPN bool
	for len(exts.b) > 0 {
		typ := exts.u16()
		data := exts.sub(exts.u16())
		if exts.bad {
			return nil, ErrMalformed
		}
		switch typ {
		case extServerName:
			if seenSNI {
				return nil, ErrMalformed
			}
			seenSNI = true
			sni, err := parseServerName(data)
			if err != nil {
				return nil, err
			}
			ch.SNI = sni
		case extALPN:
			if seenALPN {
				return nil, ErrMalformed
			}
			seenALPN = true
			alpn, err := parseALPN(data)
			if err != nil {
				return nil, err
			}
			ch.ALPN = alpn
		}
	}
	return ch, nil
}

func parseServerName(data reader) (string, error) {
	list := data.sub(data.u16())
	if data.bad {
		return "", ErrMalformed
	}
	for len(list.b) > 0 {
		nameType := list.u8()
		name := list.sub(list.u16())
		if list.bad {
			return "", ErrMalformed
		}
		if nameType != 0 { // only host_name is defined
			continue
		}
		return validateSNI(name.b)
	}
	return "", nil
}

func parseALPN(data reader) ([]string, error) {
	list := data.sub(data.u16())
	if data.bad {
		return nil, ErrMalformed
	}
	var out []string
	for len(list.b) > 0 {
		p := list.sub(list.u8())
		if list.bad || len(p.b) == 0 {
			return nil, ErrMalformed
		}
		out = append(out, string(p.b))
	}
	return out, nil
}

// validateSNI accepts printable ASCII of 1..255 bytes. It deliberately does
// not enforce full hostname syntax: the point of the tool is to observe
// whatever SNI the client chose to send.
func validateSNI(b []byte) (string, error) {
	if len(b) == 0 || len(b) > maxSNILen {
		return "", ErrInvalidSNI
	}
	for _, c := range b {
		if c < 0x21 || c > 0x7e {
			return "", ErrInvalidSNI
		}
	}
	return string(b), nil
}

// ValidateSNI reports whether s is acceptable as an SNI to probe with, using
// the same rules applied to received SNIs.
func ValidateSNI(s string) error {
	_, err := validateSNI([]byte(s))
	return err
}

// reader is a bounds-checked cursor; once any read overruns, bad stays set
// and all later reads return zero values.
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || n < 0 || n > len(r.b) {
		r.bad = true
		r.b = nil
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) skip(n int) { r.take(n) }

func (r *reader) u8() int {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return int(b[0])
}

func (r *reader) u16() int {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return int(b[0])<<8 | int(b[1])
}

func (r *reader) sub(n int) reader {
	b := r.take(n)
	return reader{b: b, bad: r.bad}
}
