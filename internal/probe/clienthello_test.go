package probe

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
)

// realHello captures the first TLS record produced by crypto/tls, so the
// parser is exercised against a genuine ClientHello.
func realHello(t *testing.T, sni string, alpn []string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		tls.Client(c1, &tls.Config{ServerName: sni, NextProtos: alpn, InsecureSkipVerify: true}).Handshake()
	}()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c2, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(c2, body); err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

// fragment re-wraps a single-record hello into records of at most n bytes.
func fragment(rec []byte, n int) []byte {
	payload := rec[5:]
	var out []byte
	for len(payload) > 0 {
		k := min(n, len(payload))
		out = append(out, rec[0], rec[1], rec[2], byte(k>>8), byte(k))
		out = append(out, payload[:k]...)
		payload = payload[k:]
	}
	return out
}

func TestReadClientHello(t *testing.T) {
	tests := []struct {
		name string
		sni  string
		alpn []string
		want string // expected SNI
	}{
		{"sni", "www.google.com", nil, "www.google.com"},
		{"sni+alpn", "Example.COM", []string{"sr-token-abc"}, "Example.COM"},
		{"multi alpn", "a.b.c", []string{"h2", "http/1.1"}, "a.b.c"},
		{"no sni", "", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := realHello(t, tc.sni, tc.alpn)
			ch, err := ReadClientHello(bytes.NewReader(rec), 0)
			if err != nil {
				t.Fatal(err)
			}
			if ch.SNI != tc.want {
				t.Errorf("SNI = %q, want %q", ch.SNI, tc.want)
			}
			// crypto/tls may add or reorder nothing in ALPN; compare when set.
			if tc.alpn != nil && !reflect.DeepEqual(ch.ALPN, tc.alpn) {
				t.Errorf("ALPN = %v, want %v", ch.ALPN, tc.alpn)
			}
		})
	}
}

func TestDigestAndRaw(t *testing.T) {
	rec := realHello(t, "digest.example.org", nil)
	one, err := ReadClientHello(bytes.NewReader(rec), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one.Raw, rec) {
		t.Error("Raw must be exactly the bytes consumed")
	}
	// The digest covers the handshake message, not the record framing, so
	// re-fragmenting must not change it.
	split, err := ReadClientHello(bytes.NewReader(fragment(rec, 100)), 0)
	if err != nil {
		t.Fatal(err)
	}
	if one.Digest != split.Digest || one.Digest == [32]byte{} {
		t.Errorf("digest differs across fragmentation: %x vs %x", one.Digest, split.Digest)
	}
	if !bytes.Equal(rec[5:], one.Raw[5:]) || sha256.Sum256(rec[5:]) != one.Digest {
		t.Error("digest is not SHA-256 of the handshake message")
	}
	// Trailing bytes after the hello are not consumed.
	trail := append(append([]byte(nil), rec...), []byte("EXTRA")...)
	r := bytes.NewReader(trail)
	if _, err := ReadClientHello(r, 0); err != nil || r.Len() != 5 {
		t.Errorf("consumed past the ClientHello: err=%v left=%d", err, r.Len())
	}
}

func TestReadClientHelloFragmented(t *testing.T) {
	rec := realHello(t, "frag.example.org", []string{"tok"})
	for _, size := range []int{64, 100, 500} {
		ch, err := ReadClientHello(bytes.NewReader(fragment(rec, size)), 0)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if ch.SNI != "frag.example.org" {
			t.Errorf("size %d: SNI = %q", size, ch.SNI)
		}
	}
}

func TestReadClientHelloErrors(t *testing.T) {
	good := realHello(t, "x.example.com", nil)

	tooBig := append([]byte(nil), good...)
	tooBig[6], tooBig[7], tooBig[8] = 0x01, 0x00, 0x00 // handshake length 64KiB

	notHello := append([]byte(nil), good...)
	notHello[5] = 2 // ServerHello

	zeroRec := []byte{0x16, 3, 1, 0, 0}

	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"http", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), ErrNotTLS},
		{"not clienthello", notHello, ErrNotClientHello},
		{"too large", tooBig, ErrTooLarge},
		{"zero-length record", zeroRec, ErrMalformed},
		{"truncated", good[:len(good)/2], io.ErrUnexpectedEOF},
		{"empty", nil, io.EOF},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadClientHello(bytes.NewReader(tc.in), 0)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestReadClientHelloEndlessFragments(t *testing.T) {
	// Many 1-byte records must be cut off by the record-count limit.
	rec := realHello(t, "x.example.com", nil)
	_, err := ReadClientHello(bytes.NewReader(fragment(rec, 1)), 0)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestReadClientHelloSizeLimit(t *testing.T) {
	rec := realHello(t, "x.example.com", nil)
	if _, err := ReadClientHello(bytes.NewReader(rec), 50); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestInvalidSNI(t *testing.T) {
	for _, sni := range []string{"has space.com", "bad\x01name", strings.Repeat("a", 256)} {
		rec := realHello(t, sni, nil)
		// crypto/tls may refuse to send odd names; only assert on what it sent.
		ch, err := ReadClientHello(bytes.NewReader(rec), 0)
		if err == nil {
			t.Errorf("SNI %q accepted as %q", sni, ch.SNI)
		} else if !errors.Is(err, ErrInvalidSNI) {
			t.Errorf("SNI %q: err = %v, want ErrInvalidSNI", sni, err)
		}
	}
}

// Every prefix and every single-byte corruption must be handled without
// panicking.
func TestParseNeverPanics(t *testing.T) {
	rec := realHello(t, "panic.example.com", []string{"tok", "h2"})
	body := rec[9:] // strip record header + handshake header
	for i := 0; i <= len(body); i++ {
		ParseClientHello(body[:i])
	}
	for i := range body {
		for _, v := range []byte{0x00, 0xff, body[i] + 1} {
			m := append([]byte(nil), body...)
			m[i] = v
			ParseClientHello(m)
		}
	}
}

func FuzzReadClientHello(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		ReadClientHello(bytes.NewReader(in), 0)
	})
}
