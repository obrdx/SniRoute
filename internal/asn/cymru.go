package asn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Cymru uses Team Cymru's IP-to-ASN mapping over DNS TXT records: the origin
// zone maps an address to ASN(s) and prefix, and AS<n>.asn.cymru.com maps an
// ASN to its name.
type Cymru struct {
	// LookupTXT resolves a TXT name; default is the system resolver.
	LookupTXT func(ctx context.Context, name string) ([]string, error)
	Timeout   time.Duration
}

// NewCymru creates a provider using the system resolver.
func NewCymru() *Cymru {
	return &Cymru{LookupTXT: net.DefaultResolver.LookupTXT, Timeout: 8 * time.Second}
}

// Name implements Provider.
func (c *Cymru) Name() string { return "cymru" }

// originName builds the query name: reversed octets under origin.asn.cymru.com,
// or reversed nibbles under origin6.asn.cymru.com.
func originName(ip netip.Addr) string {
	ip = ip.Unmap()
	if ip.Is4() {
		b := ip.As4()
		return strconv.Itoa(int(b[3])) + "." + strconv.Itoa(int(b[2])) + "." + strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[0])) + ".origin.asn.cymru.com"
	}
	const hexd = "0123456789abcdef"
	b := ip.As16()
	var sb strings.Builder
	for i := 15; i >= 0; i-- {
		sb.WriteByte(hexd[b[i]&0xf])
		sb.WriteByte('.')
		sb.WriteByte(hexd[b[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("origin6.asn.cymru.com")
	return sb.String()
}

func fields(txt string) []string {
	parts := strings.Split(txt, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func isNotFound(err error) bool {
	var d *net.DNSError
	return errors.As(err, &d) && d.IsNotFound
}

func (c *Cymru) txt(ctx context.Context, name string) ([]string, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	lookup := c.LookupTXT
	if lookup == nil {
		lookup = net.DefaultResolver.LookupTXT
	}
	out, err := lookup(ctx, name)
	if err != nil {
		var d *net.DNSError
		switch {
		case isNotFound(err):
			return nil, err
		case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &d) && d.IsTimeout):
			return nil, &LookupError{KindTimeout, "dns"}
		}
		return nil, &LookupError{KindUnavailable, "dns: " + clamp(err.Error(), 120)}
	}
	return out, nil
}

// Lookup implements Provider.
func (c *Cymru) Lookup(ctx context.Context, ip netip.Addr) (*Info, error) {
	recs, err := c.txt(ctx, originName(ip))
	info := &Info{IP: ip.Unmap().String(), Source: c.Name(), Status: StatusOK, ASNs: []Number{}}
	if err != nil {
		if isNotFound(err) {
			info.Status = StatusNoData
			return info, nil
		}
		return nil, err
	}
	// A single answer holds "ASNs | prefix | CC | registry | allocated"; the
	// ASN field can list several origins separated by spaces.
	seen := map[int]bool{}
	for _, r := range recs {
		f := fields(r)
		if len(f) < 2 {
			return nil, &LookupError{KindBadResponse, "unexpected origin record"}
		}
		if info.Prefix == "" {
			info.Prefix = clamp(f[1], 64)
		}
		for _, a := range strings.Fields(f[0]) {
			n, e := strconv.Atoi(a)
			if e != nil || n <= 0 {
				return nil, &LookupError{KindBadResponse, "unparseable ASN"}
			}
			if !seen[n] && len(info.ASNs) < 4 {
				seen[n] = true
				info.ASNs = append(info.ASNs, Number{ASN: n})
			}
		}
	}
	if len(info.ASNs) == 0 {
		info.Status = StatusNoData
		return info, nil
	}
	for i := range info.ASNs {
		names, err := c.txt(ctx, "AS"+strconv.Itoa(info.ASNs[i].ASN)+".asn.cymru.com")
		if err != nil || len(names) == 0 {
			info.Error = "name lookup failed"
			continue
		}
		if f := fields(names[0]); len(f) >= 5 {
			info.ASNs[i].Name = clamp(f[4], 200)
		}
	}
	return info, nil
}
