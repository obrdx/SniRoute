// Package link builds and parses the single-string onboarding link the server
// menu hands out. One paste is all a client needs: control URL, certificate
// pin, one-time registration token and the labels to record.
//
// The token and the pin live in the URL fragment, so a browser or proxy that
// the operator clicks through never sees them: fragments are not sent in the
// request. That also keeps them out of any access log on the way.
package link

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Path is the informational page the link points at. Opening the link in a
// browser shows the same instructions, since the fragment is never sent and
// the server cannot act on it anyway.
const Path = "/join"

// Link is a decoded onboarding link.
type Link struct {
	Server string // control service URL, e.g. https://observer.example.com:8443
	Pin    string // SHA-256 of the control certificate (empty when a CA-issued cert is used)
	Token  string // one-time registration token
	Name   string // node name to register with (optional)
	Label  string // provider label (optional)
}

// Build returns the onboarding link for l. Server must be a plain
// https://host:port base; anything else is rejected so a link is never built
// from an address a client would refuse.
func Build(l Link) (string, error) {
	base, err := NormalizeServer(l.Server)
	if err != nil {
		return "", err
	}
	var parts []string
	for _, s := range []string{l.Token, l.Pin, b64(l.Name), b64(l.Label)} {
		if strings.Contains(s, ".") {
			return "", errors.New("link fields must not contain '.'")
		}
		parts = append(parts, s)
	}
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 {
		return base + Path, nil
	}
	return base + Path + "#" + strings.Join(parts, "."), nil
}

// Parse accepts an onboarding link, a bare server URL, or just host:port.
// Everything after '#' is decoded locally; without a fragment the result only
// carries the server address, which is what an already-registered client
// needs when the operator moves it to a new observer.
func Parse(s string) (Link, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Link{}, errors.New("empty link")
	}
	// A scheme-less "host:port" is a common paste; https is the only scheme
	// this tool speaks.
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	var frag string
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s, frag = s[:i], s[i+1:]
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 && strings.HasSuffix(s[:i], Path) {
		s = s[:i]
	}
	if strings.HasSuffix(strings.TrimRight(s, "/"), Path) {
		s = strings.TrimSuffix(strings.TrimRight(s, "/"), Path)
	}
	base, err := NormalizeServer(s)
	if err != nil {
		return Link{}, err
	}
	out := Link{Server: base}
	if frag == "" {
		return out, nil
	}
	f := strings.Split(frag, ".")
	get := func(i int) string {
		if i < len(f) {
			return f[i]
		}
		return ""
	}
	out.Token = get(0)
	out.Pin = strings.ToLower(get(1))
	if out.Pin != "" && (len(out.Pin) != 64 || !isHex(out.Pin)) {
		return Link{}, errors.New("certificate pin must be 64 hex characters")
	}
	if out.Name, err = unb64(get(2)); err != nil {
		return Link{}, fmt.Errorf("node name: %w", err)
	}
	if out.Label, err = unb64(get(3)); err != nil {
		return Link{}, fmt.Errorf("provider label: %w", err)
	}
	return out, nil
}

// NormalizeServer validates a control URL and returns it without a trailing
// slash. Only https:// is accepted: the control channel carries the node key
// and the probe pin.
func NormalizeServer(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("server address is empty")
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("server address: %w", err)
	}
	if u.Scheme != "https" {
		return "", errors.New("server address must start with https://")
	}
	if u.Host == "" {
		return "", errors.New("server address needs a host and port, e.g. https://observer.example.com:8443")
	}
	if u.Port() == "" {
		return "", errors.New("server address needs an explicit port (the control service defaults to 8443)")
	}
	if u.Path != "" && u.Path != "/" && u.Path != Path {
		return "", errors.New("server address must not have a path")
	}
	if u.User != nil || u.RawQuery != "" {
		return "", errors.New("server address must not carry credentials or a query")
	}
	return "https://" + u.Host, nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func unb64(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", errors.New("not valid base64url")
	}
	return string(b), nil
}
