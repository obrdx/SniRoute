package link

import (
	"strings"
	"testing"
)

func TestBuildParseRoundTrip(t *testing.T) {
	l := Link{
		Server: "https://observer.example.com:8443", Pin: strings.Repeat("ab", 32),
		Token: "reg_" + strings.Repeat("A", 43), Name: "vps-东京", Label: "Provider X",
	}
	s, err := Build(l)
	if err != nil {
		t.Fatal(err)
	}
	// The secrets ride in the fragment so no browser or proxy sees them.
	if !strings.Contains(s, "/join#") || strings.Contains(strings.Split(s, "#")[0], l.Token) {
		t.Fatalf("token is not confined to the fragment: %s", s)
	}
	back, err := Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	if back.Server != l.Server || back.Pin != l.Pin || back.Token != l.Token || back.Name != l.Name || back.Label != l.Label {
		t.Fatalf("round trip =\n%+v\nwant\n%+v", back, l)
	}
}

func TestParseAcceptsTheShapesPeoplePaste(t *testing.T) {
	cases := []struct{ in, server string }{
		{"https://h.example:8443/join#tok", "https://h.example:8443"},
		{"https://h.example:8443", "https://h.example:8443"},
		{"https://h.example:8443/", "https://h.example:8443"},
		{"h.example:8443", "https://h.example:8443"},
		{"  198.51.100.9:8443/join  ", "https://198.51.100.9:8443"},
	}
	for _, c := range cases {
		l, err := Parse(c.in)
		if err != nil || l.Server != c.server {
			t.Errorf("%q: %q %v", c.in, l.Server, err)
		}
	}
	// A fragment without a pin leaves the pin empty, not invalid.
	if l, err := Parse("https://h.example:8443/join#tok"); err != nil || l.Token != "tok" || l.Pin != "" {
		t.Errorf("token only: %+v %v", l, err)
	}
	if l, err := Parse("https://h.example:8443/join#tok." + strings.Repeat("cd", 32) + ".dnBzLTE"); err != nil || l.Token != "tok" || l.Name != "vps-1" {
		t.Errorf("full: %+v %v", l, err)
	}
}

func TestParseRejectsUnsafeAddresses(t *testing.T) {
	for _, in := range []string{
		"",
		"http://h.example:8443",             // not TLS
		"https://h.example",                 // no port: ambiguous
		"https://h.example:8443/api/x",      // a path is not a control base
		"https://user:pw@h.example:8443",    // credentials must not travel in a link
		"https://h.example:8443/?x=1",       // query
		"https://h.example:8443/join#t.bad", // bad pin
		"https://h.example:8443/join#t.zz",  // short pin
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("%q: accepted", in)
		}
	}
}

func TestBuildRequiresNormalisedFields(t *testing.T) {
	if _, err := Build(Link{Server: "h.example:8443"}); err == nil {
		t.Error("scheme-less server accepted")
	}
	// A '.' in a raw field would split the fragment at the wrong place. Names
	// and labels are base64url encoded, so they cannot introduce one.
	if _, err := Build(Link{Server: "https://h.example:8443", Token: "a.b"}); err == nil {
		t.Error("dot in token accepted")
	}
	sd, err := Build(Link{Server: "https://h.example:8443", Token: "t", Name: "has.dot", Label: "a.b"})
	if err != nil {
		t.Fatalf("dotted name should be encoded, not rejected: %v", err)
	}
	if back, err := Parse(sd); err != nil || back.Name != "has.dot" || back.Label != "a.b" {
		t.Errorf("dotted names: %+v %v", back, err)
	}
	// Empty fields are simply omitted.
	bare, err := Build(Link{Server: "https://h.example:8443"})
	if err != nil || bare != "https://h.example:8443/join" {
		t.Errorf("bare link = %q %v", bare, err)
	}
}
