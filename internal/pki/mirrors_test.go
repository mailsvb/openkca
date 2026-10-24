package pki

import (
	"encoding/asn1"
	"strings"
	"testing"
)

func TestPublishedURLs(t *testing.T) {
	crl, cert := PublishedURLs([]string{"http://a.example", "http://b.lan:8080/pki/"}, "abc")
	if strings.Join(crl, " ") != "http://a.example/abc.crl http://b.lan:8080/pki/abc.crl" ||
		strings.Join(cert, " ") != "http://a.example/abc.crt http://b.lan:8080/pki/abc.crt" {
		t.Fatalf("%v %v", crl, cert)
	}
	if crl, cert := PublishedURLs(nil, "abc"); crl != nil || cert != nil {
		t.Fatal("no base URLs")
	}
}

// TestMirrorExtensions: the mirrors are one distribution point with two
// names, followed by the free-text entries as distribution points of
// their own; caIssuers URLs come before the free-text AIA entries.
func TestMirrorExtensions(t *testing.T) {
	spec := ExtSpec{
		CRLMirrors: []string{"http://ext.example/x.crl", "http://int.lan/x.crl"},
		CRLDist:    "URI:http://other.example/y.crl",
		CAIssuers:  []string{"http://ext.example/x.crt", "http://int.lan/x.crt"},
		AuthInfAcc: "OCSP;URI:http://ocsp.example",
	}
	exts, err := BuildExtensions(spec, ExtContext{})
	if err != nil {
		t.Fatal(err)
	}
	var cdp, aia []byte
	for _, e := range exts {
		switch {
		case e.Id.Equal(oidCRLDP):
			cdp = e.Value
		case e.Id.Equal(oidAIA):
			aia = e.Value
		}
	}
	// DistributionPoint ::= SEQUENCE { distributionPoint [0] { fullName [0] GeneralNames } }
	var dps []asn1.RawValue
	if _, err := asn1.Unmarshal(cdp, &dps); err != nil || len(dps) != 2 {
		t.Fatalf("distribution points %d: %v", len(dps), err)
	}
	names := func(dp asn1.RawValue) []string {
		var dpn, full asn1.RawValue
		asn1.Unmarshal(dp.Bytes, &dpn)
		asn1.Unmarshal(dpn.Bytes, &full)
		var out []string
		for rest := full.Bytes; len(rest) > 0; {
			var gn asn1.RawValue
			rest, _ = asn1.Unmarshal(rest, &gn)
			if gn.Tag != 6 {
				t.Fatalf("name tag %d", gn.Tag)
			}
			out = append(out, string(gn.Bytes))
		}
		return out
	}
	if got := names(dps[0]); strings.Join(got, " ") != "http://ext.example/x.crl http://int.lan/x.crl" {
		t.Fatalf("mirrors %v", got)
	}
	if got := names(dps[1]); strings.Join(got, " ") != "http://other.example/y.crl" {
		t.Fatalf("free-text point %v", got)
	}
	var ads []struct {
		Method   asn1.ObjectIdentifier
		Location asn1.RawValue
	}
	if _, err := asn1.Unmarshal(aia, &ads); err != nil || len(ads) != 3 {
		t.Fatalf("access descriptions %d: %v", len(ads), err)
	}
	if !ads[0].Method.Equal(oidCAIssuers) || string(ads[0].Location.Bytes) != "http://ext.example/x.crt" ||
		!ads[1].Method.Equal(oidCAIssuers) || string(ads[1].Location.Bytes) != "http://int.lan/x.crt" ||
		!ads[2].Method.Equal(oidOCSP) {
		t.Fatalf("AIA %+v", ads)
	}
	// Without any of them, neither extension.
	exts, _ = BuildExtensions(ExtSpec{}, ExtContext{})
	for _, e := range exts {
		if e.Id.Equal(oidCRLDP) || e.Id.Equal(oidAIA) {
			t.Fatal("empty spec built CDP or AIA")
		}
	}
}
