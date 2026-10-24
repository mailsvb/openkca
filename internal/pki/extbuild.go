package pki

import (
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
)

// ExtSpec is the extension part of the certificate editor. Field names and
// encodings follow XCA's template keys (pki_temp), so templates can map onto
// it in phase 5.
type ExtSpec struct {
	CA                                                                                          int    // basicConstraints: 0 not defined, 1 CA:TRUE, 2 CA:FALSE ("ca")
	BCCritical                                                                                  bool   // "bcCritical"
	PathLen                                                                                     string // "basicPath"
	SubKey                                                                                      bool   // subjectKeyIdentifier "hash" ("subKey")
	AuthKey                                                                                     bool   // authorityKeyIdentifier "keyid,issuer" ("authKey")
	KeyUse                                                                                      int    // bit i = KeyUsageNames[i] ("keyUse")
	KUCritical                                                                                  bool   // "kuCritical"
	EKU                                                                                         []string
	EKUCrit                                                                                     bool   // "ekuCritical"
	NameCons                                                                                    string // "nameCons", e.g. "permitted;DNS:.example.org"
	SubAltName                                                                                  string // "subAltName", e.g. "DNS:copycn, IP:192.0.2.1"
	IssAltName                                                                                  string // "issAltName"
	CRLDist                                                                                     string // "crlDist", e.g. "URI:http://crl.example.org/ca.crl"
	AuthInfAcc                                                                                  string // "authInfAcc", e.g. "OCSP;URI:http://ocsp.example.org"
	OCSPStaple                                                                                  bool   // TLS feature status_request ("OCSPstaple")
	NSCertType                                                                                  int    // bit i = NSCertTypeNames[i] ("nsCertType")
	NSComment                                                                                   string // "nsComment"
	NSBaseURL, NSRevocationURL, NSCARevocationURL, NSRenewalURL, NSCAPolicyURL, NSSSLServerName string
	AdvExt                                                                                      string // "adv_ext": further extensions in OpenSSL config syntax

	// CRLMirrors are URLs of one CRL, put as mirrors into one distribution
	// point ahead of CRLDist's (go-ca's published CRL of the issuer).
	CRLMirrors []string
	// CAIssuers are caIssuers URLs put into authorityInfoAccess ahead of
	// AuthInfAcc's (go-ca's published certificate of the issuer).
	CAIssuers []string
}

// PublishedURLs returns where go-ca publishes a CA's CRL and certificate
// (package pubserve) below each base URL, in the base URLs' order.
func PublishedURLs(baseURLs []string, authorityID string) (crl, cert []string) {
	for _, b := range baseURLs {
		b = strings.TrimRight(b, "/")
		crl = append(crl, b+"/"+authorityID+".crl")
		cert = append(cert, b+"/"+authorityID+".crt")
	}
	return crl, cert
}

// uriName is a GeneralName uniformResourceIdentifier.
func uriName(u string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(u)}
}

// distributionPoint encodes a DistributionPoint with a fullName of names.
func distributionPoint(names []asn1.RawValue) ([]byte, error) {
	var gnb []byte
	for _, gn := range names {
		b, err := asn1.Marshal(gn)
		if err != nil {
			return nil, err
		}
		gnb = append(gnb, b...)
	}
	full, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: gnb})
	dpn, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: full})
	return seqOf(dpn)
}

// KeyUsageNames in XCA's (and RFC 5280's bit) order.
var KeyUsageNames = []string{"digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
	"keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"}

// NSCertTypeNames in XCA's list order; nsCertTypeBits maps them to bits.
var NSCertTypeNames = []string{"client", "server", "email", "objsign", "sslCA", "emailCA", "objCA"}
var nsCertTypeBits = []int{0, 1, 2, 3, 5, 6, 7}

// EKUNames are the extended key usages offered in the editor (OpenSSL short names).
var EKUNames = []string{"serverAuth", "clientAuth", "codeSigning", "emailProtection", "timeStamping",
	"OCSPSigning", "ipsecIKE", "msSmartcardLogin", "msEFS", "anyExtendedKeyUsage"}

var ekuOIDs = map[string]asn1.ObjectIdentifier{
	"serverAuth":          {1, 3, 6, 1, 5, 5, 7, 3, 1},
	"clientAuth":          {1, 3, 6, 1, 5, 5, 7, 3, 2},
	"codeSigning":         {1, 3, 6, 1, 5, 5, 7, 3, 3},
	"emailProtection":     {1, 3, 6, 1, 5, 5, 7, 3, 4},
	"timeStamping":        {1, 3, 6, 1, 5, 5, 7, 3, 8},
	"OCSPSigning":         {1, 3, 6, 1, 5, 5, 7, 3, 9},
	"ipsecIKE":            {1, 3, 6, 1, 5, 5, 7, 3, 17},
	"msSmartcardLogin":    {1, 3, 6, 1, 4, 1, 311, 20, 2, 2},
	"msEFS":               {1, 3, 6, 1, 4, 1, 311, 10, 3, 4},
	"anyExtendedKeyUsage": {2, 5, 29, 37, 0},
}

var (
	oidBC        = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidSKI       = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAKI       = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidKU        = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidEKU       = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidNC        = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidSAN       = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidIAN       = asn1.ObjectIdentifier{2, 5, 29, 18}
	oidCRLDP     = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidAIA       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidTLSFeat   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	oidNSType    = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1}
	oidNSBase    = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 2}
	oidNSRev     = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 3}
	oidNSCARev   = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 4}
	oidNSRenew   = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 7}
	oidNSPolicy  = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 8}
	oidNSSSLName = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 12}
	oidNSComment = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 13}
	oidOCSP      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidCAIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
	oidEmailAttr = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	oidCN        = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// ExtContext is what extension values may refer to.
type ExtContext struct {
	SubjectSPKI  []byte // DER SubjectPublicKeyInfo of the new certificate
	Subject      []byte // DER subject name, for DNS:copycn and email:copy
	IssuerSPKI   []byte // signer's public key (self-signed: the subject's)
	IssuerSKI    []byte // signer certificate's subject key identifier
	IssuerName   []byte // signer certificate's issuer name, for AKI issuer
	IssuerSerial *big.Int
	IssuerSAN    []byte // signer's SAN extension value, for issuer:copy
	SelfSigned   bool
	Request      bool // building CSR extensions: no AKI and IAN (as XCA)
	NoNetscape   bool // settings disable_netscape
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func ctxTag(tag int, b []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, Bytes: b}
}

// parseGeneralName parses one "type:value" item in OpenSSL config syntax.
func parseGeneralName(item string, nc bool) (asn1.RawValue, error) {
	typ, val, ok := strings.Cut(item, ":")
	if !ok {
		return asn1.RawValue{}, fmt.Errorf("%q: expected type:value", item)
	}
	typ, val = strings.TrimSpace(typ), strings.TrimSpace(val)
	switch strings.ToLower(typ) {
	case "email":
		return ctxTag(1, []byte(val)), nil
	case "dns":
		return ctxTag(2, []byte(val)), nil
	case "uri":
		return ctxTag(6, []byte(val)), nil
	case "rid":
		oid, err := parseOID(val)
		if err != nil {
			return asn1.RawValue{}, err
		}
		b, _ := asn1.Marshal(oid)
		return ctxTag(8, b[2:]), nil
	case "ip":
		if nc {
			if _, ipnet, err := net.ParseCIDR(val); err == nil {
				ip := ipnet.IP
				if v4 := ip.To4(); v4 != nil {
					ip = v4
				}
				return ctxTag(7, append(append([]byte{}, ip...), ipnet.Mask...)), nil
			}
			if a, m, ok := strings.Cut(val, "/"); ok {
				ip, mask := net.ParseIP(a), net.ParseIP(m)
				if ip != nil && mask != nil {
					if v4 := ip.To4(); v4 != nil && mask.To4() != nil {
						return ctxTag(7, append(append([]byte{}, v4...), mask.To4()...)), nil
					}
					return ctxTag(7, append(append([]byte{}, ip.To16()...), mask.To16()...)), nil
				}
			}
			return asn1.RawValue{}, fmt.Errorf("%q: expected address/mask", item)
		}
		ip := net.ParseIP(val)
		if ip == nil {
			return asn1.RawValue{}, fmt.Errorf("%q: invalid IP address", item)
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		return ctxTag(7, ip), nil
	case "upn": // XCA's short form of otherName:msUPN;UTF8:…
		return otherName(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}, "UTF8:"+val)
	case "othername": // OID;TYPE:value
		o, v, ok := strings.Cut(val, ";")
		if !ok {
			return asn1.RawValue{}, fmt.Errorf("%q: expected otherName:OID;TYPE:value", item)
		}
		oid, err := lookupOID(o)
		if err != nil {
			return asn1.RawValue{}, err
		}
		return otherName(oid, v)
	case "dirname":
		return asn1.RawValue{}, fmt.Errorf("%q: dirName needs a config section; use the advanced extensions", item)
	}
	return asn1.RawValue{}, fmt.Errorf("%q: unknown name type %q", item, typ)
}

func otherName(oid asn1.ObjectIdentifier, typedValue string) (asn1.RawValue, error) {
	v, err := asn1Value(typedValue, 0)
	if err != nil {
		return asn1.RawValue{}, err
	}
	oidDER, _ := asn1.Marshal(oid)
	inner, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: v})
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: append(oidDER, inner...)}, nil
}

func nameValues(der []byte, oid asn1.ObjectIdentifier) []string {
	entries, _ := ParseName(der)
	var out []string
	for _, e := range entries {
		if e.OID == oid.String() {
			out = append(out, e.Value)
		}
	}
	return out
}

// buildGeneralNames builds a GeneralNames body from a config list, expanding
// DNS:copycn, email:copy/email:move and issuer:copy.
func buildGeneralNames(list string, ctx ExtContext) ([]byte, error) {
	var body []byte
	for _, item := range splitList(list) {
		switch strings.ToLower(strings.ReplaceAll(item, " ", "")) {
		case "dns:copycn":
			for _, cn := range nameValues(ctx.Subject, oidCN) {
				b, _ := asn1.Marshal(ctxTag(2, []byte(cn)))
				body = append(body, b...)
			}
			continue
		case "email:copy", "email:move":
			for _, m := range nameValues(ctx.Subject, oidEmailAttr) {
				b, _ := asn1.Marshal(ctxTag(1, []byte(m)))
				body = append(body, b...)
			}
			continue
		case "issuer:copy":
			if len(ctx.IssuerSAN) > 0 {
				var seq asn1.RawValue
				if _, err := asn1.Unmarshal(ctx.IssuerSAN, &seq); err == nil {
					body = append(body, seq.Bytes...)
				}
			}
			continue
		}
		gn, err := parseGeneralName(item, false)
		if err != nil {
			return nil, err
		}
		b, err := asn1.Marshal(gn)
		if err != nil {
			return nil, err
		}
		body = append(body, b...)
	}
	return body, nil
}

func seqOf(body []byte) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
}

// bitString encodes the set bits with trailing zero bits removed (DER).
func bitString(bits []int) asn1.BitString {
	max := -1
	for _, b := range bits {
		if b > max {
			max = b
		}
	}
	if max < 0 {
		return asn1.BitString{}
	}
	bs := asn1.BitString{Bytes: make([]byte, max/8+1), BitLength: max + 1}
	for _, b := range bits {
		bs.Bytes[b/8] |= 0x80 >> (b % 8)
	}
	return bs
}

func keyIDFromSPKI(spkiDER []byte) ([]byte, error) {
	var s spki
	if _, err := asn1.Unmarshal(spkiDER, &s); err != nil {
		return nil, err
	}
	sum := sha1.Sum(s.PublicKey.Bytes)
	return sum[:], nil
}

// BuildExtensions turns the editor's choices into extensions, in the order
// XCA's NewX509::getAllExt produces them. Empty fields produce nothing.
func BuildExtensions(spec ExtSpec, ctx ExtContext) ([]pkix.Extension, error) {
	var out []pkix.Extension
	add := func(oid asn1.ObjectIdentifier, critical bool, val []byte, err error) error {
		if err != nil {
			return err
		}
		out = append(out, pkix.Extension{Id: oid, Critical: critical, Value: val})
		return nil
	}
	// basicConstraints
	if spec.CA == 1 || spec.CA == 2 {
		var bc struct {
			CA      bool `asn1:"optional"`
			PathLen int  `asn1:"optional,default:-1"`
		}
		bc.PathLen = -1
		if spec.CA == 1 {
			bc.CA = true
			if p := strings.TrimSpace(spec.PathLen); p != "" {
				n, err := strconv.Atoi(p)
				if err != nil || n < 0 {
					return nil, fmt.Errorf("path length %q is not a number", p)
				}
				bc.PathLen = n
			}
		}
		v, err := asn1.Marshal(bc)
		if err := add(oidBC, spec.BCCritical, v, err); err != nil {
			return nil, err
		}
	}
	// subjectKeyIdentifier = hash
	if spec.SubKey {
		id, err := keyIDFromSPKI(ctx.SubjectSPKI)
		if err != nil {
			return nil, err
		}
		v, err := asn1.Marshal(id)
		if err := add(oidSKI, false, v, err); err != nil {
			return nil, err
		}
	}
	// authorityKeyIdentifier = keyid,issuer (not for self-signed or requests)
	if spec.AuthKey && !ctx.SelfSigned && !ctx.Request {
		var aki struct {
			KeyID  []byte        `asn1:"optional,tag:0"`
			Issuer asn1.RawValue `asn1:"optional,tag:1"`
			Serial *big.Int      `asn1:"optional,tag:2"`
		}
		aki.KeyID = ctx.IssuerSKI
		if len(aki.KeyID) == 0 && len(ctx.IssuerSPKI) > 0 {
			aki.KeyID, _ = keyIDFromSPKI(ctx.IssuerSPKI)
		}
		if len(aki.KeyID) == 0 && len(ctx.IssuerName) > 0 { // "issuer" only when no keyid
			dir, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: ctx.IssuerName})
			aki.Issuer = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: dir}
			aki.Serial = ctx.IssuerSerial
		}
		v, err := asn1.Marshal(aki)
		if err := add(oidAKI, false, v, err); err != nil {
			return nil, err
		}
	}
	// keyUsage
	if spec.KeyUse != 0 {
		var bits []int
		for i := range KeyUsageNames {
			if spec.KeyUse&(1<<i) != 0 {
				bits = append(bits, i)
			}
		}
		v, err := asn1.Marshal(bitString(bits))
		if err := add(oidKU, spec.KUCritical, v, err); err != nil {
			return nil, err
		}
	}
	// extendedKeyUsage
	if len(spec.EKU) > 0 {
		var oids []asn1.ObjectIdentifier
		for _, n := range spec.EKU {
			o, err := lookupOID(n)
			if err != nil {
				return nil, fmt.Errorf("unknown extended key usage %q", n)
			}
			oids = append(oids, o)
		}
		v, err := asn1.Marshal(oids)
		if err := add(oidEKU, spec.EKUCrit, v, err); err != nil {
			return nil, err
		}
	}
	// nameConstraints
	if strings.TrimSpace(spec.NameCons) != "" {
		v, err := nameConstraints(spec.NameCons)
		if err := add(oidNC, true, v, err); err != nil {
			return nil, err
		}
	}
	// subjectAltName, issuerAltName
	for _, x := range []struct {
		oid  asn1.ObjectIdentifier
		list string
		skip bool
	}{{oidSAN, spec.SubAltName, false}, {oidIAN, spec.IssAltName, ctx.Request}} {
		if x.skip || strings.TrimSpace(x.list) == "" {
			continue
		}
		body, err := buildGeneralNames(x.list, ctx)
		if err != nil {
			return nil, err
		}
		if len(body) == 0 { // e.g. DNS:copycn without a CN
			continue
		}
		v, err := seqOf(body)
		if err := add(x.oid, false, v, err); err != nil {
			return nil, err
		}
	}
	// crlDistributionPoints: the mirrors as one distribution point, then
	// one distribution point per CRLDist entry, as OpenSSL
	if len(spec.CRLMirrors) > 0 || strings.TrimSpace(spec.CRLDist) != "" {
		var dps []byte
		if len(spec.CRLMirrors) > 0 {
			var names []asn1.RawValue
			for _, u := range spec.CRLMirrors {
				names = append(names, uriName(u))
			}
			dp, err := distributionPoint(names)
			if err != nil {
				return nil, err
			}
			dps = append(dps, dp...)
		}
		for _, item := range splitList(spec.CRLDist) {
			gn, err := parseGeneralName(item, false)
			if err != nil {
				return nil, err
			}
			dp, err := distributionPoint([]asn1.RawValue{gn})
			if err != nil {
				return nil, err
			}
			dps = append(dps, dp...)
		}
		v, err := seqOf(dps)
		if err := add(oidCRLDP, false, v, err); err != nil {
			return nil, err
		}
	}
	// authorityInfoAccess: the caIssuers URLs, then "OCSP;URI:…, caIssuers;URI:…"
	if len(spec.CAIssuers) > 0 || strings.TrimSpace(spec.AuthInfAcc) != "" {
		var ads []byte
		for _, u := range spec.CAIssuers {
			ad, err := asn1.Marshal(struct {
				Method   asn1.ObjectIdentifier
				Location asn1.RawValue
			}{oidCAIssuers, uriName(u)})
			if err != nil {
				return nil, err
			}
			ads = append(ads, ad...)
		}
		for _, item := range splitList(spec.AuthInfAcc) {
			method, loc, ok := strings.Cut(item, ";")
			if !ok {
				return nil, fmt.Errorf("%q: expected method;type:value", item)
			}
			var m asn1.ObjectIdentifier
			switch strings.ToLower(strings.TrimSpace(method)) {
			case "ocsp":
				m = oidOCSP
			case "caissuers":
				m = oidCAIssuers
			default:
				var err error
				if m, err = parseOID(strings.TrimSpace(method)); err != nil {
					return nil, fmt.Errorf("%q: unknown access method", item)
				}
			}
			gn, err := parseGeneralName(loc, false)
			if err != nil {
				return nil, err
			}
			ad, err := asn1.Marshal(struct {
				Method   asn1.ObjectIdentifier
				Location asn1.RawValue
			}{m, gn})
			if err != nil {
				return nil, err
			}
			ads = append(ads, ad...)
		}
		v, err := seqOf(ads)
		if err := add(oidAIA, false, v, err); err != nil {
			return nil, err
		}
	}
	// TLS feature status_request (OCSP must-staple)
	if spec.OCSPStaple {
		v, err := asn1.Marshal([]int{5})
		if err := add(oidTLSFeat, false, v, err); err != nil {
			return nil, err
		}
	}
	adv, err := BuildAdvanced(spec.AdvExt, ctx)
	if err != nil {
		return nil, err
	}
	out = append(out, adv...)
	if !ctx.NoNetscape {
		if spec.NSCertType != 0 {
			var bits []int
			for i := range NSCertTypeNames {
				if spec.NSCertType&(1<<i) != 0 {
					bits = append(bits, nsCertTypeBits[i])
				}
			}
			v, err := asn1.Marshal(bitString(bits))
			if err := add(oidNSType, false, v, err); err != nil {
				return nil, err
			}
		}
		for _, x := range []struct {
			oid asn1.ObjectIdentifier
			val string
		}{{oidNSBase, spec.NSBaseURL}, {oidNSRev, spec.NSRevocationURL}, {oidNSCARev, spec.NSCARevocationURL},
			{oidNSRenew, spec.NSRenewalURL}, {oidNSPolicy, spec.NSCAPolicyURL}, {oidNSSSLName, spec.NSSSLServerName},
			{oidNSComment, spec.NSComment}} {
			if strings.TrimSpace(x.val) == "" {
				continue
			}
			v, err := asn1.MarshalWithParams(x.val, "ia5")
			if err := add(x.oid, false, v, err); err != nil {
				return nil, err
			}
		}
	}
	seen := map[string]bool{}
	for _, e := range out {
		if seen[e.Id.String()] {
			name := extNames[e.Id.String()]
			if name == "" {
				name = e.Id.String()
			}
			return nil, fmt.Errorf("the extension %s is defined twice", name)
		}
		seen[e.Id.String()] = true
	}
	return out, nil
}

func nameConstraints(list string) ([]byte, error) {
	var permitted, excluded []byte
	for _, item := range splitList(list) {
		kind, gnText, ok := strings.Cut(item, ";")
		if !ok {
			return nil, fmt.Errorf("%q: expected permitted;… or excluded;…", item)
		}
		gn, err := parseGeneralName(gnText, true)
		if err != nil {
			return nil, err
		}
		gnb, _ := asn1.Marshal(gn)
		sub, _ := seqOf(gnb) // GeneralSubtree { base }
		switch strings.ToLower(strings.TrimSpace(kind)) {
		case "permitted":
			permitted = append(permitted, sub...)
		case "excluded":
			excluded = append(excluded, sub...)
		default:
			return nil, fmt.Errorf("%q: expected permitted or excluded", item)
		}
	}
	var body []byte
	if len(permitted) > 0 {
		b, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: permitted})
		body = append(body, b...)
	}
	if len(excluded) > 0 {
		b, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: excluded})
		body = append(body, b...)
	}
	if len(body) == 0 {
		return nil, errors.New("empty name constraints")
	}
	return seqOf(body)
}
