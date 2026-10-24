package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
)

// isPublishedURL reports whether u is a URL of a CA's published file
// (PublishedURLs) under any base URL: its last path element is
// "<authority ID><ext>".
func isPublishedURL(u, authorityID, ext string) bool {
	i := strings.LastIndex(u, "/")
	return i >= 0 && strings.EqualFold(u[i+1:], authorityID+ext)
}

// ReplacePublished updates a certificate's extensions to point at the
// issuer's published CRL (crl, as mirrors in one distribution point) and
// certificate (cert, as caIssuers entries), for a renewal: distribution
// points and caIssuers entries that name the issuer's published files
// under any base URL are dropped, other entries are kept after the new
// ones. doCDP and doAIA select which extension is updated; with nothing to
// add and nothing left, the extension goes.
func ReplacePublished(exts []pkix.Extension, authorityID string, crl, cert []string, doCDP, doAIA bool) ([]pkix.Extension, error) {
	out := make([]pkix.Extension, 0, len(exts)+2)
	sawCDP, sawAIA := false, false
	for _, e := range exts {
		switch {
		case doCDP && e.Id.Equal(oidCRLDP):
			sawCDP = true
			v, err := replaceCDP(e.Value, authorityID, crl)
			if err != nil {
				return nil, err
			}
			if v != nil {
				out = append(out, pkix.Extension{Id: e.Id, Critical: e.Critical, Value: v})
			}
		case doAIA && e.Id.Equal(oidAIA):
			sawAIA = true
			v, err := replaceAIA(e.Value, authorityID, cert)
			if err != nil {
				return nil, err
			}
			if v != nil {
				out = append(out, pkix.Extension{Id: e.Id, Critical: e.Critical, Value: v})
			}
		default:
			out = append(out, e)
		}
	}
	if doCDP && !sawCDP && len(crl) > 0 {
		v, err := replaceCDP(nil, authorityID, crl)
		if err != nil {
			return nil, err
		}
		out = append(out, pkix.Extension{Id: oidCRLDP, Value: v})
	}
	if doAIA && !sawAIA && len(cert) > 0 {
		v, err := replaceAIA(nil, authorityID, cert)
		if err != nil {
			return nil, err
		}
		out = append(out, pkix.Extension{Id: oidAIA, Value: v})
	}
	return out, nil
}

// replaceCDP returns the CRLDistributionPoints value with the mirrors
// first and the old distribution points that do not name the published
// CRL; nil when nothing is left.
func replaceCDP(old []byte, authorityID string, mirrors []string) ([]byte, error) {
	var body []byte
	if len(mirrors) > 0 {
		var names []asn1.RawValue
		for _, u := range mirrors {
			names = append(names, uriName(u))
		}
		dp, err := distributionPoint(names)
		if err != nil {
			return nil, err
		}
		body = append(body, dp...)
	}
	if old != nil {
		var dps []asn1.RawValue
		if _, err := asn1.Unmarshal(old, &dps); err != nil {
			return nil, err
		}
		for _, dp := range dps {
			if !publishedDP(dp, authorityID) {
				body = append(body, dp.FullBytes...)
			}
		}
	}
	if len(body) == 0 {
		return nil, nil
	}
	return seqOf(body)
}

// publishedDP reports whether a distribution point names nothing but the
// issuer's published CRL.
func publishedDP(dp asn1.RawValue, authorityID string) bool {
	var dpn asn1.RawValue
	if _, err := asn1.Unmarshal(dp.Bytes, &dpn); err != nil || dpn.Class != asn1.ClassContextSpecific || dpn.Tag != 0 {
		return false
	}
	var full asn1.RawValue
	if _, err := asn1.Unmarshal(dpn.Bytes, &full); err != nil || full.Tag != 0 {
		return false
	}
	n := 0
	for rest := full.Bytes; len(rest) > 0; n++ {
		var gn asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &gn); err != nil {
			return false
		}
		if gn.Class != asn1.ClassContextSpecific || gn.Tag != 6 || !isPublishedURL(string(gn.Bytes), authorityID, ".crl") {
			return false
		}
	}
	return n > 0
}

// replaceAIA returns the AuthorityInfoAccess value with caIssuers entries
// for urls first and the old entries except the published certificate's;
// nil when nothing is left.
func replaceAIA(old []byte, authorityID string, urls []string) ([]byte, error) {
	type accessDescription struct {
		Method   asn1.ObjectIdentifier
		Location asn1.RawValue
	}
	var body []byte
	for _, u := range urls {
		b, err := asn1.Marshal(accessDescription{oidCAIssuers, uriName(u)})
		if err != nil {
			return nil, err
		}
		body = append(body, b...)
	}
	if old != nil {
		var ads []asn1.RawValue
		if _, err := asn1.Unmarshal(old, &ads); err != nil {
			return nil, err
		}
		for _, raw := range ads {
			var ad accessDescription
			if _, err := asn1.Unmarshal(raw.FullBytes, &ad); err == nil && ad.Method.Equal(oidCAIssuers) &&
				ad.Location.Class == asn1.ClassContextSpecific && ad.Location.Tag == 6 &&
				isPublishedURL(string(ad.Location.Bytes), authorityID, ".crt") {
				continue
			}
			body = append(body, raw.FullBytes...)
		}
	}
	if len(body) == 0 {
		return nil, nil
	}
	return seqOf(body)
}
