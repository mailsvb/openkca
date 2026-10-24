package pkcs12

import (
	"hash"
	"unicode/utf16"
)

// Diversifiers of the PKCS#12 key derivation (RFC 7292 B.3).
const (
	idKey byte = 1
	idIV  byte = 2
	idMAC byte = 3
)

// deriveKey is the PKCS#12 key derivation of RFC 7292 Appendix B.2 with
// the hash h. password is the BMPString form, terminator included.
func deriveKey(h func() hash.Hash, id byte, password, salt []byte, iterations, size int) []byte {
	d := h()
	u, v := d.Size(), d.BlockSize()
	D := make([]byte, v)
	for i := range D {
		D[i] = id
	}
	I := append(fill(salt, v), fill(password, v)...)
	defer clear(I)
	c := (size + u - 1) / u
	out := make([]byte, 0, c*u)
	var A []byte
	for i := 0; i < c; i++ {
		d.Reset()
		d.Write(D)
		d.Write(I)
		A = d.Sum(A[:0])
		for j := 1; j < iterations; j++ {
			d.Reset()
			d.Write(A)
			A = d.Sum(A[:0])
		}
		out = append(out, A...)
		if i == c-1 {
			break
		}
		// I_j = (I_j + B + 1) mod 2^(8v), B being A repeated to v bytes
		B := fill(A, v)
		for j := 0; j < len(I); j += v {
			carry := 1
			for k := v - 1; k >= 0; k-- {
				sum := int(I[j+k]) + int(B[k]) + carry
				I[j+k] = byte(sum)
				carry = sum >> 8
			}
		}
	}
	clear(A)
	return out[:size]
}

// fill repeats pattern to a multiple of v bytes, at least len(pattern).
func fill(pattern []byte, v int) []byte {
	if len(pattern) == 0 {
		return nil
	}
	out := make([]byte, v*((len(pattern)+v-1)/v))
	for i := range out {
		out[i] = pattern[i%len(pattern)]
	}
	return out
}

// password is a PKCS#12 password in the two encodings a file uses: the
// zero terminated BMPString of the PKCS#12 derivation (RFC 7292 B.1) and
// UTF-8 for PBES2 and PBMAC1 (RFC 9579), as OpenSSL and Windows use it.
type password struct {
	bmp, utf8 []byte
}

// newPassword encodes s. Characters outside the BMP become surrogate
// pairs, as OpenSSL's OPENSSL_utf82uni writes them.
func newPassword(s string) password {
	u := utf16.Encode([]rune(s))
	bmp := make([]byte, 0, 2*len(u)+2)
	for _, c := range u {
		bmp = append(bmp, byte(c>>8), byte(c))
	}
	return password{bmp: append(bmp, 0, 0), utf8: []byte(s)}
}

// emptyPasswords are the forms of the empty password: a lone terminator
// (OpenSSL, go-pkcs12) or no bytes at all (some other software).
func emptyPasswords() []password {
	return []password{newPassword(""), {utf8: []byte{}}}
}

func (p password) clear() {
	clear(p.bmp)
	clear(p.utf8)
}
