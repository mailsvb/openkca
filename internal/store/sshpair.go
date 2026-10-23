package store

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"path"
	"strings"
	"time"
)

// sshPair names the export formats of one SSH key pair download.
type sshPair struct {
	plain, crypt, pub int    // export format IDs
	privExt, pubExt   string // file name extensions in the archive
}

// sshPairs are the key pair downloads: OpenSSH (id_ed25519 and
// id_ed25519.pub, as ssh-keygen names them), and PuTTY's private key file
// with the RFC 4716 public key PuTTYgen saves next to it.
var sshPairs = map[string]sshPair{
	"openssh": {100, 101, 23, "", ".pub"},
	"putty":   {102, 103, 106, ".ppk", ".pub"},
	"putty2":  {104, 105, 106, ".ppk", ".pub"},
}

// SSHPair exports a key's private and public part as a ZIP archive, in the
// SSH format flavor ("openssh", "putty" or "putty2"). req selects one key;
// its Password, when set, encrypts the private key.
func (h *Handle) SSHPair(ctx context.Context, flavor string, req ExportRequest) (*ExportResult, error) {
	p, ok := sshPairs[flavor]
	if !ok {
		return nil, errors.New("unknown SSH key format")
	}
	if len(req.IDs) != 1 {
		return nil, errors.New("select exactly one key")
	}
	req.Format = p.plain
	if len(req.Password) > 0 {
		req.Format = p.crypt
	}
	priv, err := h.Export(ctx, req)
	if err != nil {
		return nil, err
	}
	req.Format = p.pub
	pub, err := h.Export(ctx, req)
	if err != nil {
		return nil, err
	}
	base := strings.TrimSuffix(priv.Filename, path.Ext(priv.Filename))
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	now := time.Now()
	for _, f := range []struct {
		name string
		data []byte
	}{{base + p.privExt, priv.Data}, {base + p.pubExt, pub.Data}} {
		w, err := z.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Deflate, Modified: now})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(f.data); err != nil {
			return nil, err
		}
	}
	clear(priv.Data)
	if err := z.Close(); err != nil {
		return nil, err
	}
	return &ExportResult{Filename: base + ".zip", ContentType: "application/zip", Data: buf.Bytes()}, nil
}
