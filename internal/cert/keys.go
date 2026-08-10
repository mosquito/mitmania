// Package cert implements mitmania's certificate machinery: the root CA,
// deterministic leaf/intermediate/ssh key derivation, cert cloning, and the
// on-disk leaf cache.
package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// infoLeaf/infoIntermediate/infoSSH are HKDF's "info" context strings for
// deterministic key derivation — part of the key-derivation input, not
// just labels, so changing them (e.g. a future project rename) changes
// every derived key: any cluster that already derived keys under the old
// strings gets *different* keys after upgrading, since HKDF's info
// parameter feeds directly into the output. Not a concern pre-deployment,
// but worth knowing if this ever ran for real.
const (
	infoLeaf         = "mitmania/leaf/p256/v1"
	infoIntermediate = "mitmania/intermediate/p256/v1"
	infoSSH          = "mitmania/ssh/hostkey/v1"

	hkdfOutputLen = 48 // L=48, the HKDF output length fed into the scalar derivation below
)

// DetKeyDeriver derives deterministic ECDSA P-256 keys from a cluster key.
// The same clusterKey + same salt always yields the same key, on every
// node.
type DetKeyDeriver struct {
	ClusterKey []byte
}

// LeafKey derives the deterministic key for a leaf certificate whose
// canonical identity is its SAN set: salt = SHA256(sorted type-tagged
// SANs). sans must already be type-tagged ("dns:…"/"ip:…",
// see tagSANs/typeTaggedSANStrings in clone.go) — LeafKey itself is
// agnostic to the tagging convention, it just sorts+hashes whatever it's
// given, but every caller must agree on the same encoding or a cache hit
// and a fresh key derivation would disagree.
func (d DetKeyDeriver) LeafKey(sans []string) (*ecdsa.PrivateKey, error) {
	return deriveKey(d.ClusterKey, leafSalt(sans), infoLeaf)
}

// IntermediateKey derives the deterministic key for an intermediate
// certificate. Intermediates typically have no SAN set to key off of, so
// we salt on the real intermediate's issuer+serial instead, reusing the
// same bytes as serialFor's clone-serial formula (clone.go) so it's
// guaranteed unique per real intermediate.
func (d DetKeyDeriver) IntermediateKey(rawIssuer []byte, serial *big.Int) (*ecdsa.PrivateKey, error) {
	return deriveKey(d.ClusterKey, issuerSerialHash(rawIssuer, serial), infoIntermediate)
}

// SSHHostKey derives the deterministic key for an SSH host, salted on
// "host:port". Not used by the in-scope explicit-proxy path; exposed for
// a possible future SSH man-in-the-middle mode.
func (d DetKeyDeriver) SSHHostKey(hostport string) (*ecdsa.PrivateKey, error) {
	salt := sha256.Sum256([]byte(hostport))
	return deriveKey(d.ClusterKey, salt[:], infoSSH)
}

// leafSalt computes SHA256(sorted SANs), joining the sorted SAN list with
// a NUL separator so no ordering/concatenation ambiguity exists. Callers
// pass already type-tagged SANs (see LeafKey).
func leafSalt(sans []string) []byte {
	sorted := append([]string(nil), sans...)
	sort.Strings(sorted)
	h := sha256.Sum256([]byte(strings.Join(sorted, "\x00")))
	return h[:]
}

// issuerSerialHash computes SHA256(realIssuerDN || realSerial), the byte
// sequence shared by serialFor's clone-serial formula (clone.go) and the
// intermediate key salt.
func issuerSerialHash(rawIssuer []byte, serial *big.Int) []byte {
	h := sha256.New()
	h.Write(rawIssuer)
	h.Write(serial.Bytes())
	return h.Sum(nil)
}

// deriveKey implements the HKDF-based scalar derivation:
//
//	d = (HKDF(ikm=clusterKey, salt, info, L=48) mod (n-1)) + 1
func deriveKey(clusterKey, salt []byte, info string) (*ecdsa.PrivateKey, error) {
	curve := elliptic.P256()

	prk, err := hkdf.Extract(sha256.New, clusterKey, salt)
	if err != nil {
		return nil, fmt.Errorf("cert: hkdf extract: %w", err)
	}
	okm, err := hkdf.Expand(sha256.New, prk, info, hkdfOutputLen)
	if err != nil {
		return nil, fmt.Errorf("cert: hkdf expand: %w", err)
	}

	n := curve.Params().N
	nMinus1 := new(big.Int).Sub(n, big.NewInt(1))
	d := new(big.Int).SetBytes(okm)
	d.Mod(d, nMinus1)
	d.Add(d, big.NewInt(1)) // d in [1, n-1]

	// ParseRawPrivateKey requires a fixed-length big-endian encoding (32
	// bytes for P-256); FillBytes left-pads, d.Bytes() alone would not for
	// the fraction of scalars whose top byte(s) are zero.
	raw := make([]byte, 32)
	d.FillBytes(raw)

	priv, err := ecdsa.ParseRawPrivateKey(curve, raw)
	if err != nil {
		return nil, fmt.Errorf("cert: parse derived key: %w", err)
	}
	return priv, nil
}
