package cert

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net"
)

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// cloneTemplate builds a synthetic certificate template from a real
// certificate as an allow-list copy — Subject, full SAN set (verbatim
// raw extension bytes, so order is preserved exactly), validity
// (NotBefore/NotAfter), KeyUsage, ExtKeyUsage, BasicConstraints — into a
// fresh x509.Certificate{}. Nothing outside this list is ever copied, so
// embedded SCTs / AIA-OCSP / CRLDP are absent by construction, not by
// active stripping. SubjectKeyId/AuthorityKeyId are left unset: signing
// root→...→leaf in order lets x509.CreateCertificate compute both.
func cloneTemplate(real *x509.Certificate) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber:          serialFor(real),
		Subject:               real.Subject,
		NotBefore:             real.NotBefore,
		NotAfter:              real.NotAfter,
		KeyUsage:              real.KeyUsage,
		ExtKeyUsage:           append([]x509.ExtKeyUsage(nil), real.ExtKeyUsage...),
		UnknownExtKeyUsage:    append([]asn1.ObjectIdentifier(nil), real.UnknownExtKeyUsage...),
		BasicConstraintsValid: real.BasicConstraintsValid,
		IsCA:                  real.IsCA,
		MaxPathLen:            real.MaxPathLen,
		MaxPathLenZero:        real.MaxPathLenZero,
	}
	if real.IsCA {
		// Intermediates copy CA constraints verbatim: BasicConstraints
		// CA:true, KeyUsage certSign (real.KeyUsage should already carry
		// this, but a defensive OR costs nothing).
		tmpl.BasicConstraintsValid = true
		tmpl.IsCA = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	if san := findExtension(real.Extensions, oidSubjectAltName); san != nil {
		// ExtraExtensions values override anything x509.CreateCertificate
		// would otherwise derive from DNSNames/IPAddresses/etc, and are
		// copied byte-for-byte — the simplest way to guarantee "order
		// preserved" across interleaved SAN types.
		tmpl.ExtraExtensions = []pkix.Extension{*san}
	}
	return tmpl
}

func findExtension(exts []pkix.Extension, oid asn1.ObjectIdentifier) *pkix.Extension {
	for i := range exts {
		if exts[i].Id.Equal(oid) {
			return &exts[i]
		}
	}
	return nil
}

// serialFor computes serial = trunc160(SHA256(realIssuerDN || realSerial))
// — cross-node stable, unique under our issuer.
func serialFor(real *x509.Certificate) *big.Int {
	sum := issuerSerialHash(real.RawIssuer, real.SerialNumber)
	return new(big.Int).SetBytes(sum[:20]) // trunc160
}

// SANStrings flattens a certificate's SAN set into the canonical untagged
// string form used by the operator-facing names/ index in the leaf cache —
// a human/API-facing lookup by exact name, where "dns:"/"ip:" prefixes would
// just be noise. NOT used for key derivation any more (see
// typeTaggedSANStrings) since an untagged string can't distinguish a
// DNSName that happens to look like an IP literal from an actual IP SAN.
func SANStrings(c *x509.Certificate) []string {
	var out []string
	out = append(out, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	out = append(out, c.EmailAddresses...)
	for _, u := range c.URIs {
		out = append(out, u.String())
	}
	return out
}

// tagSANs builds the type-tagged SAN identity — salt = SHA256(sorted
// type-tagged SANs), with "dns:…"/"ip:…" tags so a DNSName that happens to
// look like an IP literal can never collide with an actual IP SAN — from a
// leaf's DNS names and IP addresses directly, before those are wrapped in
// a parsed *x509.Certificate — the shape SelfCert's mint path needs, since
// it must derive the key before the certificate (and hence Leaf.DNSNames/
// IPAddresses) exists.
func tagSANs(dnsNames []string, ipAddrs []net.IP) []string {
	out := make([]string, 0, len(dnsNames)+len(ipAddrs))
	for _, n := range dnsNames {
		out = append(out, "dns:"+n)
	}
	for _, ip := range ipAddrs {
		out = append(out, "ip:"+ip.String())
	}
	return out
}

// typeTaggedSANStrings is tagSANs applied to an already-parsed certificate
// (a real chain element being cloned, or a cached leaf being re-verified/
// re-keyed) — the counterpart used everywhere except SelfCert's pre-mint
// path. EmailAddresses/URIs are tagged too for completeness, though real
// leaf certs essentially never carry them.
func typeTaggedSANStrings(c *x509.Certificate) []string {
	tagged := tagSANs(c.DNSNames, c.IPAddresses)
	for _, e := range c.EmailAddresses {
		tagged = append(tagged, "email:"+e)
	}
	for _, u := range c.URIs {
		tagged = append(tagged, "uri:"+u.String())
	}
	return tagged
}

// chainDERFingerprint computes SHA256 over a real chain's raw DER bytes,
// leaf-first — the "SHA256(real-chain DER)" half of the certs/ cache-id
// formula (see certID in cache.go). Folds in every element's identity, issuer, serial, validity,
// and public key at once, so distinct real certs never collide and a
// renewal (different serial/validity/SPKI) is a different id by
// construction — no separate freshness check needed.
func chainDERFingerprint(chain []*x509.Certificate) []byte {
	h := sha256.New()
	for _, c := range chain {
		h.Write(c.Raw)
	}
	return h.Sum(nil)
}

// CloneChain reproduces the real chain (leaf + intermediates, leaf-first
// as returned by tls.ConnectionState.PeerCertificates) as its synthetic
// counterpart, signed up to our own signing CA. Each synthetic
// element copies validity verbatim, so the client fails or passes at
// exactly the same position as against the real chain — except the one
// element signed directly by the signing CA, whose NotAfter is clamped
// to the signing CA's own (a CA can't vouch for a cert outliving it).
//
// When the signing CA can't issue enough intermediate levels to cover
// the real chain (ca.issuanceBudget — always unconstrained for the
// auto-generated root, but can be limited when the operator supplies
// their own signing CA with a pathLenConstraint), CloneChain flattens:
// realChain is truncated to just the leaf, which is then signed directly
// by the signing CA, cloning no intermediates. This is the same code
// path as an already-single-element realChain; flattening just gets
// there by truncation first.
func CloneChain(ca *CA, keys DetKeyDeriver, realChain []*x509.Certificate) ([]*x509.Certificate, []*ecdsa.PrivateKey, error) {
	if len(realChain) == 0 {
		return nil, nil, errors.New("cert: empty real chain")
	}

	effectiveChain := realChain
	if budget, constrained := ca.issuanceBudget(); constrained {
		intermediates := len(realChain) - 1
		if intermediates > budget {
			effectiveChain = realChain[:1] // flatten: leaf signed directly by the signing CA
		}
	}

	synthCerts := make([]*x509.Certificate, len(effectiveChain))
	synthKeys := make([]*ecdsa.PrivateKey, len(effectiveChain))

	// Sign root-down-to-leaf: each parent's SubjectKeyId (auto-generated by
	// x509.CreateCertificate for CA templates) must exist before it's
	// needed as the child's AuthorityKeyId.
	for i := len(effectiveChain) - 1; i >= 0; i-- {
		real := effectiveChain[i]
		tmpl := cloneTemplate(real)

		var key *ecdsa.PrivateKey
		var err error
		if i == 0 {
			key, err = keys.LeafKey(typeTaggedSANStrings(real))
		} else {
			key, err = keys.IntermediateKey(real.RawIssuer, real.SerialNumber)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("cert: derive key for chain element %d: %w", i, err)
		}

		parentCert, parentKey := ca.Cert, ca.Key
		if i != len(effectiveChain)-1 {
			parentCert, parentKey = synthCerts[i+1], synthKeys[i+1]
		} else if tmpl.NotAfter.After(ca.Cert.NotAfter) {
			tmpl.NotAfter = ca.Cert.NotAfter
		}

		der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, parentKey)
		if err != nil {
			return nil, nil, fmt.Errorf("cert: sign chain element %d: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, fmt.Errorf("cert: parse chain element %d: %w", i, err)
		}

		synthCerts[i] = cert
		synthKeys[i] = key
	}

	return synthCerts, synthKeys, nil
}
