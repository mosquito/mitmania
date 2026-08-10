package cert

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// selfCertValidity is how long a --listen-https-proxy identity cert is
// valid for — long enough to be effectively permanent for this tool's
// purposes. There is no renewal mechanism: it mints once and is served
// from the leaf cache forever after, same as everything else there.
const selfCertValidity = 10 * 365 * 24 * time.Hour

// SelfCert mints (or serves from cache) a long-lived leaf identifying the
// proxy's own https-proxy listener, signed directly by the root CA. names
// is the ordered list from one or more repeated ?cn= query params:
// names[0] always becomes the Subject.CommonName, unrestricted —
// CN isn't used for hostname verification by modern clients, so it can be
// any free-text label (e.g. the default "Internal Proxy"). The SAN set is
// built from whichever entries are ACTUALLY valid: an entry that parses
// as an IP becomes an IPAddresses SAN, one that's syntactically a valid
// DNS hostname becomes a DNSNames SAN — anything else (a free-text CN
// with a space, say) is silently excluded from the SAN set entirely.
// This isn't optional politeness: OpenSSL-based clients (curl, most
// browsers) fail X509_verify_cert with error 53 ("unsupported name
// syntax") for the WHOLE certificate the instant ANY dNSName SAN entry
// has invalid syntax — confirmed via a live openssl s_client/curl smoke
// test — so one bad entry poisons every entry, not just itself. An
// operator wanting real verification passes an additional, syntactically
// valid ?cn= alongside the friendly one (e.g.
// ?cn=Friendly%20Name&cn=proxy.internal.example); the default single
// "Internal Proxy" value alone still mints a servable cert, just one with
// an empty SAN set that only lenient (non-OpenSSL) clients can verify.
// Unlike For (which clones a real origin's identity) or Fallback (which
// is ephemeral and deliberately never cached), there's no real chain to
// derive this from — but unlike Fallback, this one IS persisted in the
// same leaf cache as any MITM'd leaf: --https-proxy is a stable endpoint,
// not a one-off error page, so it should mint exactly once and then be
// byte-identical across every node sharing Storage. A different names
// list is simply a different cache identity — nothing to invalidate,
// nothing to clean up, consistent with the cache's general "no TTL, no
// separate freshness check" design.
func (f *CertFactory) SelfCert(ctx context.Context, names []string) (*tls.Certificate, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("cert: factory: self-cert requires at least one name")
	}
	start := time.Now()

	if f.tracer != nil {
		var span trace.Span
		ctx, span = f.tracer.Start(ctx, "cert", trace.WithAttributes(
			attribute.String("op", "selfcert"), attribute.StringSlice("names", names)))
		defer span.End()
	}

	var dnsNames []string
	var ipAddrs []net.IP
	for _, n := range names {
		switch ip := net.ParseIP(n); {
		case ip != nil:
			ipAddrs = append(ipAddrs, ip)
		case isValidDNSName(n):
			dnsNames = append(dnsNames, n)
		default:
			// Contributes to Subject.CommonName only (via names[0]
			// below, if this is that entry) — never to the SAN set.
		}
	}
	// identity is what typeTaggedSANStrings(leaf) will also produce once
	// parsed back from a cached DER cert (dns: then ip:, the same
	// type-tagged convention tagSANs uses) — fresh-mint and cache-hit key
	// derivation/verify-on-hit must all agree on this encoding.
	identity := tagSANs(dnsNames, ipAddrs)

	// The cache id (like the serial) is derived from the FULL raw names
	// list, not just the filtered SAN identity: two different
	// free-text-only CNs (e.g. "Internal Proxy" vs "My Proxy") both
	// filter down to an empty SAN set, and must not collide into the same
	// cached cert/CN.
	serial := selfCertSerial(names)
	id := f.cache.SelfCertIDFor(names)

	cached, ok, source, err := f.cache.get(ctx, id)
	if err != nil {
		return nil, err
	}
	if ok {
		f.metrics.CertCache(ctx, source)
		f.metrics.CertDuration(ctx, "selfcert", source, time.Since(start))
		return f.selfCertFromChain(cached)
	}

	key, err := f.keys.LeafKey(identity)
	if err != nil {
		return nil, fmt.Errorf("cert: factory: self-cert key for %v: %w", names, err)
	}

	notBefore := time.Now().Add(-time.Hour) // backdated, same clock-skew fudge as the root
	notAfter := notBefore.Add(selfCertValidity)
	if notAfter.After(f.ca.Cert.NotAfter) {
		notAfter = f.ca.Cert.NotAfter // a CA can't vouch for a cert outliving it
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddrs,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca.Cert, &key.PublicKey, f.ca.Key)
	if err != nil {
		return nil, fmt.Errorf("cert: factory: self-cert sign for %v: %w", names, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("cert: factory: self-cert parse for %v: %w", names, err)
	}
	chain := []*x509.Certificate{leaf}

	if err := f.cache.put(ctx, id, chain); err != nil {
		return nil, err
	}
	if err := f.cache.ensureLinks(ctx, id, leaf); err != nil {
		return nil, err
	}

	if f.log != nil {
		fp := sha256.Sum256(leaf.Raw)
		f.log.Info("generated https-proxy certificate", "cn", names[0], "names", names, "id", id, "fingerprint_sha256", fmt.Sprintf("%x", fp))
	}
	f.metrics.CertMint(ctx, "leaf")
	f.metrics.CertCache(ctx, "miss")
	f.metrics.CertDuration(ctx, "selfcert", "miss", time.Since(start))

	return &tls.Certificate{
		Certificate: append([][]byte{leaf.Raw}, f.ca.ChainDER()...),
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// isValidDNSName reports whether s is syntactically a valid DNS hostname
// (RFC 952/1123 LDH rule: labels of letters/digits/hyphens, dot-joined,
// hyphens never leading/trailing a label) — deliberately conservative, so
// a free-text CN like "Internal Proxy" (space) is rejected outright
// rather than risk emitting a SAN entry some OpenSSL-based client would
// choke on (see SelfCert's doc comment for why that matters here).
func isValidDNSName(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for label := range strings.SplitSeq(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			case c == '-' && i != 0 && i != len(label)-1:
			default:
				return false
			}
		}
	}
	return true
}

// selfCertFromChain re-derives the leaf private key (never persisted to
// disk, always re-derived from clusterKey) for a cache hit and appends
// the root CA cert to the served chain —
// same as the fresh-mint path, so a cache hit and a fresh mint are
// indistinguishable to a client either way.
func (f *CertFactory) selfCertFromChain(chain []*x509.Certificate) (*tls.Certificate, error) {
	leafKey, err := f.keys.LeafKey(typeTaggedSANStrings(chain[0]))
	if err != nil {
		return nil, fmt.Errorf("cert: factory: re-derive self-cert leaf key: %w", err)
	}
	return &tls.Certificate{
		Certificate: append([][]byte{chain[0].Raw}, f.ca.ChainDER()...),
		PrivateKey:  leafKey,
		Leaf:        chain[0],
	}, nil
}

// selfCertIdentityHash hashes the full, RAW ?cn= names list (not the
// filtered SAN identity — see SelfCert's cache-id comment for why: two
// different free-text-only CNs must never collide just because they both
// filter down to an empty SAN set), namespaced away from serialFor's
// real-chain space (clone.go) and fallbackSerial's ephemeral space
// (fallback.go) so none of the three are ever confusable even on an input
// collision. Each entry is \x00-prefixed (rather than simply joined) so
// ["ab","c"] and ["a","bc"] can't collide. Shared by selfCertSerial
// (truncated to 160 bits, the same convention serialFor/fallbackSerial
// use) and CertCache.SelfCertIDFor (the full 256 bits, standing in for
// the "real-chain DER fingerprint" that certID hashes instead — a
// self-cert has no real chain to fingerprint, so its raw identity stands
// in for it).
func selfCertIdentityHash(names []string) [32]byte {
	h := sha256.New()
	h.Write([]byte("mitmania/https-proxy/v1"))
	for _, n := range names {
		h.Write([]byte{0})
		h.Write([]byte(n))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// selfCertSerial derives a stable serial from the full, RAW ?cn= names
// list — see selfCertIdentityHash for the shared hash and collision-safety
// rationale.
func selfCertSerial(names []string) *big.Int {
	sum := selfCertIdentityHash(names)
	return new(big.Int).SetBytes(sum[:20]) // trunc160, same convention as serialFor/fallbackSerial
}
