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
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// fallbackValidity is how long a fallback ("sorry page") leaf is valid for
// — short-lived since it's minted fresh on demand, not cached.
const fallbackValidity = 24 * time.Hour

// Fallback mints a synthetic leaf for sni alone — unlike CloneChain,
// there's no real chain to copy identity from (this is for when upstream
// is unreachable in the first place). CN and the sole SAN are both sni;
// the key is deterministic (same LeafKey derivation as a real clone,
// salt=[sni]), but the cert itself is never persisted to the certs/
// on-disk cache — that's keyed by a real leaf's serial, which doesn't
// exist here, and minting is cheap enough to just redo on every use.
//
// This is what lets a post-CONNECT upstream failure still complete a TLS
// handshake with the client over the already-established CONNECT tunnel
// — using this cert instead of a clone — so a Squid-style error page can
// be served as a normal HTTP response inside that session instead of a
// bare TLS reset.
func (f *CertFactory) Fallback(ctx context.Context, sni string) (*tls.Certificate, error) {
	start := time.Now()
	if f.tracer != nil {
		var span trace.Span
		_, span = f.tracer.Start(ctx, "cert", trace.WithAttributes(
			attribute.String("op", "fallback"), attribute.String("sni", sni)))
		defer span.End()
	}

	var dnsNames []string
	var ipAddrs []net.IP
	if ip := net.ParseIP(sni); ip != nil {
		ipAddrs = []net.IP{ip}
	} else {
		dnsNames = []string{sni}
	}

	key, err := f.keys.LeafKey(tagSANs(dnsNames, ipAddrs))
	if err != nil {
		return nil, fmt.Errorf("cert: factory: fallback key for %q: %w", sni, err)
	}

	notAfter := time.Now().Add(fallbackValidity)
	if notAfter.After(f.ca.Cert.NotAfter) {
		notAfter = f.ca.Cert.NotAfter // a CA can't vouch for a cert outliving it
	}
	tmpl := &x509.Certificate{
		SerialNumber: fallbackSerial(sni),
		Subject:      pkix.Name{CommonName: sni},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddrs,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca.Cert, &key.PublicKey, f.ca.Key)
	if err != nil {
		return nil, fmt.Errorf("cert: factory: fallback sign for %q: %w", sni, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("cert: factory: fallback parse for %q: %w", sni, err)
	}

	if f.log != nil {
		f.log.Debug("minted fallback leaf", "sni", sni)
	}
	f.metrics.CertMint(ctx, "fallback")
	f.metrics.CertDuration(ctx, "fallback", "miss", time.Since(start))

	return &tls.Certificate{
		Certificate: append([][]byte{leaf.Raw}, f.ca.ChainDER()...),
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// fallbackSerial derives a stable serial from sni alone, namespaced away
// from serialFor's real-chain-derived space (clone.go) so the two are
// never confusable even if inputs happened to collide.
func fallbackSerial(sni string) *big.Int {
	sum := sha256.Sum256([]byte("mitmania/fallback/v1\x00" + sni))
	return new(big.Int).SetBytes(sum[:20]) // trunc160, same convention as serialFor
}
