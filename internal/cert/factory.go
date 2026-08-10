package cert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/singleflight"

	"mitmania/internal/telemetry"
)

// CertFactory is the entry point TLSService uses: given the SNI dialed and
// the real chain observed on that connection, return a ready-to-serve
// tls.Certificate for the synthetic clone.
type CertFactory struct {
	ca    *CA
	cache *CertCache
	keys  DetKeyDeriver
	sf    singleflight.Group
	log   *slog.Logger // nil disables factory-level logging (WithFactoryLogger)

	// metrics/tracer back the cert.* observability signals (mints.total,
	// cache.total, duration; a "cert" span per call) — nil-safe, same
	// convention as log.
	metrics *telemetry.Metrics
	tracer  trace.Tracer
}

// CertFactoryOption configures NewCertFactory.
type CertFactoryOption func(*CertFactory)

// WithFactoryLogger enables Debug-level logging of every mint (a real
// cache miss — cloning + signing a fresh synthetic leaf) and every
// Fallback call — nil (the default) disables it, same convention as
// Http1Handler.Logger.
func WithFactoryLogger(log *slog.Logger) CertFactoryOption {
	return func(f *CertFactory) { f.log = log }
}

// WithFactoryMetrics enables the cert.mints.total/cache.total/duration
// metrics — nil (the default) leaves them unrecorded.
func WithFactoryMetrics(m *telemetry.Metrics) CertFactoryOption {
	return func(f *CertFactory) { f.metrics = m }
}

// WithFactoryTracer enables a "cert" child span per For/Fallback/SelfCert
// call — nil (the default) leaves tracing off.
func WithFactoryTracer(t trace.Tracer) CertFactoryOption {
	return func(f *CertFactory) { f.tracer = t }
}

func NewCertFactory(ca *CA, cache *CertCache, keys DetKeyDeriver, opts ...CertFactoryOption) *CertFactory {
	f := &CertFactory{ca: ca, cache: cache, keys: keys}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// For returns a synthetic tls.Certificate cloning realChain's identity
// (leaf-first, as from tls.ConnectionState.PeerCertificates), minting one
// if the cache is missing and serving the cached clone otherwise (no
// TTL — the cache key folds in the real chain's DER fingerprint, so a
// renewal is a cache miss by construction, with no separate freshness
// check needed). Concurrent calls for the same real chain — the id, not
// sni — are coalesced via singleflight, since two different SNIs backed
// by the same real chain (SAN coverage overlap) should still share one
// mint.
func (f *CertFactory) For(ctx context.Context, sni string, realChain []*x509.Certificate) (*tls.Certificate, error) {
	if len(realChain) == 0 {
		return nil, fmt.Errorf("cert: factory: empty real chain for %q", sni)
	}

	var span trace.Span
	if f.tracer != nil {
		ctx, span = f.tracer.Start(ctx, "cert", trace.WithAttributes(
			attribute.String("op", "for"), attribute.String("sni", sni)))
		defer span.End()
	}

	id := f.cache.IDFor(realChain)
	v, err, _ := f.sf.Do(id, func() (any, error) {
		return f.mint(ctx, sni, id, realChain)
	})
	if err != nil {
		if span != nil {
			span.RecordError(err)
		}
		return nil, err
	}
	return v.(*tls.Certificate), nil
}

func (f *CertFactory) mint(ctx context.Context, sni, id string, realChain []*x509.Certificate) (*tls.Certificate, error) {
	start := time.Now()

	cached, ok, source, err := f.cache.get(ctx, id)
	if err != nil {
		return nil, err
	}
	if ok {
		f.metrics.CertCache(ctx, source)
		f.metrics.CertDuration(ctx, "for", source, time.Since(start))
		return f.toTLSCertificate(cached)
	}

	synthChain, synthKeys, err := CloneChain(f.ca, f.keys, realChain)
	if err != nil {
		return nil, fmt.Errorf("cert: factory: mint: %w", err)
	}
	if err := f.cache.put(ctx, id, synthChain); err != nil {
		return nil, err
	}
	if err := f.cache.ensureLinks(ctx, id, synthChain[0]); err != nil {
		return nil, err
	}
	if f.log != nil {
		f.log.Debug("minted synthetic leaf", "sni", sni, "id", id, "serial", realChain[0].SerialNumber.String(), "chain_len", len(synthChain))
	}
	f.metrics.CertMint(ctx, "leaf")
	f.metrics.CertCache(ctx, "miss")
	f.metrics.CertDuration(ctx, "for", "miss", time.Since(start))

	return f.toDERCertificate(synthChain, synthKeys[0]), nil
}

// toTLSCertificate re-derives the cached chain's leaf private key from
// clusterKey — private keys are never persisted to disk.
func (f *CertFactory) toTLSCertificate(chain []*x509.Certificate) (*tls.Certificate, error) {
	leafKey, err := f.keys.LeafKey(typeTaggedSANStrings(chain[0]))
	if err != nil {
		return nil, fmt.Errorf("cert: factory: re-derive leaf key: %w", err)
	}
	return f.toDERCertificate(chain, leafKey), nil
}

// toDERCertificate builds the served tls.Certificate: the synthetic
// chain (leaf + any cloned intermediates), followed by the signing CA
// and any further intermediates up to its own trust-anchor root — so a
// client can build a path to a root it already trusts, without a
// separate install step, even when the signing CA is a bring-your-own
// sub-CA rather than mitmania's own root.
func (f *CertFactory) toDERCertificate(chain []*x509.Certificate, leafKey any) *tls.Certificate {
	der := make([][]byte, 0, len(chain)+1+len(f.ca.Chain))
	for _, c := range chain {
		der = append(der, c.Raw)
	}
	der = append(der, f.ca.ChainDER()...)
	return &tls.Certificate{Certificate: der, PrivateKey: leafKey, Leaf: chain[0]}
}
