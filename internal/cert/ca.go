package cert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"mitmania/internal/storage"
)

// CA is mitmania's signing certificate authority — the auto-generated
// throwaway root by default, or, when the operator supplies their own
// signing CA instead, that one.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey

	// Chain holds any further intermediates between Cert and a
	// self-signed trust-anchor root, exclusive of the root itself —
	// populated when the operator's bring-your-own signing CA is itself
	// an intermediate beneath a separate root (or chain of
	// intermediates), empty for the common case where Cert is itself the
	// (self-signed) root. Sent on the wire
	// alongside every synthetic chain (ChainDER); the root is never sent,
	// since clients already trust it directly.
	Chain []*x509.Certificate

	// Generated reports whether LoadOrGenerateCA minted this root fresh
	// (true) or loaded it from an existing ca.p12 (false) — callers use
	// this for a startup log line distinguishing the two.
	Generated bool
}

// ChainDER returns Cert followed by Chain, in DER form — appended after
// any synthetic leaf/intermediate chain when serving over TLS, so
// a client can build the path to a root it already trusts without a
// separate install step. For the common case (Cert is the root itself,
// Chain empty) this is just [Cert] — harmless/conventional to include
// even though the client, having installed the root directly, doesn't
// strictly need it.
func (ca *CA) ChainDER() [][]byte {
	der := make([][]byte, 0, 1+len(ca.Chain))
	der = append(der, ca.Cert.Raw)
	for _, c := range ca.Chain {
		der = append(der, c.Raw)
	}
	return der
}

// issuanceBudget reports how many intermediate levels CloneChain may
// clone beneath Cert — derived from Cert's own BasicConstraints
// pathLenConstraint, regardless of whether Cert itself is a root or an
// intermediate: an unconstrained cert (no pathLenConstraint at all)
// imposes no limit of its own, matching ordinary X.509 semantics.
// constrained is false for the common unconstrained-root case.
func (ca *CA) issuanceBudget() (budget int, constrained bool) {
	if ca.Cert.MaxPathLenZero {
		return 0, true
	}
	if ca.Cert.MaxPathLen >= 0 {
		return ca.Cert.MaxPathLen, true
	}
	return 0, false
}

const (
	caKey      = "ca/ca.p12"
	leafPrefix = "leaf/"
	tupleKey   = ".tuple"

	rootValidity   = 20 * 365 * 24 * time.Hour
	rootClockFudge = time.Hour // NotBefore is backdated so minor clock skew never rejects our own root
)

var serialLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// CAOption configures LoadOrGenerateCA.
type CAOption func(*caOptions)

type caOptions struct {
	log *slog.Logger
}

// WithCALogger enables a Warn-level record whenever "leaf/" gets wiped
// because the root or clusterKey changed out from under an existing
// ca.p12 — the disruptive case; the routine wipe-on-fresh-generation
// case logs at Info instead. nil (the default) disables both.
func WithCALogger(log *slog.Logger) CAOption {
	return func(o *caOptions) { o.log = log }
}

// LoadOrGenerateCA loads the root CA from "ca/ca.p12" in store, generating
// and persisting a new one if absent — the root is always randomly
// generated, never derived from clusterKey, so nothing but ca.p12 itself
// fixes its identity across restarts. It also validates the ".tuple" key,
// wiping "leaf/" wholesale whenever the root or clusterKey has changed.
//
// A ca.p12 that exists but fails to decode under clusterKey is a fail-start
// error, never a silent regenerate: regenerating would produce a new random
// root and silently break the "copy ca.p12 to every node" multi-node trust
// model.
func LoadOrGenerateCA(ctx context.Context, store storage.Storage, clusterKey []byte, opts ...CAOption) (*CA, error) {
	var o caOptions
	for _, opt := range opts {
		opt(&o)
	}

	data, _, err := store.Get(ctx, caKey)

	var ca *CA
	generated := false

	switch {
	case errors.Is(err, storage.ErrNotExist):
		ca, err = generateCA()
		if err != nil {
			return nil, fmt.Errorf("cert: generate root CA: %w", err)
		}
		if err := persistCA(ctx, store, ca, clusterKey); err != nil {
			return nil, fmt.Errorf("cert: persist root CA: %w", err)
		}
		generated = true

	case err != nil:
		return nil, fmt.Errorf("cert: read %s: %w", caKey, err)

	default:
		ca, err = decodeCA(data, clusterKey)
		if err != nil {
			return nil, fmt.Errorf("cert: decode %s (check --cluster-key matches the file that produced it): %w", caKey, err)
		}
	}

	if err := reconcileTuple(ctx, store, ca, clusterKey, generated, o.log); err != nil {
		return nil, err
	}

	ca.Generated = generated
	return ca, nil
}

func generateCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now().Add(-rootClockFudge)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		// Deliberately generic, not proxy-branded: Country/Organization/
		// CommonName is the minimal DN shape real root CAs publish, but
		// with no distinctive name to notice or search — a mitmania-branded
		// issuer is exactly the kind of detail that derails an automated
		// consumer of the chain (a browsing agent, cert-tooling) into
		// treating it as something unusual worth investigating, which is
		// far more disruptive to them than to a human glancing past it.
		Subject: pkix.Name{
			Organization: []string{"Root CA"},
			CommonName:   "Root CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// p12Password is the PKCS#12 encryption password for ca/ca.p12 — the
// clusterKey re-encoded to the exact base64 text an operator passes
// verbatim to --cluster-key, not the decoded raw bytes. clusterKey is
// always produced by base64-decoding
// that CLI argument (config.go), so re-encoding it here deterministically
// reconstructs it byte-for-byte — giving operators a plain ASCII-safe
// password they can hand to `openssl pkcs12 -passout pass:"$CLUSTER_KEY"`
// directly, rather than needing to work with raw (possibly
// non-printable) key bytes as a shell argument. Every OTHER use of
// clusterKey (HKDF ikm for leaf/intermediate/SSH key derivation, the
// CertCache namespace) still uses the raw decoded bytes — this encoding
// is specific to the PKCS#12 password alone.
func p12Password(clusterKey []byte) string {
	return base64.StdEncoding.EncodeToString(clusterKey)
}

func persistCA(ctx context.Context, store storage.Storage, ca *CA, clusterKey []byte) error {
	data, err := pkcs12.Modern.Encode(ca.Key, ca.Cert, nil, p12Password(clusterKey))
	if err != nil {
		return err
	}
	return store.Put(ctx, caKey, data)
}

// decodeCA parses ca/ca.p12 and validates it before ever being trusted
// to sign anything — validation happens at load time, and any failure is
// a fail-start, never a silent downgrade. Any failure here is returned
// to the caller unwrapped-but-annotated, which LoadOrGenerateCA turns
// into a fail-start error.
func decodeCA(data, clusterKey []byte) (*CA, error) {
	key, cert, caCerts, err := pkcs12.DecodeChain(data, p12Password(clusterKey))
	if err != nil {
		return nil, err
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("root CA private key is %T, want *ecdsa.PrivateKey", key)
	}
	if err := validateSigningCert(ecKey, cert); err != nil {
		return nil, err
	}
	chain, err := resolveChain(cert, caCerts)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: ecKey, Chain: chain}, nil
}

var (
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
)

// validateSigningCert checks everything required of a bring-your-own
// signing cert+key before it's ever used to sign anything: key type
// (ECDSA P-256 or P-384 — the ISSUING root above it may be anything,
// including RSA, since only our own signing key ever does the actual
// signing here), that the key's public half matches the cert's, CA
// BasicConstraints (critical), KeyUsage keyCertSign (critical), and that
// it isn't expired or not-yet-valid. The auto-generated root always
// passes this by construction; it's exercised for a loaded ca.p12 only.
func validateSigningCert(key *ecdsa.PrivateKey, cert *x509.Certificate) error {
	switch key.Curve {
	case elliptic.P256(), elliptic.P384():
	default:
		return fmt.Errorf("signing key curve is %s, want P-256 or P-384", key.Curve.Params().Name)
	}

	certKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !certKey.Equal(&key.PublicKey) {
		return fmt.Errorf("signing key does not match certificate's public key")
	}

	if !cert.BasicConstraintsValid || !cert.IsCA {
		return fmt.Errorf("signing certificate is not a CA (BasicConstraints CA:true required)")
	}
	if ext := findExtension(cert.Extensions, oidBasicConstraints); ext == nil || !ext.Critical {
		return fmt.Errorf("signing certificate's BasicConstraints extension must be marked critical")
	}

	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("signing certificate KeyUsage does not include keyCertSign")
	}
	if ext := findExtension(cert.Extensions, oidKeyUsage); ext == nil || !ext.Critical {
		return fmt.Errorf("signing certificate's KeyUsage extension must be marked critical")
	}

	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("signing certificate not yet valid (NotBefore %s)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("signing certificate has expired (NotAfter %s)", cert.NotAfter)
	}
	return nil
}

// isSelfSigned reports whether cert is its own trust anchor — verified
// cryptographically (the signature actually checks out), not just by
// comparing Issuer/Subject names.
func isSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}

// resolveChain validates and returns the CA.Chain for cert: nil if cert
// is itself a self-signed root (the common case — nothing further
// needed), else the ordered intermediates from cert's issuer up to but
// excluding a self-signed root found within pool — the bundle must carry
// the chain up to a self-signed root, or loading fails. Each link is
// verified cryptographically (issuer/subject name matching alone isn't
// enough — a wrong or spoofed cert with the right DN would otherwise
// pass), and a cycle is a load error rather than an infinite loop.
func resolveChain(cert *x509.Certificate, pool []*x509.Certificate) ([]*x509.Certificate, error) {
	if isSelfSigned(cert) {
		return nil, nil
	}

	var chain []*x509.Certificate
	current := cert
	seen := map[string]bool{string(cert.Raw): true}
	for {
		parent := findVerifiedParent(current, pool)
		if parent == nil {
			return nil, fmt.Errorf("signing certificate is an intermediate (issuer %q != subject %q) but the bundle does not carry a complete, verifiable chain to a self-signed root", current.Issuer, current.Subject)
		}
		if seen[string(parent.Raw)] {
			return nil, fmt.Errorf("signing certificate's chain contains a cycle at %q", parent.Subject)
		}
		seen[string(parent.Raw)] = true

		if isSelfSigned(parent) {
			return chain, nil // parent is the root: stop here, don't include it (never sent on the wire)
		}
		chain = append(chain, parent)
		current = parent
	}
}

// findVerifiedParent locates cert's issuer within pool by subject/issuer
// name match, then confirms the signature actually verifies under that
// candidate before accepting it.
func findVerifiedParent(cert *x509.Certificate, pool []*x509.Certificate) *x509.Certificate {
	for _, c := range pool {
		if bytes.Equal(c.RawSubject, cert.RawIssuer) && cert.CheckSignatureFrom(c) == nil {
			return c
		}
	}
	return nil
}

// tupleHash computes SHA256(signingCertDER || clusterKeyID || cloneFormatVersion)
// — the fingerprint stored at ".tuple" and checked on every load to decide
// whether "leaf/" needs wiping. clusterKeyID is SHA256(clusterKey) —
// stable, non-secret, and changes iff clusterKey does.
//
// Hashes the FULL cert (cert.Raw), not just its public key: when the
// operator supplies their own signing CA, it can be re-issued (same key,
// new cert) with a different pathLenConstraint, validity, or issuer chain —
// changes that alter what CloneChain does with that key (flatten vs.
// full clone, NotAfter clamp, wire chain) without the key itself ever
// changing. A SPKI-only hash would miss all of that (a stale mint's
// signature still cryptographically verifies against the new cert, same
// key), silently leaving already-cached leaves governed by the OLD
// cert's policy instead of the new one. Hashing the whole DER makes any
// such re-issuance flip the tuple, wiping leaf/ so every leaf re-mints
// under the current policy.
//
// Folding in cloneFormatVersion means bumping it (any future change to
// the clone/id encoding) also flips the tuple, so a rolling upgrade's
// nodes wipe leaf/ and start fresh under the new format instead of
// needing a manual migration — the same self-healing path a CA/clusterKey
// change already takes.
func tupleHash(cert *x509.Certificate, clusterKey []byte) []byte {
	keyID := sha256.Sum256(clusterKey)
	h := sha256.New()
	h.Write(cert.Raw)
	h.Write(keyID[:])
	h.Write([]byte(cloneFormatVersion))
	return h.Sum(nil)
}

func reconcileTuple(ctx context.Context, store storage.Storage, ca *CA, clusterKey []byte, justGenerated bool, log *slog.Logger) error {
	want := tupleHash(ca.Cert, clusterKey)

	if !justGenerated {
		existing, _, err := store.Get(ctx, tupleKey)
		if err == nil && bytes.Equal(existing, want) {
			return nil // unchanged, nothing to do
		}
		if err != nil && !errors.Is(err, storage.ErrNotExist) {
			return fmt.Errorf("cert: read %s: %w", tupleKey, err)
		}
		// A tuple existed (or errored not-exist, i.e. absent) and didn't
		// match — the root or clusterKey changed out from under an
		// existing ca.p12. Disruptive: every cached leaf is about to be
		// invalidated.
		if log != nil {
			log.Warn("root or cluster key changed since last run, wiping leaf cache", "prefix", leafPrefix)
		}
	} else if log != nil {
		log.Info("fresh root generated, wiping any stale leaf cache", "prefix", leafPrefix)
	}

	if err := store.DeletePrefix(ctx, leafPrefix); err != nil {
		return fmt.Errorf("cert: wipe %s: %w", leafPrefix, err)
	}
	if err := store.Put(ctx, tupleKey, want); err != nil {
		return fmt.Errorf("cert: write %s: %w", tupleKey, err)
	}
	return nil
}
