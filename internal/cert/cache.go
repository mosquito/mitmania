package cert

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/google/uuid"
	"software.sslmate.com/src/go-pkcs12"

	"mitmania/internal/storage"
)

const (
	certsPrefix = leafPrefix + "certs/"
	namesPrefix = leafPrefix + "names/"

	// cloneFormatVersion is folded into both the certs/ id (certID below)
	// and .tuple (via ca.go's tupleHash) — bumping it on any future
	// change to the clone/id encoding makes a rolling upgrade's nodes
	// compute disjoint ids for the new format (never misreading another
	// version's bytes under a shared key) and makes .tuple mismatch on
	// upgrade, which best-effort wipes leaf/ and lets stale-format
	// entries age out via verify-on-hit rather than needing a manual
	// migration.
	cloneFormatVersion = "v1"
)

// CertCache is the on-disk leaf cache: a CAS-style cert-only store keyed by
// UUID5(perClusterNamespace, cloneFormatVersion ‖ SHA256(real-chain DER))
// — a full content identity of the real chain, not SANs+serial — plus a
// parallel names/ index (exact SAN + CN, including wildcard SANs — names
// are hashed, not stored as literal keys, so a bare "*" is no different
// from any other name) maintained via Storage's optional Linker
// capability where the backend supports it. Private keys are never
// written to disk — they're re-derived from clusterKey on load.
//
// get/put also maintain an in-memory hot map keyed by id, so a repeat
// connection to an already-seen real chain within this process's
// lifetime skips the Storage read + PKCS#12 decrypt/decode entirely. It
// holds only parsed chains, never private keys (those are re-derived per
// call in factory.go, same as ever), and it's not persisted — a restart
// just means a cold, empty map that refills lazily from Storage, which
// stays the sole source of truth.
type CertCache struct {
	storage   storage.Storage
	password  string // clusterKey, as the p12 password
	namespace uuid.UUID
	ca        *CA           // current root — verify-on-hit checks every cache hit still chains to this
	keys      DetKeyDeriver // verify-on-hit re-derives the leaf key from this on every hit
	log       *slog.Logger  // nil disables cache-level logging (WithCacheLogger)

	mu  sync.RWMutex
	hot map[string][]*x509.Certificate // id -> already-loaded chain (leaf-first)
}

// CertCacheOption configures NewCertCache.
type CertCacheOption func(*CertCache)

// WithCacheLogger enables Debug-level logging of hot-map hits and
// Info-level logging of Flush — nil (the default) disables it, same
// convention as Http1Handler.Logger.
func WithCacheLogger(log *slog.Logger) CertCacheOption {
	return func(c *CertCache) { c.log = log }
}

// NewCertCache returns a leaf cache backed by store, under the "leaf/"
// key prefix. ca is the current root CA — every cache hit (hot-map or
// Storage) is re-verified against it ("verify on hit" — see the verify
// method) before being served, so a CA/clusterKey change out from under a stale cached entry
// self-heals as a miss rather than serving the wrong cert.
func NewCertCache(store storage.Storage, clusterKey []byte, ca *CA, opts ...CertCacheOption) *CertCache {
	c := &CertCache{
		storage:   store,
		password:  string(clusterKey),
		namespace: sanNamespace(clusterKey),
		ca:        ca,
		keys:      DetKeyDeriver{ClusterKey: clusterKey},
		hot:       map[string][]*x509.Certificate{},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// sanNamespace derives a per-cluster UUID namespace from clusterKey. Using
// clusterKey (rather than a fixed, published namespace constant) means
// certs/ and names/ entries for a given real target aren't a public
// function of its identity alone — two independent mitmania clusters
// proxying the same origin get different, uncorrelatable cache
// identifiers.
func sanNamespace(clusterKey []byte) uuid.UUID {
	sum := sha256.Sum256(clusterKey)
	var ns uuid.UUID
	copy(ns[:], sum[:16])
	return ns
}

// idFromFingerprint is the shared UUID5(namespace, cloneFormatVersion ‖
// fingerprint) construction behind both certID (real-chain DER
// fingerprint) and SelfCertIDFor (self-cert identity-hash fingerprint,
// selfcert.go) — cloneFormatVersion has a fixed byte length so
// concatenating it directly with a fixed-length SHA256 sum needs no
// separator to stay unambiguous.
func idFromFingerprint(namespace uuid.UUID, fingerprint []byte) string {
	name := append([]byte(cloneFormatVersion), fingerprint...)
	return uuid.NewSHA1(namespace, name).String()
}

// certID computes the canonical certs/ cache key for a real chain:
// UUID5(perClusterNamespace, cloneFormatVersion ‖ SHA256(real-chain DER))
// — a full content identity of the real chain, not SANs+serial (a serial
// is unique only within an issuer, and flattened SANs erase type, so both
// could collide). The chain-DER fingerprint folds in real issuer, serial,
// validity, public key and the whole intermediate chain, so distinct real
// certs never collide and a renewal is a different id by construction —
// no separate freshness check needed. The leaf's *cryptographic* key
// still salts on its type-tagged SAN set alone (see LeafKey in keys.go),
// deliberately not the full chain fingerprint, so it stays stable across
// a renewal even though its storage address doesn't.
func certID(namespace uuid.UUID, realChain []*x509.Certificate) string {
	return idFromFingerprint(namespace, chainDERFingerprint(realChain))
}

// nameID computes the names/ cache key for one lookup name (exact SAN or
// CN) — hashed rather than stored as the literal string, for the same
// not-a-public-function-of-identity reason certID is namespace-scoped.
func nameID(namespace uuid.UUID, name string) string {
	return uuid.NewSHA1(namespace, []byte(name)).String()
}

// IDFor computes the certs/ cache key for a real chain, scoped to this
// cache's cluster namespace.
func (c *CertCache) IDFor(realChain []*x509.Certificate) string {
	return certID(c.namespace, realChain)
}

// SelfCertIDFor computes the certs/ cache key for a --listen-https-proxy
// self-signed identity leaf (selfcert.go) — the same
// UUID5(namespace, cloneFormatVersion ‖ fingerprint) shape as certID, but
// fingerprinted from the raw ?cn= names list (selfCertIdentityHash)
// instead of a real chain's DER, since SelfCert has no real chain to
// clone from.
func (c *CertCache) SelfCertIDFor(names []string) string {
	fp := selfCertIdentityHash(names)
	return idFromFingerprint(c.namespace, fp[:])
}

// Count returns the number of cached synthetic chains (certs/ entries) —
// backs the GET /stats endpoint's cache-size figure.
func (c *CertCache) Count(ctx context.Context) (int, error) {
	entries, err := c.storage.List(ctx, certsPrefix)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Key, ".p12") {
			n++
		}
	}
	return n, nil
}

// Flush removes every cached entry — backs the DELETE /cache endpoint.
func (c *CertCache) Flush(ctx context.Context) error {
	if err := c.storage.DeletePrefix(ctx, leafPrefix); err != nil {
		return fmt.Errorf("cert: cache: flush: %w", err)
	}
	c.mu.Lock()
	n := len(c.hot)
	c.hot = map[string][]*x509.Certificate{}
	c.mu.Unlock()
	if c.log != nil {
		c.log.Info("cert cache flushed", "hot_entries_evicted", n)
	}
	return nil
}

// shardedKey returns prefix+xx/yy/zz/tail+ext for id — a CAS layout that
// spreads entries across nested directories instead of one flat directory
// with thousands of files (matters for PosixStorage; harmless elsewhere).
// id is a UUID string; its hex digits (dashes stripped) are split into
// three 2-hex-char levels plus a tail component.
func shardedKey(prefix, id, ext string) string {
	hex := strings.ReplaceAll(id, "-", "")
	return prefix + hex[0:2] + "/" + hex[2:4] + "/" + hex[4:6] + "/" + hex[6:] + ext
}

func certKey(id string) string { return shardedKey(certsPrefix, id, ".p12") }
func nameKey(id string) string { return shardedKey(namesPrefix, id, ".p12") }

// get loads the cached synthetic chain (leaf-first) for id, preferring the
// in-memory hot map over disk when this process has already loaded it. ok
// is false on a clean cache miss OR a verify-on-hit failure: the node
// recomputes the derived leaf key and checks pub == cert SPKI, and that
// the chain still chains to the current Root CA — before serving from
// EITHER source; either mismatch is treated exactly like a miss, letting
// the caller re-mint rather than serve something wrong. source is
// "hotmap"/"storage" on a real hit (empty on a miss) — the same
// vocabulary the cert.cache.total metric uses, exposed here so
// CertFactory can pass it straight through rather than re-deriving it.
func (c *CertCache) get(ctx context.Context, id string) (chain []*x509.Certificate, ok bool, source string, err error) {
	c.mu.RLock()
	chain, ok = c.hot[id]
	c.mu.RUnlock()
	if ok {
		if !c.verify(chain) {
			if c.log != nil {
				c.log.Warn("cert cache: hot-map entry failed verify-on-hit, treating as a miss", "id", id)
			}
			return nil, false, "", nil
		}
		if c.log != nil {
			c.log.Debug("cert cache hit", "id", id, "source", "hot")
		}
		return chain, true, "hotmap", nil
	}

	key := certKey(id)
	data, _, err := c.storage.Get(ctx, key)
	if errors.Is(err, storage.ErrNotExist) {
		return nil, false, "", nil
	}
	if err != nil {
		return nil, false, "", fmt.Errorf("cert: cache: read %s: %w", key, err)
	}

	certs, err := pkcs12.DecodeTrustStore(data, c.password)
	if err != nil {
		return nil, false, "", fmt.Errorf("cert: cache: decode %s: %w", key, err)
	}
	ordered, err := orderChainLeafFirst(certs)
	if err != nil {
		return nil, false, "", fmt.Errorf("cert: cache: %s: %w", key, err)
	}
	if !c.verify(ordered) {
		if c.log != nil {
			c.log.Warn("cert cache: storage entry failed verify-on-hit, treating as a miss", "id", id)
		}
		return nil, false, "", nil
	}

	c.mu.Lock()
	c.hot[id] = ordered
	c.mu.Unlock()

	return ordered, true, "storage", nil
}

// verify implements "verify on hit": re-derive chain's leaf private
// key from clusterKey and check its public key equals the cached leaf's
// SPKI, and that every element (leaf up through any intermediates) still
// chains to c.ca — the CURRENT root. Either mismatch means the cached
// entry no longer matches this node's key material (a CA/clusterKey
// change, or corruption) and must not be served.
func (c *CertCache) verify(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}
	key, err := c.keys.LeafKey(typeTaggedSANStrings(chain[0]))
	if err != nil {
		return false
	}
	if !key.PublicKey.Equal(chain[0].PublicKey) {
		return false
	}
	for i, elem := range chain {
		parent := c.ca.Cert
		if i+1 < len(chain) {
			parent = chain[i+1]
		}
		if err := elem.CheckSignatureFrom(parent); err != nil {
			return false
		}
	}
	return true
}

// put persists a freshly-minted synthetic chain atomically and populates
// the hot map so this process's own next lookup for id is
// in-memory.
func (c *CertCache) put(ctx context.Context, id string, chain []*x509.Certificate) error {
	entries := make([]pkcs12.TrustStoreEntry, len(chain))
	for i, cert := range chain {
		entries[i] = pkcs12.TrustStoreEntry{Cert: cert, FriendlyName: fmt.Sprintf("%d", i)}
	}
	key := certKey(id)
	data, err := pkcs12.Modern.EncodeTrustStoreEntries(entries, c.password)
	if err != nil {
		return fmt.Errorf("cert: cache: encode %s: %w", key, err)
	}
	if err := c.storage.Put(ctx, key, data); err != nil {
		return fmt.Errorf("cert: cache: write %s: %w", key, err)
	}
	c.mu.Lock()
	c.hot[id] = chain
	c.mu.Unlock()
	return nil
}

// ensureLinks maintains the names/ index — one per exact SAN + CN,
// wildcard SANs included: since names are hashed rather than stored as
// literal keys, a bare "*" is no different from any other name here, so
// nothing needs special-casing. A no-op if the backing Storage doesn't
// implement Linker — this index is never consulted on the serving path,
// so a backend without an equivalent primitive just doesn't get this
// operator index.
func (c *CertCache) ensureLinks(ctx context.Context, id string, leaf *x509.Certificate) error {
	linker, ok := c.storage.(storage.Linker)
	if !ok {
		return nil
	}

	names := map[string]bool{}
	if leaf.Subject.CommonName != "" {
		names[leaf.Subject.CommonName] = true
	}
	for _, n := range SANStrings(leaf) {
		names[n] = true
	}

	for name := range names {
		if err := c.symlink(ctx, linker, id, name); err != nil {
			return err
		}
	}
	return nil
}

// symlink creates names/{nameID(name)} -> certs/{id}.
func (c *CertCache) symlink(ctx context.Context, linker storage.Linker, id, name string) error {
	linkKey := nameKey(nameID(c.namespace, name))
	targetKey := certKey(id)
	if err := linker.Symlink(ctx, linkKey, targetKey); err != nil {
		return fmt.Errorf("cert: cache: symlink %s: %w", linkKey, err)
	}
	return nil
}

// orderChainLeafFirst reconstructs leaf-first chain order from an unordered
// set of certificates (PKCS#12 trust stores don't guarantee bag order) by
// following each cert's RawIssuer to the next cert's RawSubject. The leaf
// is the one element whose RawSubject is never any other element's
// RawIssuer.
func orderChainLeafFirst(certs []*x509.Certificate) ([]*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, errors.New("empty chain")
	}

	bySubject := make(map[string]*x509.Certificate, len(certs))
	isIssuer := make(map[string]bool, len(certs))
	for _, c := range certs {
		bySubject[string(c.RawSubject)] = c
		isIssuer[string(c.RawIssuer)] = true
	}

	var leaf *x509.Certificate
	for _, c := range certs {
		if !isIssuer[string(c.RawSubject)] {
			leaf = c
			break
		}
	}
	if leaf == nil {
		return nil, errors.New("no unique leaf (every subject is also an issuer)")
	}

	ordered := make([]*x509.Certificate, 0, len(certs))
	seen := make(map[string]bool, len(certs))
	cur := leaf
	for {
		ordered = append(ordered, cur)
		seen[string(cur.RawSubject)] = true
		next, ok := bySubject[string(cur.RawIssuer)]
		if !ok || seen[string(next.RawSubject)] {
			break
		}
		cur = next
	}
	if len(ordered) != len(certs) {
		return nil, fmt.Errorf("chain has %d certs but only %d chain from the leaf", len(certs), len(ordered))
	}
	return ordered, nil
}
