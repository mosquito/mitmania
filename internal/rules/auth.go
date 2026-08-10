package rules

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// defaultRealm is auth.http_proxy's Proxy-Authenticate realm when the rule
// file omits "realm".
const defaultRealm = "mitmania"

// CompiledAuth is auth.http_proxy's validated, ready-to-check form —
// compiled once at load like every other rule-file construct, so the
// request-serving path never re-parses hash strings.
type CompiledAuth struct {
	Required bool
	Realm    string
	Basic    []BasicCredential
	Bearer   []BearerCredential
	Broker   *AuthBroker
}

// CompileAuth validates a's http_proxy block: hash formats, broker
// socket/url mutual exclusivity, and that a required gate actually has
// some way to authenticate. nil in, nil out — no auth block configured
// is not an error, it's simply "auth.http_proxy is absent" (the default:
// source IP alone is the client's identity).
func CompileAuth(a *AuthConfig) (*CompiledAuth, error) {
	if a == nil || a.HTTPProxy == nil {
		return nil, nil
	}
	hp := a.HTTPProxy

	if hp.Broker != nil {
		hasSocket := hp.Broker.Socket != ""
		hasURL := hp.Broker.URL != ""
		if hasSocket == hasURL {
			return nil, fmt.Errorf("auth.http_proxy.broker: exactly one of \"socket\" or \"url\" is required")
		}
		if hasSocket && hp.Broker.Path == "" {
			hp.Broker.Path = "/"
		} else if hasURL && hp.Broker.Path != "" {
			return nil, fmt.Errorf("auth.http_proxy.broker: \"path\" only applies to a \"socket\" target")
		}
	}

	if hp.Required && len(hp.Basic) == 0 && len(hp.Bearer) == 0 && hp.Broker == nil {
		return nil, fmt.Errorf("auth.http_proxy: required is true but no scheme (basic/bearer/broker) is configured")
	}

	seenUsers := map[string]bool{}
	for _, c := range hp.Basic {
		if c.User == "" {
			return nil, fmt.Errorf("auth.http_proxy.basic: empty \"user\"")
		}
		if seenUsers[c.User] {
			return nil, fmt.Errorf("auth.http_proxy.basic: duplicate user %q", c.User)
		}
		seenUsers[c.User] = true
		if _, err := parseArgon2idHash(c.Hash); err != nil {
			return nil, fmt.Errorf("auth.http_proxy.basic[%q]: %w", c.User, err)
		}
	}

	seenIDs := map[string]bool{}
	for _, c := range hp.Bearer {
		if c.ID == "" {
			return nil, fmt.Errorf("auth.http_proxy.bearer: empty \"id\"")
		}
		if seenIDs[c.ID] {
			return nil, fmt.Errorf("auth.http_proxy.bearer: duplicate id %q", c.ID)
		}
		seenIDs[c.ID] = true
		if _, err := parseSHA256Hash(c.Hash); err != nil {
			return nil, fmt.Errorf("auth.http_proxy.bearer[%q]: %w", c.ID, err)
		}
	}

	realm := hp.Realm
	if realm == "" {
		realm = defaultRealm
	}

	return &CompiledAuth{
		Required: hp.Required,
		Realm:    realm,
		Basic:    hp.Basic,
		Bearer:   hp.Bearer,
		Broker:   hp.Broker,
	}, nil
}

// ChallengeSchemes lists the Proxy-Authenticate scheme names a 407 should
// challenge with: Basic when local basic credentials or a broker
// are configured (a broker accepts whatever wire form the client used, so
// it doesn't rule Basic out), Bearer likewise for bearer/broker.
func (ca *CompiledAuth) ChallengeSchemes() []string {
	var schemes []string
	if len(ca.Basic) > 0 || ca.Broker != nil {
		schemes = append(schemes, "Basic")
	}
	if len(ca.Bearer) > 0 || ca.Broker != nil {
		schemes = append(schemes, "Bearer")
	}
	return schemes
}

// Authenticate checks proxyAuthorization (the raw Proxy-Authorization
// header value) against ca's LOCAL basic/bearer credentials only — the
// broker scheme (needing an OutcallService this package doesn't depend
// on) is the caller's job, tried when this returns ok=false and
// ca.Broker != nil. The first credential that validates wins: within
// Basic there's one presented credential to check against every
// configured user, likewise for Bearer.
func (ca *CompiledAuth) Authenticate(proxyAuthorization string) (ok bool, principal string) {
	scheme, value, found := strings.Cut(proxyAuthorization, " ")
	if !found {
		return false, ""
	}
	switch scheme {
	case "Basic":
		return ca.authenticateBasic(value)
	case "Bearer":
		return ca.authenticateBearer(value)
	default:
		return false, ""
	}
}

func (ca *CompiledAuth) authenticateBasic(b64 string) (bool, string) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return false, ""
	}
	user, pass, found := strings.Cut(string(raw), ":")
	if !found {
		return false, ""
	}
	for _, c := range ca.Basic {
		if c.User != user {
			continue
		}
		if ok, err := verifyArgon2id(c.Hash, pass); err == nil && ok {
			return true, c.User
		}
	}
	return false, ""
}

func (ca *CompiledAuth) authenticateBearer(token string) (bool, string) {
	for _, c := range ca.Bearer {
		if ok, err := verifyBearerToken(c.Hash, token); err == nil && ok {
			return true, c.ID
		}
	}
	return false, ""
}

// parseArgon2idHash validates hash is a well-formed canonical PHC-format
// argon2id string ($argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>) without
// checking any password — used at compile time, since a malformed hash is
// a load-time rejection, and by verifyArgon2id itself.
func parseArgon2idHash(hash string) (argon2idParams, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return argon2idParams{}, fmt.Errorf("not a canonical $argon2id$... hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return argon2idParams{}, fmt.Errorf("parse argon2id version: %w", err)
	}
	var memory, iterTime uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterTime, &threads); err != nil {
		return argon2idParams{}, fmt.Errorf("parse argon2id params: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return argon2idParams{}, fmt.Errorf("decode argon2id salt: %w", err)
	}
	sum, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argon2idParams{}, fmt.Errorf("decode argon2id hash: %w", err)
	}
	return argon2idParams{memory: memory, time: iterTime, threads: threads, salt: salt, sum: sum}, nil
}

type argon2idParams struct {
	memory, time uint32
	threads      uint8
	salt, sum    []byte
}

// verifyArgon2id checks password against a canonical PHC-format argon2id
// hash string — the stored basic-auth credential format. Comparison
// against the derived key is constant-time, so hash-string layout never
// leaks timing beyond what the KDF itself already costs.
func verifyArgon2id(hash, password string) (bool, error) {
	p, err := parseArgon2idHash(hash)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), p.salt, p.time, p.memory, p.threads, uint32(len(p.sum)))
	return subtle.ConstantTimeCompare(got, p.sum) == 1, nil
}

// parseSHA256Hash validates hash is well-formed "sha256:<hex>" — the
// bearer-token hash format — without checking any token.
func parseSHA256Hash(hash string) ([]byte, error) {
	hexPart, ok := strings.CutPrefix(hash, "sha256:")
	if !ok {
		return nil, fmt.Errorf("bearer hash must be \"sha256:<hex>\"")
	}
	sum, err := hex.DecodeString(hexPart)
	if err != nil {
		return nil, fmt.Errorf("decode sha256 hash: %w", err)
	}
	if len(sum) != sha256.Size {
		return nil, fmt.Errorf("sha256 hash must be %d bytes, got %d", sha256.Size, len(sum))
	}
	return sum, nil
}

// verifyBearerToken checks token against a stored "sha256:<hex>" hash.
// Tokens are high-entropy, so a fast hash is safe here — unlike a
// password, which needs argon2id's deliberate slowness.
func verifyBearerToken(hash, token string) (bool, error) {
	want, err := parseSHA256Hash(hash)
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(sum[:], want) == 1, nil
}
