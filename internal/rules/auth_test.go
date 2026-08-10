package rules

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/crypto/argon2"
)

// testArgon2Hash builds a real, valid $argon2id$... hash for password,
// deterministic (fixed salt) so tests can assert exact behavior.
func testArgon2Hash(password string) string {
	salt := []byte("0123456789abcdef")
	sum := argon2.IDKey([]byte(password), salt, 3, 65536, 4, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum))
}

func testBearerHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestCompileAuth_NilInNilOut(t *testing.T) {
	ca, err := CompileAuth(nil)
	if err != nil || ca != nil {
		t.Fatalf("CompileAuth(nil) = %v, %v; want nil, nil", ca, err)
	}
	ca, err = CompileAuth(&AuthConfig{})
	if err != nil || ca != nil {
		t.Fatalf("CompileAuth(&AuthConfig{}) = %v, %v; want nil, nil (no http_proxy key)", ca, err)
	}
}

func TestCompileAuth_ValidConfig(t *testing.T) {
	ca, err := CompileAuth(&AuthConfig{HTTPProxy: &HTTPProxyAuth{
		Required: true,
		Realm:    "corp",
		Basic:    []BasicCredential{{User: "alice", Hash: testArgon2Hash("s3cret")}},
		Bearer:   []BearerCredential{{ID: "ci-bot", Hash: testBearerHash("tok123")}},
	}})
	if err != nil {
		t.Fatalf("CompileAuth: %v", err)
	}
	if !ca.Required || ca.Realm != "corp" {
		t.Errorf("compiled fields wrong: %+v", ca)
	}
}

func TestCompileAuth_DefaultRealm(t *testing.T) {
	ca, err := CompileAuth(&AuthConfig{HTTPProxy: &HTTPProxyAuth{
		Basic: []BasicCredential{{User: "alice", Hash: testArgon2Hash("x")}},
	}})
	if err != nil {
		t.Fatalf("CompileAuth: %v", err)
	}
	if ca.Realm != "mitmania" {
		t.Errorf("Realm = %q, want default %q", ca.Realm, "mitmania")
	}
}

func TestCompileAuth_RequiredWithNoSchemeRejected(t *testing.T) {
	_, err := CompileAuth(&AuthConfig{HTTPProxy: &HTTPProxyAuth{Required: true}})
	if err == nil {
		t.Fatalf("expected an error for required:true with no scheme configured")
	}
}

func TestCompileAuth_BrokerMutualExclusivity(t *testing.T) {
	cases := []struct {
		name   string
		broker *AuthBroker
	}{
		{"neither", &AuthBroker{}},
		{"both", &AuthBroker{Socket: "/run/authn.sock", URL: "https://authn.example/"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := CompileAuth(&AuthConfig{HTTPProxy: &HTTPProxyAuth{Broker: c.broker}})
			if err == nil {
				t.Fatalf("expected an error for broker with %s of socket/url", c.name)
			}
		})
	}
}

func TestCompileAuth_BrokerSocketDefaultsPath(t *testing.T) {
	ca, err := CompileAuth(&AuthConfig{HTTPProxy: &HTTPProxyAuth{Broker: &AuthBroker{Socket: "/run/authn.sock"}}})
	if err != nil {
		t.Fatalf("CompileAuth: %v", err)
	}
	if ca.Broker.Path != "/" {
		t.Errorf("Broker.Path = %q, want \"/\" default", ca.Broker.Path)
	}
}

func TestCompileAuth_BrokerURLWithPathRejected(t *testing.T) {
	_, err := CompileAuth(&AuthConfig{HTTPProxy: &HTTPProxyAuth{
		Broker: &AuthBroker{URL: "https://authn.example/", Path: "/authn"},
	}})
	if err == nil {
		t.Fatalf("expected an error for \"path\" alongside a url target")
	}
}

func TestCompileAuth_MalformedBasicHashRejected(t *testing.T) {
	_, err := CompileAuth(&AuthConfig{HTTPProxy: &HTTPProxyAuth{
		Basic: []BasicCredential{{User: "alice", Hash: "not-a-hash"}},
	}})
	if err == nil {
		t.Fatalf("expected an error for a malformed basic hash")
	}
}

func TestCompileAuth_MalformedBearerHashRejected(t *testing.T) {
	_, err := CompileAuth(&AuthConfig{HTTPProxy: &HTTPProxyAuth{
		Bearer: []BearerCredential{{ID: "ci", Hash: "not-a-hash"}},
	}})
	if err == nil {
		t.Fatalf("expected an error for a malformed bearer hash")
	}
}

func TestCompileAuth_EmptyUserOrIDRejected(t *testing.T) {
	if _, err := CompileAuth(&AuthConfig{HTTPProxy: &HTTPProxyAuth{
		Basic: []BasicCredential{{User: "", Hash: testArgon2Hash("x")}},
	}}); err == nil {
		t.Fatalf("expected an error for an empty basic user")
	}
	if _, err := CompileAuth(&AuthConfig{HTTPProxy: &HTTPProxyAuth{
		Bearer: []BearerCredential{{ID: "", Hash: testBearerHash("x")}},
	}}); err == nil {
		t.Fatalf("expected an error for an empty bearer id")
	}
}

func TestCompileAuth_DuplicateUserOrIDRejected(t *testing.T) {
	if _, err := CompileAuth(&AuthConfig{HTTPProxy: &HTTPProxyAuth{
		Basic: []BasicCredential{
			{User: "alice", Hash: testArgon2Hash("a")},
			{User: "alice", Hash: testArgon2Hash("b")},
		},
	}}); err == nil {
		t.Fatalf("expected an error for a duplicate basic user")
	}
	if _, err := CompileAuth(&AuthConfig{HTTPProxy: &HTTPProxyAuth{
		Bearer: []BearerCredential{
			{ID: "ci", Hash: testBearerHash("a")},
			{ID: "ci", Hash: testBearerHash("b")},
		},
	}}); err == nil {
		t.Fatalf("expected an error for a duplicate bearer id")
	}
}

func TestCompiledAuth_ChallengeSchemes(t *testing.T) {
	tests := []struct {
		name string
		hp   HTTPProxyAuth
		want []string
	}{
		{"basic only", HTTPProxyAuth{Basic: []BasicCredential{{User: "a", Hash: testArgon2Hash("x")}}}, []string{"Basic"}},
		{"bearer only", HTTPProxyAuth{Bearer: []BearerCredential{{ID: "a", Hash: testBearerHash("x")}}}, []string{"Bearer"}},
		{"broker only", HTTPProxyAuth{Broker: &AuthBroker{Socket: "/s"}}, []string{"Basic", "Bearer"}},
		{"basic and bearer", HTTPProxyAuth{
			Basic:  []BasicCredential{{User: "a", Hash: testArgon2Hash("x")}},
			Bearer: []BearerCredential{{ID: "a", Hash: testBearerHash("x")}},
		}, []string{"Basic", "Bearer"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca, err := CompileAuth(&AuthConfig{HTTPProxy: &tt.hp})
			if err != nil {
				t.Fatalf("CompileAuth: %v", err)
			}
			got := ca.ChallengeSchemes()
			if len(got) != len(tt.want) {
				t.Fatalf("ChallengeSchemes() = %v, want %v", got, tt.want)
			}
			for i, s := range tt.want {
				if got[i] != s {
					t.Errorf("ChallengeSchemes()[%d] = %q, want %q", i, got[i], s)
				}
			}
		})
	}
}

func TestCompiledAuth_Authenticate_Basic(t *testing.T) {
	ca, err := CompileAuth(&AuthConfig{HTTPProxy: &HTTPProxyAuth{
		Basic: []BasicCredential{{User: "alice", Hash: testArgon2Hash("s3cret")}},
	}})
	if err != nil {
		t.Fatalf("CompileAuth: %v", err)
	}

	good := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	if ok, principal := ca.Authenticate(good); !ok || principal != "alice" {
		t.Errorf("Authenticate(good) = %v, %q; want true, \"alice\"", ok, principal)
	}

	bad := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:wrong"))
	if ok, _ := ca.Authenticate(bad); ok {
		t.Errorf("Authenticate(wrong password) = true, want false")
	}

	unknownUser := "Basic " + base64.StdEncoding.EncodeToString([]byte("mallory:s3cret"))
	if ok, _ := ca.Authenticate(unknownUser); ok {
		t.Errorf("Authenticate(unknown user) = true, want false")
	}
}

func TestCompiledAuth_Authenticate_Bearer(t *testing.T) {
	ca, err := CompileAuth(&AuthConfig{HTTPProxy: &HTTPProxyAuth{
		Bearer: []BearerCredential{{ID: "ci-bot", Hash: testBearerHash("tok-good")}},
	}})
	if err != nil {
		t.Fatalf("CompileAuth: %v", err)
	}

	if ok, principal := ca.Authenticate("Bearer tok-good"); !ok || principal != "ci-bot" {
		t.Errorf("Authenticate(good token) = %v, %q; want true, \"ci-bot\"", ok, principal)
	}
	if ok, _ := ca.Authenticate("Bearer tok-bad"); ok {
		t.Errorf("Authenticate(wrong token) = true, want false")
	}
}

func TestCompiledAuth_Authenticate_MalformedOrUnknownScheme(t *testing.T) {
	ca, err := CompileAuth(&AuthConfig{HTTPProxy: &HTTPProxyAuth{
		Basic: []BasicCredential{{User: "alice", Hash: testArgon2Hash("x")}},
	}})
	if err != nil {
		t.Fatalf("CompileAuth: %v", err)
	}
	cases := []string{"", "Basic", "Digest " + base64.StdEncoding.EncodeToString([]byte("alice:x")), "garbage-no-space-but-also-no-scheme-match"}
	for _, c := range cases {
		if ok, _ := ca.Authenticate(c); ok {
			t.Errorf("Authenticate(%q) = true, want false", c)
		}
	}
}

func TestVerifyArgon2id(t *testing.T) {
	hash := testArgon2Hash("correct horse battery staple")
	if ok, err := verifyArgon2id(hash, "correct horse battery staple"); err != nil || !ok {
		t.Errorf("verifyArgon2id(correct) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := verifyArgon2id(hash, "wrong password"); err != nil || ok {
		t.Errorf("verifyArgon2id(wrong) = %v, %v; want false, nil", ok, err)
	}
	if _, err := verifyArgon2id("not-a-hash", "x"); err == nil {
		t.Errorf("verifyArgon2id(malformed hash) expected an error")
	}
}

func TestVerifyBearerToken(t *testing.T) {
	hash := testBearerHash("my-token")
	if ok, err := verifyBearerToken(hash, "my-token"); err != nil || !ok {
		t.Errorf("verifyBearerToken(correct) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := verifyBearerToken(hash, "other-token"); err != nil || ok {
		t.Errorf("verifyBearerToken(wrong) = %v, %v; want false, nil", ok, err)
	}
	if _, err := verifyBearerToken("not-a-hash", "x"); err == nil {
		t.Errorf("verifyBearerToken(malformed hash) expected an error")
	}
	if _, err := verifyBearerToken("sha256:zz", "x"); err == nil {
		t.Errorf("verifyBearerToken(bad hex) expected an error")
	}
}
