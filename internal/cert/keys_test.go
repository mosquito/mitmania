package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"
)

func testClusterKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func TestLeafKeyDeterministic(t *testing.T) {
	ck := testClusterKey()
	d := DetKeyDeriver{ClusterKey: ck}

	sans := []string{"b.example.com", "a.example.com", "*.example.com"}
	k1, err := d.LeafKey(sans)
	if err != nil {
		t.Fatalf("LeafKey: %v", err)
	}
	// Same clusterKey + same remote (order-independent SAN set) -> identical key.
	shuffled := []string{"*.example.com", "b.example.com", "a.example.com"}
	k2, err := d.LeafKey(shuffled)
	if err != nil {
		t.Fatalf("LeafKey: %v", err)
	}
	if !k1.Equal(k2) {
		t.Fatalf("LeafKey not deterministic across SAN ordering")
	}

	other := DetKeyDeriver{ClusterKey: bytes.Repeat([]byte{0xAA}, 32)}
	k3, err := other.LeafKey(sans)
	if err != nil {
		t.Fatalf("LeafKey: %v", err)
	}
	if k1.Equal(k3) {
		t.Fatalf("different clusterKey produced the same leaf key")
	}

	diffSans, err := d.LeafKey([]string{"different.example.com"})
	if err != nil {
		t.Fatalf("LeafKey: %v", err)
	}
	if k1.Equal(diffSans) {
		t.Fatalf("different SAN set produced the same leaf key")
	}
}

func TestIntermediateKeyDeterministic(t *testing.T) {
	ck := testClusterKey()
	d := DetKeyDeriver{ClusterKey: ck}

	issuer := []byte("CN=Some Intermediate CA")
	serial := big.NewInt(0x1234)

	k1, err := d.IntermediateKey(issuer, serial)
	if err != nil {
		t.Fatalf("IntermediateKey: %v", err)
	}
	k2, err := d.IntermediateKey(issuer, serial)
	if err != nil {
		t.Fatalf("IntermediateKey: %v", err)
	}
	if !k1.Equal(k2) {
		t.Fatalf("IntermediateKey not deterministic")
	}

	k3, err := d.IntermediateKey(issuer, big.NewInt(0x5678))
	if err != nil {
		t.Fatalf("IntermediateKey: %v", err)
	}
	if k1.Equal(k3) {
		t.Fatalf("different serial produced the same intermediate key")
	}

	leafK, err := d.LeafKey([]string{"example.com"})
	if err != nil {
		t.Fatalf("LeafKey: %v", err)
	}
	if k1.Equal(leafK) {
		t.Fatalf("intermediate and leaf derivations collided")
	}
}

func TestSSHHostKeyDeterministic(t *testing.T) {
	d := DetKeyDeriver{ClusterKey: testClusterKey()}
	k1, err := d.SSHHostKey("example.com:22")
	if err != nil {
		t.Fatalf("SSHHostKey: %v", err)
	}
	k2, err := d.SSHHostKey("example.com:22")
	if err != nil {
		t.Fatalf("SSHHostKey: %v", err)
	}
	if !k1.Equal(k2) {
		t.Fatalf("SSHHostKey not deterministic")
	}
	k3, err := d.SSHHostKey("other.example.com:22")
	if err != nil {
		t.Fatalf("SSHHostKey: %v", err)
	}
	if k1.Equal(k3) {
		t.Fatalf("different host produced the same SSH host key")
	}
}

// TestDeriveKeyLeftPadEdgeCase exercises the one place a naive
// big.Int.Bytes() (without left-padding to 32 bytes) would silently produce
// a key ecdsa.ParseRawPrivateKey rejects: a derived scalar whose top byte(s)
// happen to be zero. We can't force HKDF's output, so instead we directly
// confirm the fixed-length-encoding contract deriveKey relies on: a small
// scalar, left-padded via FillBytes, still parses.
func TestDeriveKeyLeftPadEdgeCase(t *testing.T) {
	small := new(big.Int).SetInt64(1) // big.Int.Bytes() alone would give 1 byte, not 32
	raw := make([]byte, 32)
	small.FillBytes(raw)
	if len(raw) != 32 {
		t.Fatalf("FillBytes produced %d bytes, want 32", len(raw))
	}
	if _, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw); err != nil {
		t.Fatalf("ParseRawPrivateKey rejected a left-padded small scalar: %v", err)
	}
}
