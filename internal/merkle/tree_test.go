package merkle

import (
	"encoding/json"
	"os"
	"testing"

	internalhash "github.com/psavelis/zkp-merkle-tree/internal/hash"
)

func TestSHA256ProofRoundTrip(t *testing.T) {
	hasher := internalhash.NewSHA256Hasher()
	tree, err := Build(hasher, [][]byte{[]byte("alice"), []byte("bob"), []byte("carol")})
	if err != nil {
		t.Fatalf("build tree: %v", err)
	}

	proof, err := tree.Prove(1)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}

	parsed, err := ParseProof(encoded)
	if err != nil {
		t.Fatalf("parse proof: %v", err)
	}

	ok, err := Verify(hasher, parsed)
	if err != nil {
		t.Fatalf("verify proof: %v", err)
	}
	if !ok {
		t.Fatal("expected proof to verify")
	}
}

func TestPoseidonProofRoundTrip(t *testing.T) {
	hasher := internalhash.NewPoseidonHasher()
	tree, err := Build(hasher, [][]byte{[]byte("alpha"), []byte("beta"), []byte("gamma"), []byte("delta")})
	if err != nil {
		t.Fatalf("build tree: %v", err)
	}

	proof, err := tree.Prove(2)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	ok, err := Verify(hasher, proof)
	if err != nil {
		t.Fatalf("verify proof: %v", err)
	}
	if !ok {
		t.Fatal("expected poseidon proof to verify")
	}
}

func TestTamperedProofFails(t *testing.T) {
	hasher := internalhash.NewSHA256Hasher()
	tree, err := Build(hasher, [][]byte{[]byte("alice"), []byte("bob")})
	if err != nil {
		t.Fatalf("build tree: %v", err)
	}

	proof, err := tree.Prove(0)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	proof.Leaf = "mallory"
	proof.rawLeaf = []byte("mallory")

	ok, err := Verify(hasher, proof)
	if err != nil {
		t.Fatalf("verify proof: %v", err)
	}
	if ok {
		t.Fatal("expected tampered proof to fail")
	}
}

func TestBinaryLeafProofRoundTrip(t *testing.T) {
	hasher := internalhash.NewSHA256Hasher()
	tree, err := Build(hasher, [][]byte{{0x00, 0xff, 0x10, 0x80}, []byte("text")})
	if err != nil {
		t.Fatalf("build tree: %v", err)
	}

	proof, err := tree.Prove(0)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}

	parsed, err := ParseProof(encoded)
	if err != nil {
		t.Fatalf("parse proof: %v", err)
	}

	ok, err := Verify(hasher, parsed)
	if err != nil {
		t.Fatalf("verify proof: %v", err)
	}
	if !ok {
		t.Fatal("expected binary proof to verify")
	}
}

func TestPoseidonLeafEncodingDistinguishesLengthsAndLeadingZeros(t *testing.T) {
	hasher := internalhash.NewPoseidonHasher()

	testCases := []struct {
		name string
		leaf []byte
	}{
		{name: "empty", leaf: []byte{}},
		{name: "single zero", leaf: []byte{0x00}},
		{name: "double zero", leaf: []byte{0x00, 0x00}},
		{name: "leading zero text", leaf: []byte{0x00, 'a'}},
		{name: "plain text", leaf: []byte{'a'}},
	}

	seen := make(map[string]string, len(testCases))
	for _, testCase := range testCases {
		digest, err := hasher.HashLeaf(testCase.leaf)
		if err != nil {
			t.Fatalf("hash leaf %s: %v", testCase.name, err)
		}
		if previous, exists := seen[digest.String()]; exists {
			t.Fatalf("leaf %s collided with %s", testCase.name, previous)
		}
		seen[digest.String()] = testCase.name
	}
}

func TestParseProofSupportsLegacyLeafEncoding(t *testing.T) {
	data, err := os.ReadFile("../../testdata/sample-proof.json")
	if err != nil {
		t.Fatalf("read sample proof: %v", err)
	}

	proof, err := ParseProof(data)
	if err != nil {
		t.Fatalf("parse proof: %v", err)
	}
	if proof.LeafBase64 != "" {
		t.Fatal("expected legacy proof without leaf_base64")
	}

	ok, err := Verify(internalhash.NewSHA256Hasher(), proof)
	if err != nil {
		t.Fatalf("verify proof: %v", err)
	}
	if !ok {
		t.Fatal("expected legacy proof to verify")
	}
}
