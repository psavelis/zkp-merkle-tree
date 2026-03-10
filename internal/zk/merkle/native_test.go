package merkle

import (
	"math/big"
	"testing"
)

func TestAccountTreeProofRoundTrip(t *testing.T) {
	tree, err := BuildAccountTree([]AccountLeaf{
		{AccountID: 3, Balance: 11, Nonce: 2},
		{AccountID: 7, Balance: 25, Nonce: 1},
		{AccountID: 9, Balance: 40, Nonce: 4},
		{AccountID: 12, Balance: 7, Nonce: 3},
	})
	if err != nil {
		t.Fatalf("build account tree: %v", err)
	}

	proof, err := tree.Prove(1)
	if err != nil {
		t.Fatalf("prove account leaf: %v", err)
	}

	ok, err := VerifyAccountProof(proof)
	if err != nil {
		t.Fatalf("verify proof: %v", err)
	}
	if !ok {
		t.Fatal("expected account proof to verify")
	}
}

func TestTamperedAccountProofFails(t *testing.T) {
	tree, err := BuildAccountTree([]AccountLeaf{
		{AccountID: 3, Balance: 11, Nonce: 2},
		{AccountID: 7, Balance: 25, Nonce: 1},
		{AccountID: 9, Balance: 40, Nonce: 4},
		{AccountID: 12, Balance: 7, Nonce: 3},
	})
	if err != nil {
		t.Fatalf("build account tree: %v", err)
	}

	proof, err := tree.Prove(1)
	if err != nil {
		t.Fatalf("prove account leaf: %v", err)
	}
	proof.Siblings[0] = new(big.Int).Add(proof.Siblings[0], big.NewInt(1))

	ok, err := VerifyAccountProof(proof)
	if err != nil {
		t.Fatalf("verify proof: %v", err)
	}
	if ok {
		t.Fatal("expected tampered account proof to fail")
	}
}

func TestRejectsNegativeAccountLeafValues(t *testing.T) {
	_, err := BuildAccountTree([]AccountLeaf{{AccountID: -1, Balance: 10, Nonce: 1}})
	if err == nil {
		t.Fatal("expected negative account id to fail")
	}
}
