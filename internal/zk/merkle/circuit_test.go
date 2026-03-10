package merkle

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	gnarktest "github.com/consensys/gnark/test"
)

func TestBalanceUpdateCircuitRejectsOldPathLengthMismatch(t *testing.T) {
	circuit := BalanceUpdateCircuit{
		PathBits:    []frontend.Variable{0},
		OldSiblings: []frontend.Variable{},
		NewSiblings: []frontend.Variable{0},
	}

	if err := circuit.Define(nil); err == nil {
		t.Fatal("expected old path mismatch to fail")
	}
}

func TestBalanceUpdateCircuitRejectsNewPathLengthMismatch(t *testing.T) {
	circuit := BalanceUpdateCircuit{
		PathBits:    []frontend.Variable{0},
		OldSiblings: []frontend.Variable{0},
		NewSiblings: []frontend.Variable{},
	}

	if err := circuit.Define(nil); err == nil {
		t.Fatal("expected new path mismatch to fail")
	}
}

func TestBalanceUpdateCircuitRejectsValuesOutsideUint64(t *testing.T) {
	oversizedAccountID := new(big.Int).Lsh(big.NewInt(1), 65)
	oldBalance := big.NewInt(25)
	amount := big.NewInt(10)
	newBalance := big.NewInt(35)
	nonce := big.NewInt(1)

	preRoot, err := poseidon2Permutation(3, []bn254fr.Element{
		bigIntToElement(oversizedAccountID),
		bigIntToElement(oldBalance),
		bigIntToElement(nonce),
	})
	if err != nil {
		t.Fatalf("compute pre-root: %v", err)
	}
	postRoot, err := poseidon2Permutation(3, []bn254fr.Element{
		bigIntToElement(oversizedAccountID),
		bigIntToElement(newBalance),
		bigIntToElement(nonce),
	})
	if err != nil {
		t.Fatalf("compute post-root: %v", err)
	}

	circuit := &BalanceUpdateCircuit{}
	assignment := &BalanceUpdateCircuit{
		AccountID:   oversizedAccountID.String(),
		Amount:      amount.String(),
		PreRoot:     preRoot.String(),
		PostRoot:    postRoot.String(),
		OldBalance:  oldBalance.String(),
		NewBalance:  newBalance.String(),
		Nonce:       nonce.String(),
		PathBits:    []frontend.Variable{},
		OldSiblings: []frontend.Variable{},
		NewSiblings: []frontend.Variable{},
	}

	if err := gnarktest.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected oversized account id to violate uint64 range constraints")
	}
}

func bigIntToElement(value *big.Int) bn254fr.Element {
	var element bn254fr.Element
	element.SetBigInt(value)
	return element
}
