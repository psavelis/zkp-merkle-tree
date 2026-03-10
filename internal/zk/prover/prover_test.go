package prover

import (
	"math/big"
	"testing"

	zkmerkle "github.com/psavelis/zkp-merkle-tree/internal/zk/merkle"
	zkrollup "github.com/psavelis/zkp-merkle-tree/internal/zk/rollup"
)

func TestProveBalanceUpdate(t *testing.T) {
	scenario, err := zkrollup.BuildBalanceUpdateScenario(7, 25, 10, 1)
	if err != nil {
		t.Fatalf("build scenario: %v", err)
	}

	result, err := ProveBalanceUpdate(BalanceUpdateInput{
		AccountID:   scenario.AccountID,
		OldBalance:  scenario.OldBalance,
		Amount:      scenario.Amount,
		Nonce:       scenario.Nonce,
		PreRoot:     scenario.PreProof.Root,
		PostRoot:    scenario.PostProof.Root,
		PathBits:    scenario.PreProof.PathBits,
		OldSiblings: scenario.PreProof.Siblings,
		NewSiblings: scenario.PostProof.Siblings,
	})
	if err != nil {
		t.Fatalf("prove balance update: %v", err)
	}
	if !result.Verified {
		t.Fatal("expected proof to verify")
	}
	if result.ConstraintCount == 0 {
		t.Fatal("expected non-zero constraint count")
	}
}

func TestProveBalanceUpdateUsesCacheWithinProcess(t *testing.T) {
	balanceCircuitCache = newBalanceCircuitArtifactsCache()

	scenario, err := zkrollup.BuildBalanceUpdateScenario(7, 25, 10, 1)
	if err != nil {
		t.Fatalf("build scenario: %v", err)
	}
	input := BalanceUpdateInput{
		AccountID:   scenario.AccountID,
		OldBalance:  scenario.OldBalance,
		Amount:      scenario.Amount,
		Nonce:       scenario.Nonce,
		PreRoot:     scenario.PreProof.Root,
		PostRoot:    scenario.PostProof.Root,
		PathBits:    scenario.PreProof.PathBits,
		OldSiblings: scenario.PreProof.Siblings,
		NewSiblings: scenario.PostProof.Siblings,
	}

	first, err := ProveBalanceUpdate(input)
	if err != nil {
		t.Fatalf("first prove balance update: %v", err)
	}
	second, err := ProveBalanceUpdate(input)
	if err != nil {
		t.Fatalf("second prove balance update: %v", err)
	}
	if first.CacheStatus != "miss" {
		t.Fatalf("expected first cache status miss, got %q", first.CacheStatus)
	}
	if second.CacheStatus != "hit" {
		t.Fatalf("expected second cache status hit, got %q", second.CacheStatus)
	}
}

func TestProveBalanceUpdateRejectsTamperedRoot(t *testing.T) {
	scenario, err := zkrollup.BuildBalanceUpdateScenario(7, 25, 10, 1)
	if err != nil {
		t.Fatalf("build scenario: %v", err)
	}
	tamperedRoot := new(big.Int).Add(scenario.PreProof.Root, big.NewInt(1))

	_, err = ProveBalanceUpdate(BalanceUpdateInput{
		AccountID:   scenario.AccountID,
		OldBalance:  scenario.OldBalance,
		Amount:      scenario.Amount,
		Nonce:       scenario.Nonce,
		PreRoot:     tamperedRoot,
		PostRoot:    scenario.PostProof.Root,
		PathBits:    scenario.PreProof.PathBits,
		OldSiblings: scenario.PreProof.Siblings,
		NewSiblings: scenario.PostProof.Siblings,
	})
	if err == nil {
		t.Fatal("expected tampered root to fail")
	}
}

func TestProveBalanceUpdateRejectsNilSibling(t *testing.T) {
	scenario, err := zkrollup.BuildBalanceUpdateScenario(7, 25, 10, 1)
	if err != nil {
		t.Fatalf("build scenario: %v", err)
	}

	oldSiblings := append([]*big.Int(nil), scenario.PreProof.Siblings...)
	oldSiblings[0] = nil

	_, err = ProveBalanceUpdate(BalanceUpdateInput{
		AccountID:   scenario.AccountID,
		OldBalance:  scenario.OldBalance,
		Amount:      scenario.Amount,
		Nonce:       scenario.Nonce,
		PreRoot:     scenario.PreProof.Root,
		PostRoot:    scenario.PostProof.Root,
		PathBits:    scenario.PreProof.PathBits,
		OldSiblings: oldSiblings,
		NewSiblings: scenario.PostProof.Siblings,
	})
	if err == nil {
		t.Fatal("expected nil sibling to fail")
	}
}

func TestProveBalanceUpdateRejectsBalanceOverflow(t *testing.T) {
	_, err := ProveBalanceUpdate(BalanceUpdateInput{
		AccountID:   7,
		OldBalance:  int(^uint(0) >> 1),
		Amount:      1,
		Nonce:       1,
		PreRoot:     big.NewInt(1),
		PostRoot:    big.NewInt(1),
		PathBits:    []bool{false},
		OldSiblings: []*big.Int{big.NewInt(1)},
		NewSiblings: []*big.Int{big.NewInt(1)},
	})
	if err == nil {
		t.Fatal("expected balance overflow to fail")
	}
	if got := err.Error(); got != "compute new balance: integer overflow" {
		t.Fatalf("unexpected error: %s", got)
	}
}

func TestProveBalanceUpdateRejectsInvalidInputs(t *testing.T) {
	testCases := []struct {
		name      string
		input     BalanceUpdateInput
		wantError string
	}{
		{
			name: "negative amount",
			input: BalanceUpdateInput{
				AccountID:   7,
				OldBalance:  25,
				Amount:      -1,
				Nonce:       1,
				PreRoot:     big.NewInt(1),
				PostRoot:    big.NewInt(1),
				PathBits:    []bool{},
				OldSiblings: []*big.Int{},
				NewSiblings: []*big.Int{},
			},
			wantError: "amount must be non-negative",
		},
		{
			name: "negative fields",
			input: BalanceUpdateInput{
				AccountID:   -1,
				OldBalance:  25,
				Amount:      1,
				Nonce:       1,
				PreRoot:     big.NewInt(1),
				PostRoot:    big.NewInt(1),
				PathBits:    []bool{},
				OldSiblings: []*big.Int{},
				NewSiblings: []*big.Int{},
			},
			wantError: "account id, old balance, and nonce must be non-negative",
		},
		{
			name: "path mismatch",
			input: BalanceUpdateInput{
				AccountID:   7,
				OldBalance:  25,
				Amount:      1,
				Nonce:       1,
				PreRoot:     big.NewInt(1),
				PostRoot:    big.NewInt(1),
				PathBits:    []bool{false},
				OldSiblings: []*big.Int{},
				NewSiblings: []*big.Int{},
			},
			wantError: "path metadata length mismatch",
		},
		{
			name: "missing roots",
			input: BalanceUpdateInput{
				AccountID:   7,
				OldBalance:  25,
				Amount:      1,
				Nonce:       1,
				PathBits:    []bool{},
				OldSiblings: []*big.Int{},
				NewSiblings: []*big.Int{},
			},
			wantError: "pre-root and post-root are required",
		},
		{
			name: "nil old sibling",
			input: BalanceUpdateInput{
				AccountID:   7,
				OldBalance:  25,
				Amount:      1,
				Nonce:       1,
				PreRoot:     big.NewInt(1),
				PostRoot:    big.NewInt(1),
				PathBits:    []bool{false},
				OldSiblings: []*big.Int{nil},
				NewSiblings: []*big.Int{big.NewInt(1)},
			},
			wantError: "old siblings entry 0 is required",
		},
		{
			name: "nil new sibling",
			input: BalanceUpdateInput{
				AccountID:   7,
				OldBalance:  25,
				Amount:      1,
				Nonce:       1,
				PreRoot:     big.NewInt(1),
				PostRoot:    big.NewInt(1),
				PathBits:    []bool{false},
				OldSiblings: []*big.Int{big.NewInt(1)},
				NewSiblings: []*big.Int{nil},
			},
			wantError: "new siblings entry 0 is required",
		},
	}

	for _, testCase := range testCases {
		_, err := ProveBalanceUpdate(testCase.input)
		if err == nil {
			t.Fatalf("%s: expected error", testCase.name)
		}
		if got := err.Error(); got != testCase.wantError {
			t.Fatalf("%s: unexpected error %s", testCase.name, got)
		}
	}
}

func TestProveBalanceUpdateAllowsZeroDepthProof(t *testing.T) {
	preTree, err := zkmerkle.BuildAccountTree([]zkmerkle.AccountLeaf{{AccountID: 7, Balance: 25, Nonce: 1}})
	if err != nil {
		t.Fatalf("build pre-tree: %v", err)
	}
	postTree, err := zkmerkle.BuildAccountTree([]zkmerkle.AccountLeaf{{AccountID: 7, Balance: 35, Nonce: 1}})
	if err != nil {
		t.Fatalf("build post-tree: %v", err)
	}

	preProof, err := preTree.Prove(0)
	if err != nil {
		t.Fatalf("prove pre-tree leaf: %v", err)
	}
	postProof, err := postTree.Prove(0)
	if err != nil {
		t.Fatalf("prove post-tree leaf: %v", err)
	}

	result, err := ProveBalanceUpdate(BalanceUpdateInput{
		AccountID:   7,
		OldBalance:  25,
		Amount:      10,
		Nonce:       1,
		PreRoot:     preProof.Root,
		PostRoot:    postProof.Root,
		PathBits:    preProof.PathBits,
		OldSiblings: preProof.Siblings,
		NewSiblings: postProof.Siblings,
	})
	if err != nil {
		t.Fatalf("prove zero-depth balance update: %v", err)
	}
	if !result.Verified {
		t.Fatal("expected zero-depth proof to verify")
	}
	if result.ProofDepth != 0 {
		t.Fatalf("expected proof depth 0, got %d", result.ProofDepth)
	}
}
