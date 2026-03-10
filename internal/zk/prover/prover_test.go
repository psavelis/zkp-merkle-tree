package prover

import (
	"math/big"
	"testing"

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
