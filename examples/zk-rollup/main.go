package main

import (
	"fmt"

	zkprover "github.com/psavelis/zkp-merkle-tree/internal/zk/prover"
	zkrollup "github.com/psavelis/zkp-merkle-tree/internal/zk/rollup"
)

func main() {
	scenario, err := zkrollup.BuildBalanceUpdateScenario(7, 25, 10, 1)
	if err != nil {
		panic(err)
	}

	proofResult, err := zkprover.ProveBalanceUpdate(zkprover.BalanceUpdateInput{
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
		panic(err)
	}

	fmt.Println("ZK rollup-style state commitment demo")
	fmt.Printf("Pre-state root:  %s\n", scenario.PreTree.Root())
	fmt.Printf("Post-state root: %s\n", scenario.PostTree.Root())
	fmt.Printf("Proof depth: %d\n", proofResult.ProofDepth)
	fmt.Printf("Commitment proof verified: %t\n", proofResult.Verified)
	fmt.Printf("Constraints: %d\n", proofResult.ConstraintCount)
	fmt.Printf("Process-local prover cache status: %s\n", proofResult.CacheStatus)
	fmt.Printf("Security note: roots are public, while balances and Merkle sibling paths stay inside the witness.\n")
}
