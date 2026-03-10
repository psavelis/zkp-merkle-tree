package prover

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	zkints "github.com/psavelis/zkp-merkle-tree/internal/zk/ints"
	zkmerkle "github.com/psavelis/zkp-merkle-tree/internal/zk/merkle"
)

var balanceCircuitCache = newBalanceCircuitArtifactsCache()

type balanceCircuitArtifacts struct {
	ccs constraint.ConstraintSystem
	pk  groth16.ProvingKey
	vk  groth16.VerifyingKey
}

type balanceCircuitArtifactsEntry struct {
	ready     chan struct{}
	artifacts balanceCircuitArtifacts
	err       error
}

type balanceCircuitArtifactsCache struct {
	mu      sync.RWMutex
	entries map[int]*balanceCircuitArtifactsEntry
}

func newBalanceCircuitArtifactsCache() *balanceCircuitArtifactsCache {
	return &balanceCircuitArtifactsCache{entries: make(map[int]*balanceCircuitArtifactsEntry)}
}

type BalanceUpdateInput struct {
	AccountID   int
	OldBalance  int
	Amount      int
	Nonce       int
	PreRoot     *big.Int
	PostRoot    *big.Int
	PathBits    []bool
	OldSiblings []*big.Int
	NewSiblings []*big.Int
}

type BalanceUpdateResult struct {
	AccountID       int    `json:"account_id"`
	Amount          int    `json:"amount"`
	PreRoot         string `json:"pre_root"`
	PostRoot        string `json:"post_root"`
	OldCommitment   string `json:"old_commitment"`
	NewCommitment   string `json:"new_commitment"`
	ProofDepth      int    `json:"proof_depth"`
	ConstraintCount int    `json:"constraint_count"`
	Verified        bool   `json:"verified"`
	CommitmentHash  string `json:"commitment_hash"`
	CacheStatus     string `json:"cache_status"`
}

func ProveBalanceUpdate(input BalanceUpdateInput) (BalanceUpdateResult, error) {
	if input.Amount < 0 {
		return BalanceUpdateResult{}, fmt.Errorf("amount must be non-negative")
	}
	if input.AccountID < 0 || input.OldBalance < 0 || input.Nonce < 0 {
		return BalanceUpdateResult{}, fmt.Errorf("account id, old balance, and nonce must be non-negative")
	}
	if len(input.PathBits) != len(input.OldSiblings) || len(input.PathBits) != len(input.NewSiblings) {
		return BalanceUpdateResult{}, fmt.Errorf("path metadata length mismatch")
	}
	if input.PreRoot == nil || input.PostRoot == nil {
		return BalanceUpdateResult{}, fmt.Errorf("pre-root and post-root are required")
	}
	if err := validateBigIntSlice("old siblings", input.OldSiblings); err != nil {
		return BalanceUpdateResult{}, err
	}
	if err := validateBigIntSlice("new siblings", input.NewSiblings); err != nil {
		return BalanceUpdateResult{}, err
	}

	newBalance, err := zkints.CheckedAdd(input.OldBalance, input.Amount)
	if err != nil {
		return BalanceUpdateResult{}, fmt.Errorf("compute new balance: %w", err)
	}

	oldCommitment, err := zkmerkle.AccountCommitment(input.AccountID, input.OldBalance, input.Nonce)
	if err != nil {
		return BalanceUpdateResult{}, err
	}
	newCommitment, err := zkmerkle.AccountCommitment(input.AccountID, newBalance, input.Nonce)
	if err != nil {
		return BalanceUpdateResult{}, err
	}

	artifacts, cacheStatus, err := balanceCircuitCache.get(len(input.PathBits))
	if err != nil {
		return BalanceUpdateResult{}, err
	}

	pathBits := make([]frontend.Variable, len(input.PathBits))
	for index, bit := range input.PathBits {
		if bit {
			pathBits[index] = 1
		} else {
			pathBits[index] = 0
		}
	}

	oldSiblingVariables, err := bigIntVariables(input.OldSiblings)
	if err != nil {
		return BalanceUpdateResult{}, err
	}
	newSiblingVariables, err := bigIntVariables(input.NewSiblings)
	if err != nil {
		return BalanceUpdateResult{}, err
	}

	assignment := zkmerkle.BalanceUpdateCircuit{
		AccountID:   input.AccountID,
		Amount:      input.Amount,
		PreRoot:     input.PreRoot.String(),
		PostRoot:    input.PostRoot.String(),
		OldBalance:  input.OldBalance,
		NewBalance:  newBalance,
		Nonce:       input.Nonce,
		PathBits:    pathBits,
		OldSiblings: oldSiblingVariables,
		NewSiblings: newSiblingVariables,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return BalanceUpdateResult{}, fmt.Errorf("build witness: %w", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		return BalanceUpdateResult{}, fmt.Errorf("extract public witness: %w", err)
	}

	proof, err := groth16.Prove(artifacts.ccs, artifacts.pk, witness)
	if err != nil {
		return BalanceUpdateResult{}, fmt.Errorf("prove statement: %w", err)
	}
	if err := groth16.Verify(proof, artifacts.vk, publicWitness); err != nil {
		return BalanceUpdateResult{}, fmt.Errorf("verify proof: %w", err)
	}

	return BalanceUpdateResult{
		AccountID:       input.AccountID,
		Amount:          input.Amount,
		PreRoot:         input.PreRoot.String(),
		PostRoot:        input.PostRoot.String(),
		OldCommitment:   oldCommitment.String(),
		NewCommitment:   newCommitment.String(),
		ProofDepth:      len(input.PathBits),
		ConstraintCount: artifacts.ccs.GetNbConstraints(),
		Verified:        true,
		CommitmentHash:  "poseidon2-permutation",
		CacheStatus:     cacheStatus,
	}, nil
}

func (cache *balanceCircuitArtifactsCache) get(depth int) (balanceCircuitArtifacts, string, error) {
	cache.mu.RLock()
	entry, ok := cache.entries[depth]
	cache.mu.RUnlock()
	if ok {
		<-entry.ready
		if entry.err != nil {
			return balanceCircuitArtifacts{}, "hit", entry.err
		}
		return entry.artifacts, "hit", nil
	}

	cache.mu.Lock()
	entry, ok = cache.entries[depth]
	if !ok {
		entry = &balanceCircuitArtifactsEntry{ready: make(chan struct{})}
		cache.entries[depth] = entry
		cache.mu.Unlock()

		var circuit zkmerkle.BalanceUpdateCircuit
		circuit.PathBits = make([]frontend.Variable, depth)
		circuit.OldSiblings = make([]frontend.Variable, depth)
		circuit.NewSiblings = make([]frontend.Variable, depth)
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			entry.err = fmt.Errorf("compile circuit: %w", err)
			close(entry.ready)
			cache.mu.Lock()
			delete(cache.entries, depth)
			cache.mu.Unlock()
			return balanceCircuitArtifacts{}, "miss", entry.err
		}
		pk, vk, err := groth16.Setup(ccs)
		if err != nil {
			entry.err = fmt.Errorf("setup proving system: %w", err)
			close(entry.ready)
			cache.mu.Lock()
			delete(cache.entries, depth)
			cache.mu.Unlock()
			return balanceCircuitArtifacts{}, "miss", entry.err
		}

		entry.artifacts = balanceCircuitArtifacts{ccs: ccs, pk: pk, vk: vk}
		close(entry.ready)
		return entry.artifacts, "miss", nil
	}
	cache.mu.Unlock()

	<-entry.ready
	if entry.err != nil {
		return balanceCircuitArtifacts{}, "hit", entry.err
	}
	return entry.artifacts, "hit", nil
}

func validateBigIntSlice(label string, values []*big.Int) error {
	for index, value := range values {
		if value == nil {
			return fmt.Errorf("%s entry %d is required", label, index)
		}
	}
	return nil
}

func bigIntVariables(values []*big.Int) ([]frontend.Variable, error) {
	items := make([]frontend.Variable, len(values))
	for index, value := range values {
		if value == nil {
			return nil, fmt.Errorf("big integer entry %d is required", index)
		}
		items[index] = value.String()
	}
	return items, nil
}
