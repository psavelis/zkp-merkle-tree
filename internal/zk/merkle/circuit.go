package merkle

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	poseidon2 "github.com/consensys/gnark/std/permutation/poseidon2"
)

const uint64BitSize = 64

type BalanceUpdateCircuit struct {
	AccountID   frontend.Variable `gnark:",public"`
	Amount      frontend.Variable `gnark:",public"`
	PreRoot     frontend.Variable `gnark:",public"`
	PostRoot    frontend.Variable `gnark:",public"`
	OldBalance  frontend.Variable
	NewBalance  frontend.Variable
	Nonce       frontend.Variable
	PathBits    []frontend.Variable
	OldSiblings []frontend.Variable
	NewSiblings []frontend.Variable
}

func (c *BalanceUpdateCircuit) Define(api frontend.API) error {
	if len(c.PathBits) != len(c.OldSiblings) {
		return fmt.Errorf("old path metadata length mismatch")
	}
	if len(c.PathBits) != len(c.NewSiblings) {
		return fmt.Errorf("new path metadata length mismatch")
	}

	api.ToBinary(c.AccountID, uint64BitSize)
	api.ToBinary(c.Amount, uint64BitSize)
	api.ToBinary(c.OldBalance, uint64BitSize)
	api.ToBinary(c.NewBalance, uint64BitSize)
	api.ToBinary(c.Nonce, uint64BitSize)

	api.AssertIsEqual(c.NewBalance, api.Add(c.OldBalance, c.Amount))

	leafHasher, err := poseidon2.NewPoseidon2FromParameters(api, 3, 8, 56)
	if err != nil {
		return err
	}
	nodeHasher, err := poseidon2.NewPoseidon2FromParameters(api, 2, 8, 56)
	if err != nil {
		return err
	}

	oldState := []frontend.Variable{c.AccountID, c.OldBalance, c.Nonce}
	if err := leafHasher.Permutation(oldState); err != nil {
		return err
	}

	newState := []frontend.Variable{c.AccountID, c.NewBalance, c.Nonce}
	if err := leafHasher.Permutation(newState); err != nil {
		return err
	}

	preRoot, err := c.verifyMembership(api, nodeHasher, oldState[0], c.OldSiblings)
	if err != nil {
		return err
	}
	postRoot, err := c.verifyMembership(api, nodeHasher, newState[0], c.NewSiblings)
	if err != nil {
		return err
	}

	api.AssertIsEqual(c.PreRoot, preRoot)
	api.AssertIsEqual(c.PostRoot, postRoot)

	return nil
}

func (c *BalanceUpdateCircuit) verifyMembership(api frontend.API, hasher *poseidon2.Permutation, current frontend.Variable, siblings []frontend.Variable) (frontend.Variable, error) {
	if len(c.PathBits) != len(siblings) {
		return nil, fmt.Errorf("path bit and sibling length mismatch")
	}
	for index := range siblings {
		api.AssertIsBoolean(c.PathBits[index])
		left := api.Select(c.PathBits[index], siblings[index], current)
		right := api.Select(c.PathBits[index], current, siblings[index])
		state := []frontend.Variable{left, right}
		if err := hasher.Permutation(state); err != nil {
			return nil, err
		}
		current = state[0]
	}
	return current, nil
}
