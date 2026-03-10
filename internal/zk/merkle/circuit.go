package merkle

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	poseidon2 "github.com/consensys/gnark/std/permutation/poseidon2"
)

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
	api.AssertIsEqual(c.NewBalance, api.Add(c.OldBalance, c.Amount))

	leafHasher := poseidon2.NewHash(3, 5, 8, 56, "leaf", ecc.BN254)
	nodeHasher := poseidon2.NewHash(3, 5, 8, 56, "node", ecc.BN254)

	oldState := []frontend.Variable{c.AccountID, c.OldBalance, c.Nonce}
	if err := leafHasher.Permutation(api, oldState); err != nil {
		return err
	}

	newState := []frontend.Variable{c.AccountID, c.NewBalance, c.Nonce}
	if err := leafHasher.Permutation(api, newState); err != nil {
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

func (c *BalanceUpdateCircuit) verifyMembership(api frontend.API, hasher poseidon2.Hash, current frontend.Variable, siblings []frontend.Variable) (frontend.Variable, error) {
	for index := range siblings {
		api.AssertIsBoolean(c.PathBits[index])
		left := api.Select(c.PathBits[index], siblings[index], current)
		right := api.Select(c.PathBits[index], current, siblings[index])
		state := []frontend.Variable{left, right, 0}
		if err := hasher.Permutation(api, state); err != nil {
			return nil, err
		}
		current = state[0]
	}
	return current, nil
}
