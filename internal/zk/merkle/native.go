package merkle

import (
	"errors"
	"fmt"
	"math/big"

	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

var ErrNoAccounts = errors.New("account tree requires at least one account")
var ErrInvalidAccountLeaf = errors.New("account leaf values must be non-negative")
var ErrNilNodeInput = errors.New("node commitment inputs are required")

type AccountLeaf struct {
	AccountID int
	Balance   int
	Nonce     int
}

type AccountTree struct {
	leaves     []AccountLeaf
	leafHashes []*big.Int
	levels     [][]*big.Int
}

type AccountProof struct {
	Leaf      AccountLeaf
	LeafIndex int
	LeafHash  *big.Int
	Root      *big.Int
	Siblings  []*big.Int
	PathBits  []bool
}

func BuildAccountTree(leaves []AccountLeaf) (*AccountTree, error) {
	if len(leaves) == 0 {
		return nil, ErrNoAccounts
	}

	clonedLeaves := append([]AccountLeaf(nil), leaves...)
	leafHashes := make([]*big.Int, len(clonedLeaves))
	for index, leaf := range clonedLeaves {
		if err := validateAccountLeaf(leaf); err != nil {
			return nil, fmt.Errorf("validate account leaf %d: %w", index, err)
		}
		digest, err := AccountCommitment(leaf.AccountID, leaf.Balance, leaf.Nonce)
		if err != nil {
			return nil, fmt.Errorf("hash account leaf %d: %w", index, err)
		}
		leafHashes[index] = cloneBigInt(digest)
	}

	levels := [][]*big.Int{cloneBigIntSlice(leafHashes)}
	current := cloneBigIntSlice(leafHashes)
	for len(current) > 1 {
		next := make([]*big.Int, 0, (len(current)+1)/2)
		for index := 0; index < len(current); index += 2 {
			left := current[index]
			right := left
			if index+1 < len(current) {
				right = current[index+1]
			}
			parent, err := NodeCommitment(left, right)
			if err != nil {
				return nil, fmt.Errorf("hash node at level %d index %d: %w", len(levels)-1, index/2, err)
			}
			next = append(next, parent)
		}
		levels = append(levels, next)
		current = next
	}

	return &AccountTree{
		leaves:     clonedLeaves,
		leafHashes: leafHashes,
		levels:     levels,
	}, nil
}

func (tree *AccountTree) Root() *big.Int {
	return cloneBigInt(tree.levels[len(tree.levels)-1][0])
}

func (tree *AccountTree) Depth() int {
	return len(tree.levels) - 1
}

func (tree *AccountTree) Prove(index int) (AccountProof, error) {
	if index < 0 || index >= len(tree.leaves) {
		return AccountProof{}, fmt.Errorf("leaf index %d out of range", index)
	}

	siblings := make([]*big.Int, 0, tree.Depth())
	pathBits := make([]bool, 0, tree.Depth())
	currentIndex := index
	for level := 0; level < len(tree.levels)-1; level++ {
		layer := tree.levels[level]
		siblingIndex := currentIndex ^ 1
		if siblingIndex >= len(layer) {
			siblingIndex = currentIndex
		}
		siblings = append(siblings, cloneBigInt(layer[siblingIndex]))
		pathBits = append(pathBits, currentIndex%2 == 1)
		currentIndex /= 2
	}

	return AccountProof{
		Leaf:      tree.leaves[index],
		LeafIndex: index,
		LeafHash:  cloneBigInt(tree.leafHashes[index]),
		Root:      tree.Root(),
		Siblings:  siblings,
		PathBits:  pathBits,
	}, nil
}

func VerifyAccountProof(proof AccountProof) (bool, error) {
	if proof.Root == nil || proof.LeafHash == nil {
		return false, fmt.Errorf("proof root and leaf hash are required")
	}
	if len(proof.Siblings) != len(proof.PathBits) {
		return false, fmt.Errorf("proof sibling count %d does not match path bit count %d", len(proof.Siblings), len(proof.PathBits))
	}
	current := cloneBigInt(proof.LeafHash)
	for index := range proof.Siblings {
		var left *big.Int
		var right *big.Int
		if proof.PathBits[index] {
			left = proof.Siblings[index]
			right = current
		} else {
			left = current
			right = proof.Siblings[index]
		}
		next, err := NodeCommitment(left, right)
		if err != nil {
			return false, fmt.Errorf("verify path step %d: %w", index, err)
		}
		current = next
	}
	return current.Cmp(proof.Root) == 0, nil
}

func AccountCommitment(accountID int, balance int, nonce int) (*big.Int, error) {
	if err := validateAccountLeaf(AccountLeaf{AccountID: accountID, Balance: balance, Nonce: nonce}); err != nil {
		return nil, err
	}
	return poseidon2Permutation(3, []bn254fr.Element{
		bn254fr.NewElement(uint64(accountID)),
		bn254fr.NewElement(uint64(balance)),
		bn254fr.NewElement(uint64(nonce)),
	})
}

func NodeCommitment(left *big.Int, right *big.Int) (*big.Int, error) {
	if left == nil || right == nil {
		return nil, ErrNilNodeInput
	}
	leftElement := new(bn254fr.Element)
	leftElement.SetBigInt(left)
	rightElement := new(bn254fr.Element)
	rightElement.SetBigInt(right)
	return poseidon2Permutation(2, []bn254fr.Element{*leftElement, *rightElement})
}

func poseidon2Permutation(width int, elements []bn254fr.Element) (*big.Int, error) {
	hasher := poseidonbn254.NewPermutation(width, 8, 56)
	state := make([]bn254fr.Element, len(elements))
	copy(state, elements)
	if err := hasher.Permutation(state); err != nil {
		return nil, fmt.Errorf("permute poseidon2 state: %w", err)
	}
	result := new(big.Int)
	state[0].BigInt(result)
	return result, nil
}

func cloneBigInt(value *big.Int) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set(value)
}

func cloneBigIntSlice(values []*big.Int) []*big.Int {
	clone := make([]*big.Int, len(values))
	for index, value := range values {
		clone[index] = cloneBigInt(value)
	}
	return clone
}

func validateAccountLeaf(leaf AccountLeaf) error {
	if leaf.AccountID < 0 || leaf.Balance < 0 || leaf.Nonce < 0 {
		return ErrInvalidAccountLeaf
	}
	return nil
}
