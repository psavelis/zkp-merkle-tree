package merkle

import (
	"errors"
	"fmt"

	internalhash "github.com/psavelis/zkp-merkle-tree/internal/hash"
)

var ErrNoLeaves = errors.New("merkle tree requires at least one leaf")

type Tree struct {
	hasher       internalhash.Hasher
	leafPayloads [][]byte
	leafHashes   []internalhash.Digest
	levels       [][]internalhash.Digest
}

func Build(hasher internalhash.Hasher, leaves [][]byte) (*Tree, error) {
	if len(leaves) == 0 {
		return nil, ErrNoLeaves
	}

	leafPayloads := cloneLeaves(leaves)
	leafHashes := make([]internalhash.Digest, len(leafPayloads))
	for index, leaf := range leafPayloads {
		digest, err := hasher.HashLeaf(leaf)
		if err != nil {
			return nil, fmt.Errorf("hash leaf %d: %w", index, err)
		}
		leafHashes[index] = digest
	}

	levels := [][]internalhash.Digest{append([]internalhash.Digest(nil), leafHashes...)}
	current := append([]internalhash.Digest(nil), leafHashes...)
	for len(current) > 1 {
		next := make([]internalhash.Digest, 0, (len(current)+1)/2)
		for index := 0; index < len(current); index += 2 {
			left := current[index]
			right := left
			if index+1 < len(current) {
				right = current[index+1]
			}
			parent, err := hasher.HashNode(left, right)
			if err != nil {
				return nil, fmt.Errorf("hash node at level %d index %d: %w", len(levels)-1, index/2, err)
			}
			next = append(next, parent)
		}
		levels = append(levels, next)
		current = next
	}

	return &Tree{
		hasher:       hasher,
		leafPayloads: leafPayloads,
		leafHashes:   leafHashes,
		levels:       levels,
	}, nil
}

func (tree *Tree) Root() internalhash.Digest {
	return tree.levels[len(tree.levels)-1][0]
}

func (tree *Tree) LeafCount() int {
	return len(tree.leafPayloads)
}

func (tree *Tree) HashName() string {
	return tree.hasher.Name()
}

func (tree *Tree) Leaf(index int) ([]byte, error) {
	if index < 0 || index >= len(tree.leafPayloads) {
		return nil, fmt.Errorf("leaf index %d out of range", index)
	}
	leaf := make([]byte, len(tree.leafPayloads[index]))
	copy(leaf, tree.leafPayloads[index])
	return leaf, nil
}

func cloneLeaves(leaves [][]byte) [][]byte {
	clone := make([][]byte, len(leaves))
	for index, leaf := range leaves {
		clone[index] = append([]byte(nil), leaf...)
	}
	return clone
}
