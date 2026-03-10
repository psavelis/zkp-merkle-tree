package merkle

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	internalhash "github.com/psavelis/zkp-merkle-tree/internal/hash"
)

type Proof struct {
	HashName   string      `json:"hash_name"`
	Leaf       string      `json:"leaf,omitempty"`
	LeafBase64 string      `json:"leaf_base64,omitempty"`
	LeafDigest string      `json:"leaf_digest"`
	LeafIndex  int         `json:"leaf_index"`
	Root       string      `json:"root"`
	Siblings   []string    `json:"siblings"`
	Directions []Direction `json:"directions"`
	Depth      int         `json:"depth"`
	rawLeaf    []byte
	path       []internalhash.Digest
	rootDigest internalhash.Digest
	leafDigest internalhash.Digest
}

type Direction string

const (
	LeftSibling  Direction = "left"
	RightSibling Direction = "right"
)

func (tree *Tree) Prove(index int) (Proof, error) {
	if index < 0 || index >= len(tree.leafPayloads) {
		return Proof{}, fmt.Errorf("leaf index %d out of range", index)
	}

	path := make([]internalhash.Digest, 0, len(tree.levels)-1)
	directions := make([]Direction, 0, len(tree.levels)-1)
	currentIndex := index
	for level := 0; level < len(tree.levels)-1; level++ {
		layer := tree.levels[level]
		siblingIndex := currentIndex ^ 1
		if siblingIndex >= len(layer) {
			siblingIndex = currentIndex
		}
		path = append(path, layer[siblingIndex])
		if currentIndex%2 == 0 {
			directions = append(directions, RightSibling)
		} else {
			directions = append(directions, LeftSibling)
		}
		currentIndex /= 2
	}

	leaf := append([]byte(nil), tree.leafPayloads[index]...)
	proof := Proof{
		HashName:   tree.hasher.Name(),
		LeafBase64: base64.StdEncoding.EncodeToString(leaf),
		LeafDigest: tree.leafHashes[index].String(),
		LeafIndex:  index,
		Root:       tree.Root().String(),
		Siblings:   make([]string, len(path)),
		Directions: append([]Direction(nil), directions...),
		Depth:      len(path),
		rawLeaf:    leaf,
		path:       append([]internalhash.Digest(nil), path...),
		rootDigest: tree.Root(),
		leafDigest: tree.leafHashes[index],
	}
	if utf8.Valid(leaf) {
		proof.Leaf = string(leaf)
	}
	for index, digest := range path {
		proof.Siblings[index] = digest.String()
	}
	return proof, nil
}

func (proof Proof) MarshalJSON() ([]byte, error) {
	type Alias Proof
	return json.Marshal(Alias(proof))
}

func ParseProof(data []byte) (Proof, error) {
	var proof Proof
	if err := json.Unmarshal(data, &proof); err != nil {
		return Proof{}, err
	}
	leafDigest, err := internalhash.DigestFromHex(proof.LeafDigest)
	if err != nil {
		return Proof{}, fmt.Errorf("parse leaf digest: %w", err)
	}
	rootDigest, err := internalhash.DigestFromHex(proof.Root)
	if err != nil {
		return Proof{}, fmt.Errorf("parse root digest: %w", err)
	}
	path := make([]internalhash.Digest, len(proof.Siblings))
	for index, encoded := range proof.Siblings {
		digest, err := internalhash.DigestFromHex(encoded)
		if err != nil {
			return Proof{}, fmt.Errorf("parse sibling %d: %w", index, err)
		}
		path[index] = digest
	}
	if proof.LeafBase64 != "" {
		rawLeaf, err := base64.StdEncoding.DecodeString(proof.LeafBase64)
		if err != nil {
			return Proof{}, fmt.Errorf("decode leaf bytes: %w", err)
		}
		proof.rawLeaf = rawLeaf
	} else {
		proof.rawLeaf = []byte(proof.Leaf)
	}
	proof.path = path
	proof.rootDigest = rootDigest
	proof.leafDigest = leafDigest
	return proof, nil
}

func Verify(hasher internalhash.Hasher, proof Proof) (bool, error) {
	if len(proof.path) != len(proof.Directions) {
		return false, fmt.Errorf("malformed proof: sibling count %d does not match direction count %d", len(proof.path), len(proof.Directions))
	}

	current, err := hasher.HashLeaf(proof.rawLeaf)
	if err != nil {
		return false, fmt.Errorf("hash leaf: %w", err)
	}
	if current != proof.leafDigest {
		return false, nil
	}

	for index, sibling := range proof.path {
		switch proof.Directions[index] {
		case RightSibling:
			current, err = hasher.HashNode(current, sibling)
		case LeftSibling:
			current, err = hasher.HashNode(sibling, current)
		default:
			return false, fmt.Errorf("invalid direction %q", proof.Directions[index])
		}
		if err != nil {
			return false, fmt.Errorf("hash path step %d: %w", index, err)
		}
	}

	return current == proof.rootDigest, nil
}
