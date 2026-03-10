package hash

import (
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

type PoseidonHasher struct{}

func NewPoseidonHasher() PoseidonHasher {
	return PoseidonHasher{}
}

func (PoseidonHasher) Name() string {
	return "poseidon"
}

func (PoseidonHasher) HashLeaf(data []byte) (Digest, error) {
	inputs := make([]*big.Int, 0, 1+len(data)/31+1)
	inputs = append(inputs, big.NewInt(0))
	inputs = append(inputs, chunkBytesToFieldElements(data)...)
	return poseidonHash(inputs)
}

func (PoseidonHasher) HashNode(left Digest, right Digest) (Digest, error) {
	inputs := []*big.Int{
		big.NewInt(1),
	}
	inputs = append(inputs, digestToFieldElements(left)...)
	inputs = append(inputs, digestToFieldElements(right)...)
	return poseidonHash(inputs)
}

func poseidonHash(inputs []*big.Int) (Digest, error) {
	result, err := poseidon.Hash(inputs)
	if err != nil {
		return Digest{}, err
	}
	var digest Digest
	encoded := result.FillBytes(make([]byte, len(digest)))
	copy(digest[:], encoded)
	return digest, nil
}

func chunkBytesToFieldElements(data []byte) []*big.Int {
	if len(data) == 0 {
		return []*big.Int{big.NewInt(0)}
	}

	chunks := make([]*big.Int, 0, len(data)/31+1)
	for start := 0; start < len(data); start += 31 {
		end := start + 31
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, new(big.Int).SetBytes(data[start:end]))
	}
	return chunks
}

func digestToFieldElements(digest Digest) []*big.Int {
	left := new(big.Int).SetBytes(digest[:16])
	right := new(big.Int).SetBytes(digest[16:])
	return []*big.Int{left, right}
}
