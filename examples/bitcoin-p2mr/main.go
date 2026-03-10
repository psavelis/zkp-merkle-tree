package main

import (
	"fmt"

	internalhash "github.com/psavelis/zkp-merkle-tree/internal/hash"
	"github.com/psavelis/zkp-merkle-tree/internal/merkle"
)

func main() {
	conditions := [][]byte{
		[]byte("branch-0: hot-wallet emergency spend"),
		[]byte("branch-1: 2-of-3 board recovery"),
		[]byte("branch-2: post-quantum migration path"),
		[]byte("branch-3: delayed social recovery"),
	}

	tree, err := merkle.Build(internalhash.NewSHA256Hasher(), conditions)
	if err != nil {
		panic(err)
	}

	proof, err := tree.Prove(2)
	if err != nil {
		panic(err)
	}

	verified, err := merkle.Verify(internalhash.NewSHA256Hasher(), proof)
	if err != nil {
		panic(err)
	}

	fmt.Println("Bitcoin-style selective branch reveal")
	fmt.Printf("Root commitment: %s\n", tree.Root())
	fmt.Printf("Revealed condition: %s\n", proof.Leaf)
	fmt.Printf("Proof depth: %d\n", proof.Depth)
	fmt.Printf("Unused branches kept private: %d\n", len(conditions)-1)
	fmt.Printf("Verification result: %t\n", verified)
}
