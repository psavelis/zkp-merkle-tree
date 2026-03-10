package main

import (
	"fmt"

	internalhash "github.com/psavelis/zkp-merkle-tree/internal/hash"
	"github.com/psavelis/zkp-merkle-tree/internal/merkle"
)

func main() {
	exitClaims := [][]byte{
		[]byte("exit:0001:user:alice:asset:ETH:amount:2"),
		[]byte("exit:0002:user:bob:asset:USDC:amount:1450"),
		[]byte("exit:0003:user:carol:asset:WBTC:amount:1"),
		[]byte("exit:0004:user:dave:asset:ETH:amount:5"),
	}

	tree, err := merkle.Build(internalhash.NewSHA256Hasher(), exitClaims)
	if err != nil {
		panic(err)
	}

	proof, err := tree.Prove(1)
	if err != nil {
		panic(err)
	}

	verified, err := merkle.Verify(internalhash.NewSHA256Hasher(), proof)
	if err != nil {
		panic(err)
	}

	fmt.Println("Bridge exit inclusion proof")
	fmt.Printf("Published exit root: %s\n", tree.Root())
	fmt.Printf("Claim being redeemed: %s\n", proof.Leaf)
	fmt.Printf("Proof depth: %d\n", proof.Depth)
	fmt.Printf("Hidden claims preserved: %d\n", len(exitClaims)-1)
	fmt.Printf("Verification result: %t\n", verified)
}
