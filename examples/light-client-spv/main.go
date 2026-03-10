package main

import (
	"fmt"

	internalhash "github.com/psavelis/zkp-merkle-tree/internal/hash"
	"github.com/psavelis/zkp-merkle-tree/internal/merkle"
)

func main() {
	txIDs := [][]byte{
		[]byte("tx:coinbase:0001"),
		[]byte("tx:deposit:alice:25"),
		[]byte("tx:swap:alice-bob:7"),
		[]byte("tx:withdraw:carol:3"),
	}

	tree, err := merkle.Build(internalhash.NewSHA256Hasher(), txIDs)
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

	fmt.Println("Light-client SPV transaction inclusion")
	fmt.Printf("Block transactions root: %s\n", tree.Root())
	fmt.Printf("Proved transaction: %s\n", proof.Leaf)
	fmt.Printf("Proof depth: %d\n", proof.Depth)
	fmt.Printf("What the light client avoids downloading: %d unrelated transactions\n", len(txIDs)-1)
	fmt.Printf("Verification result: %t\n", verified)
}
