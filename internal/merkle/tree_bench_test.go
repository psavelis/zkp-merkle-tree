package merkle

import (
	"fmt"
	"testing"

	internalhash "github.com/psavelis/zkp-merkle-tree/internal/hash"
)

func BenchmarkBuildAndProve(b *testing.B) {
	leaves := make([][]byte, 1024)
	for index := range leaves {
		leaves[index] = []byte(fmt.Sprintf("leaf-%04d", index))
	}

	hasher := internalhash.NewSHA256Hasher()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		tree, err := Build(hasher, leaves)
		if err != nil {
			b.Fatalf("build tree: %v", err)
		}
		if _, err := tree.Prove(777); err != nil {
			b.Fatalf("prove: %v", err)
		}
	}
}
