package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	internalhash "github.com/psavelis/zkp-merkle-tree/internal/hash"
	"github.com/psavelis/zkp-merkle-tree/internal/merkle"
	zkprover "github.com/psavelis/zkp-merkle-tree/internal/zk/prover"
	zkrollup "github.com/psavelis/zkp-merkle-tree/internal/zk/rollup"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "root":
		err = runRoot(os.Args[2:])
	case "prove":
		err = runProve(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "zk-balance":
		err = runZKBalance(os.Args[2:])
	default:
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runRoot(args []string) error {
	fs := flag.NewFlagSet("root", flag.ContinueOnError)
	hashName := fs.String("hash", "sha256", "hash backend: sha256 or poseidon")
	leafList := stringListFlag{}
	fs.Var(&leafList, "leaf", "leaf payload (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	hasher, err := selectHasher(*hashName)
	if err != nil {
		return err
	}
	tree, err := merkle.Build(hasher, leafList.Bytes())
	if err != nil {
		return err
	}
	output := map[string]any{
		"hash":       hasher.Name(),
		"leaf_count": tree.LeafCount(),
		"root":       tree.Root().String(),
	}
	return writeJSON(output)
}

func runProve(args []string) error {
	fs := flag.NewFlagSet("prove", flag.ContinueOnError)
	hashName := fs.String("hash", "sha256", "hash backend: sha256 or poseidon")
	index := fs.Int("index", 0, "leaf index")
	leafList := stringListFlag{}
	fs.Var(&leafList, "leaf", "leaf payload (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	hasher, err := selectHasher(*hashName)
	if err != nil {
		return err
	}
	tree, err := merkle.Build(hasher, leafList.Bytes())
	if err != nil {
		return err
	}
	proof, err := tree.Prove(*index)
	if err != nil {
		return err
	}
	return writeJSON(proof)
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	hashName := fs.String("hash", "sha256", "hash backend: sha256 or poseidon")
	proofPath := fs.String("proof-file", "", "path to a JSON proof file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *proofPath == "" {
		return errors.New("proof-file is required")
	}
	hasher, err := selectHasher(*hashName)
	if err != nil {
		return err
	}
	content, err := os.ReadFile(*proofPath)
	if err != nil {
		return err
	}
	proof, err := merkle.ParseProof(content)
	if err != nil {
		return err
	}
	ok, err := merkle.Verify(hasher, proof)
	if err != nil {
		return err
	}
	return writeJSON(map[string]any{"verified": ok})
}

func runZKBalance(args []string) error {
	fs := flag.NewFlagSet("zk-balance", flag.ContinueOnError)
	oldBalance := fs.Int("old-balance", 25, "private old balance")
	amount := fs.Int("amount", 10, "public delta")
	nonce := fs.Int("nonce", 1, "private nonce")
	accountID := fs.Int("account-id", 7, "public account id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	scenario, err := zkrollup.BuildBalanceUpdateScenario(*accountID, *oldBalance, *amount, *nonce)
	if err != nil {
		return err
	}
	result, err := zkprover.ProveBalanceUpdate(zkprover.BalanceUpdateInput{
		AccountID:   scenario.AccountID,
		OldBalance:  scenario.OldBalance,
		Amount:      scenario.Amount,
		Nonce:       scenario.Nonce,
		PreRoot:     scenario.PreProof.Root,
		PostRoot:    scenario.PostProof.Root,
		PathBits:    scenario.PreProof.PathBits,
		OldSiblings: scenario.PreProof.Siblings,
		NewSiblings: scenario.PostProof.Siblings,
	})
	if err != nil {
		return err
	}
	return writeJSON(result)
}

func printUsage() {
	fmt.Println("usage: zkp-merkle-demo <root|prove|verify|zk-balance> [flags]")
}

func selectHasher(name string) (internalhash.Hasher, error) {
	switch strings.ToLower(name) {
	case "sha256":
		return internalhash.NewSHA256Hasher(), nil
	case "poseidon":
		return internalhash.NewPoseidonHasher(), nil
	default:
		return nil, fmt.Errorf("unsupported hash backend %q", name)
	}
}

func writeJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

type stringListFlag []string

func (list *stringListFlag) String() string {
	return strings.Join(*list, ",")
}

func (list *stringListFlag) Set(value string) error {
	*list = append(*list, value)
	return nil
}

func (list *stringListFlag) Bytes() [][]byte {
	items := make([][]byte, len(*list))
	for index, item := range *list {
		items[index] = []byte(item)
	}
	return items
}
