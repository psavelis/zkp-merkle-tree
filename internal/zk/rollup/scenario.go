package rollup

import (
	"fmt"

	zkmerkle "github.com/psavelis/zkp-merkle-tree/internal/zk/merkle"
)

type BalanceUpdateScenario struct {
	AccountID  int
	OldBalance int
	Amount     int
	Nonce      int
	LeafIndex  int
	PreTree    *zkmerkle.AccountTree
	PostTree   *zkmerkle.AccountTree
	PreProof   zkmerkle.AccountProof
	PostProof  zkmerkle.AccountProof
}

func BuildBalanceUpdateScenario(accountID int, oldBalance int, amount int, nonce int) (BalanceUpdateScenario, error) {
	if amount < 0 {
		return BalanceUpdateScenario{}, fmt.Errorf("amount must be non-negative")
	}
	newBalance := oldBalance + amount
	preLeaves := []zkmerkle.AccountLeaf{
		{AccountID: 3, Balance: 11, Nonce: 2},
		{AccountID: accountID, Balance: oldBalance, Nonce: nonce},
		{AccountID: 9, Balance: 40, Nonce: 4},
		{AccountID: 12, Balance: 7, Nonce: 3},
	}
	postLeaves := []zkmerkle.AccountLeaf{
		{AccountID: 3, Balance: 11, Nonce: 2},
		{AccountID: accountID, Balance: newBalance, Nonce: nonce},
		{AccountID: 9, Balance: 40, Nonce: 4},
		{AccountID: 12, Balance: 7, Nonce: 3},
	}

	preTree, err := zkmerkle.BuildAccountTree(preLeaves)
	if err != nil {
		return BalanceUpdateScenario{}, fmt.Errorf("build pre-state tree: %w", err)
	}
	postTree, err := zkmerkle.BuildAccountTree(postLeaves)
	if err != nil {
		return BalanceUpdateScenario{}, fmt.Errorf("build post-state tree: %w", err)
	}

	preProof, err := preTree.Prove(1)
	if err != nil {
		return BalanceUpdateScenario{}, fmt.Errorf("prove pre-state leaf: %w", err)
	}
	postProof, err := postTree.Prove(1)
	if err != nil {
		return BalanceUpdateScenario{}, fmt.Errorf("prove post-state leaf: %w", err)
	}

	return BalanceUpdateScenario{
		AccountID:  accountID,
		OldBalance: oldBalance,
		Amount:     amount,
		Nonce:      nonce,
		LeafIndex:  1,
		PreTree:    preTree,
		PostTree:   postTree,
		PreProof:   preProof,
		PostProof:  postProof,
	}, nil
}
