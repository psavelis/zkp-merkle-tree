package rollup

import "testing"

func TestBuildBalanceUpdateScenarioRejectsNegativeAmount(t *testing.T) {
	_, err := BuildBalanceUpdateScenario(7, 25, -1, 1)
	if err == nil {
		t.Fatal("expected negative amount to fail")
	}
	if got := err.Error(); got != "amount must be non-negative" {
		t.Fatalf("unexpected error: %s", got)
	}
}

func TestBuildBalanceUpdateScenarioRejectsNegativeInputs(t *testing.T) {
	testCases := []struct {
		name       string
		accountID  int
		oldBalance int
		amount     int
		nonce      int
	}{
		{name: "negative account id", accountID: -1, oldBalance: 25, amount: 10, nonce: 1},
		{name: "negative old balance", accountID: 7, oldBalance: -1, amount: 10, nonce: 1},
		{name: "negative nonce", accountID: 7, oldBalance: 25, amount: 10, nonce: -1},
	}

	for _, testCase := range testCases {
		_, err := BuildBalanceUpdateScenario(testCase.accountID, testCase.oldBalance, testCase.amount, testCase.nonce)
		if err == nil {
			t.Fatalf("%s: expected error", testCase.name)
		}
		if got := err.Error(); got != "account id, old balance, and nonce must be non-negative" {
			t.Fatalf("%s: unexpected error %s", testCase.name, got)
		}
	}
}

func TestBuildBalanceUpdateScenarioRejectsOverflow(t *testing.T) {
	_, err := BuildBalanceUpdateScenario(7, int(^uint(0)>>1), 1, 1)
	if err == nil {
		t.Fatal("expected overflow to fail")
	}
	if got := err.Error(); got != "compute new balance: integer overflow" {
		t.Fatalf("unexpected error: %s", got)
	}
}
