package ibft

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func Test_parseDepositedEvent(t *testing.T) {
	validAmount, _ := new(big.Int).SetString("0x59497d27c8b585000", 0)

	testCases := []struct {
		name     string
		input    *types.Log
		expected *depositedEvent
	}{
		{
			name: "empty value and data",
			input: &types.Log{
				Topics: []common.Hash{
					common.HexToHash("0xbceab28ca952a9177ce3716580d6c8c2d677fdf721b944e57a5e7322622ffdc9"),
					common.HexToHash("0x00000000000000000000000064b2c6b40dae863b16fc591cdcec7741ebc46a1b"),
					common.HexToHash("0x0"),
				},
			},
			expected: &depositedEvent{
				Receiver: common.HexToAddress("0x64b2c6b40dae863b16fc591cdcec7741ebc46a1b"),
				Amount:   common.Big0,
				Txid:     "",
				Sender:   "",
			},
		},
		{
			name: "valid value and data",
			input: &types.Log{
				Topics: []common.Hash{
					common.HexToHash("0xbceab28ca952a9177ce3716580d6c8c2d677fdf721b944e57a5e7322622ffdc9"),
					common.HexToHash("0x00000000000000000000000064b2c6b40dae863b16fc591cdcec7741ebc46a1b"),
					common.HexToHash("0x0000000000000000000000000000000000000000000000059497d27c8b585000"),
				},
				Data: common.Hex2Bytes("000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000049336235323965363962393562356162666561323235626533313531373762633338656635613131626365643434356336626166653266656636666161313863632d303030303030303000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000022444e6f3348314b55554c7936324e704c6d74336e36626b67447843787a64646a4a47000000000000000000000000000000000000000000000000000000000000"),
			},
			expected: &depositedEvent{
				Receiver: common.HexToAddress("0x64b2c6b40dae863b16fc591cdcec7741ebc46a1b"),
				Amount:   validAmount,
				Txid:     "3b529e69b95b5abfea225be315177bc38ef5a11bced445c6bafe2fef6faa18cc-00000000",
				Sender:   "DNo3H1KUULy62NpLmt3n6bkgDxCxzddjJG",
			},
		},
	}

	bridgeABI := getBridgeABI(t)
	ev := bridgeABI.Events[_eventDeposited]

	for _, tc := range testCases {
		ev := ev
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDepositedEvent(bridgeABI, &ev, tc.input)
			if err != nil {
				t.Errorf("pares deposited event failed: %v", err)
				t.FailNow()
			}
			// event should parse as expected
			if got.Receiver != tc.expected.Receiver {
				t.Errorf("parseDepositedEvent().Receiver = %v, want %v", got.Receiver, tc.expected.Receiver)
			}
			if got.Amount.Cmp(tc.expected.Amount) != 0 {
				t.Errorf("parseDepositedEvent().Amount = %s, want %s", got.Amount, tc.expected.Amount)
			}
			if got.Txid != tc.expected.Txid {
				t.Errorf("parseDepositedEvent().Txid = %v, want %v", got.Txid, tc.expected.Txid)
			}
			if got.Sender != tc.expected.Sender {
				t.Errorf("parseDepositedEvent().Sender = %v, want %v", got.Sender, tc.expected.Sender)
			}
		})
	}
}

func Test_parseWithdrawnEvent(t *testing.T) {
	amount, _ := new(big.Int).SetString("0x59497d27c8b585000", 0)
	fee, _ := new(big.Int).SetString("0x16345785D8A0000", 0)

	testCases := []struct {
		name     string
		input    *types.Log
		expected *withdrawnEvent
	}{
		{
			name: "empty value and data",
			input: &types.Log{
				Topics: []common.Hash{
					common.HexToHash("0x62116a798bb58cc967874bea4d771de2f9aeec6c64189ff2e5a551072f3106f9"),
					common.HexToHash("0x00000000000000000000000064b2c6b40dae863b16fc591cdcec7741ebc46a1b"),
					common.HexToHash("0x0"),
					common.HexToHash("0x0"),
				},
			},
			expected: &withdrawnEvent{
				Sender:   common.HexToAddress("0x64b2c6b40dae863b16fc591cdcec7741ebc46a1b"),
				Amount:   common.Big0,
				Fee:      common.Big0,
				Receiver: "",
			},
		},
		{
			name: "valid value and data",
			input: &types.Log{
				Topics: []common.Hash{
					common.HexToHash("0x62116a798bb58cc967874bea4d771de2f9aeec6c64189ff2e5a551072f3106f9"),
					common.HexToHash("0x00000000000000000000000064b2c6b40dae863b16fc591cdcec7741ebc46a1b"),
					common.BigToHash(amount),
					common.BigToHash(fee),
				},
				Data: common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002244376178374274316e43624876337a555857686b7850686e3771544c6f7959553964000000000000000000000000000000000000000000000000000000000000"),
			},
			expected: &withdrawnEvent{
				Sender:   common.HexToAddress("0x64b2c6b40dae863b16fc591cdcec7741ebc46a1b"),
				Amount:   amount,
				Fee:      fee,
				Receiver: "D7ax7Bt1nCbHv3zUXWhkxPhn7qTLoyYU9d",
			},
		},
	}

	bridgeABI := getBridgeABI(t)
	ev := bridgeABI.Events[_eventWithdrawn]

	for _, tc := range testCases {
		ev := ev
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseWithdrawnEvent(bridgeABI, &ev, tc.input)
			if err != nil {
				t.Errorf("pares deposited event failed: %v", err)
				t.FailNow()
			}
			// event should parse as expected
			if got.Sender != tc.expected.Sender {
				t.Errorf("parseWithdrawnEvent().Sender = %v, want %v", got.Sender, tc.expected.Sender)
			}
			if got.Amount.Cmp(tc.expected.Amount) != 0 {
				t.Errorf("parseWithdrawnEvent().Amount = %s, want %s", got.Amount, tc.expected.Amount)
			}
			if got.Fee.Cmp(tc.expected.Fee) != 0 {
				t.Errorf("parseWithdrawnEvent().Txid = %v, want %v", got.Fee, tc.expected.Fee)
			}
			if got.Receiver != tc.expected.Receiver {
				t.Errorf("parseWithdrawnEvent().Receiver = %v, want %v", got.Receiver, tc.expected.Receiver)
			}
		})
	}
}

func Test_parseBurnedEvent(t *testing.T) {
	amount, _ := new(big.Int).SetString("0x59497d27c8b585000", 0)

	testCases := []struct {
		name     string
		input    *types.Log
		expected *burnedEvent
	}{
		{
			name: "empty value and data",
			input: &types.Log{
				Topics: []common.Hash{
					common.HexToHash("0x696de425f79f4a40bc6d2122ca50507f0efbeabbff86a84871b7196ab8ea8df7"),
					common.HexToHash("0x00000000000000000000000064b2c6b40dae863b16fc591cdcec7741ebc46a1b"),
					common.HexToHash("0x0"),
				},
			},
			expected: &burnedEvent{
				Sender: common.HexToAddress("0x64b2c6b40dae863b16fc591cdcec7741ebc46a1b"),
				Amount: common.Big0,
			},
		},
		{
			name: "valid value and data",
			input: &types.Log{
				Topics: []common.Hash{
					common.HexToHash("0x696de425f79f4a40bc6d2122ca50507f0efbeabbff86a84871b7196ab8ea8df7"),
					common.HexToHash("0x00000000000000000000000064b2c6b40dae863b16fc591cdcec7741ebc46a1b"),
					common.BigToHash(amount),
				},
			},
			expected: &burnedEvent{
				Sender: common.HexToAddress("0x64b2c6b40dae863b16fc591cdcec7741ebc46a1b"),
				Amount: amount,
			},
		},
	}

	bridgeABI := getBridgeABI(t)
	ev, ok := bridgeABI.Events[_eventBurned]
	if ok {
		for _, tc := range testCases {
			ev := ev
			t.Run(tc.name, func(t *testing.T) {
				got, err := parseBurnedEvent(bridgeABI, &ev, tc.input)
				if err != nil {
					t.Errorf("pares deposited event failed: %v", err)
					t.FailNow()
				}
				// event should parse as expected
				if got.Sender != tc.expected.Sender {
					t.Errorf("parseWithdrawnEvent().Sender = %v, want %v", got.Sender, tc.expected.Sender)
				}
				if got.Amount.Cmp(tc.expected.Amount) != 0 {
					t.Errorf("parseWithdrawnEvent().Amount = %s, want %s", got.Amount, tc.expected.Amount)
				}
			})
		}
	}
}

func getBridgeABI(t *testing.T) *abi.ABI {
	b, err := abi.JSON(strings.NewReader(bridgeABI))
	if err != nil {
		t.Fatal(err)
	}

	return &b
}
