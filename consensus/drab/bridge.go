package drab

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/dccontracts"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
)

const (
	_eventDeposited = "Deposited"
	_eventWithdrawn = "Withdrawn"
	_eventBurned    = "Burned"
)

var (
	_bridgeContractAddr = common.HexToAddress(dccontracts.DCBridgeContract)
	_vaultContractAddr  = common.HexToAddress(dccontracts.DCVaultContract)
)

func (d *Drab) handleBridgeEvents(state *state.StateDB, receipts []*types.Receipt) error {
	// Handle bridge logs
	for _, receipt := range receipts {
		for _, rlog := range receipt.Logs {
			if err := d.handleBridgeLog(rlog, state); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *Drab) handleBridgeLog(log *types.Log, state *state.StateDB) error {
	// Ensures it is a bridge log
	if log.Address != _bridgeContractAddr {
		return nil
	}
	// Ensures log topic
	if len(log.Topics) == 0 {
		return nil
	}
	// Get event from topic.
	// The ABI should be backward compatible
	ev, err := d.bridgeABI.EventByID(log.Topics[0])
	if err != nil {
		return err
	}

	// Use rawname for bridge event matching
	switch ev.RawName {
	case _eventDeposited:
		deposited, err := parseDepositedEvent(d.bridgeABI, ev, log)
		if err != nil {
			return err
		}
		// deposit from bridge
		state.AddBalance(deposited.Receiver, deposited.Amount)
	case _eventWithdrawn:
		withdrawn, err := parseWithdrawnEvent(d.bridgeABI, ev, log)
		if err != nil {
			return err
		}
		// the total one is the real amount of Withdrawn event
		realAmount := new(big.Int).Add(withdrawn.Amount, withdrawn.Fee)
		// withdraw balance from bridge to another network
		state.SubBalance(_bridgeContractAddr, realAmount)
		// the fee goes to system Vault contract
		state.AddBalance(_vaultContractAddr, withdrawn.Fee)
	case _eventBurned:
		burned, err := parseBurnedEvent(d.bridgeABI, ev, log)
		if err != nil {
			return err
		}
		// burn
		state.SubBalance(burned.Sender, burned.Amount)
	}

	return nil
}

type depositedEvent struct {
	Receiver common.Address
	Amount   *big.Int
	Txid     string
	Sender   string
}

func parseDepositedEvent(eventABI *abi.ABI, event *abi.Event, log *types.Log) (*depositedEvent, error) {
	out := new(depositedEvent)
	if err := unpackLog(out, eventABI, event, log); err != nil {
		return nil, err
	}
	return out, nil
}

type withdrawnEvent struct {
	Sender   common.Address
	Amount   *big.Int
	Fee      *big.Int
	Receiver string
}

func parseWithdrawnEvent(eventABI *abi.ABI, event *abi.Event, log *types.Log) (*withdrawnEvent, error) {
	out := new(withdrawnEvent)
	if err := unpackLog(out, eventABI, event, log); err != nil {
		return nil, err
	}
	return out, nil
}

type burnedEvent struct {
	Sender common.Address
	Amount *big.Int
}

func parseBurnedEvent(eventABI *abi.ABI, event *abi.Event, log *types.Log) (*burnedEvent, error) {
	out := new(burnedEvent)
	if err := unpackLog(out, eventABI, event, log); err != nil {
		return nil, err
	}
	return out, nil
}

func unpackLog(out interface{}, evABI *abi.ABI, event *abi.Event, log *types.Log) error {
	if log.Topics[0] != event.ID {
		return errors.New("event signature mismatch")
	}
	// parse data
	if len(log.Data) > 0 {
		// use name for internal matching
		if err := evABI.UnpackIntoInterface(out, event.Name, log.Data); err != nil {
			return err
		}
	}
	// parse topics
	var indexed abi.Arguments
	for _, arg := range event.Inputs {
		if arg.Indexed {
			indexed = append(indexed, arg)
		}
	}
	return abi.ParseTopics(out, indexed, log.Topics[1:])
}
