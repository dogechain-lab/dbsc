package main

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/dccontracts"
	"github.com/ethereum/go-ethereum/crypto"
)

// getValidatorSetStorageIndexes is a helper function for getting the correct indexes
// of the storage slots which need to be modified during bootstrap.
//
// It is SC dependant, and based on the SC located at:
// https://github.com/dogechain-lab/dogechain-contracts
func getValidatorSetStorageIndexes(address common.Address, index int64) *validatorSetStorageIndexes {
	storageIndexes := validatorSetStorageIndexes{}

	// Get the indexes for the mappings
	// The index for the mapping is retrieved with:
	// keccak(address . slot)
	// . stands for concatenation (basically appending the bytes)
	storageIndexes.AddressToIsValidatorIndex = getAddressMapping(address, vsAddressToIsValidatorSlot)
	storageIndexes.AddressToStakedAmountIndex = getAddressMapping(address, vsAddressToStakedAmountSlot)
	storageIndexes.AddressToValidatorIndexIndex = getAddressMapping(address, vsAddressToValidatorIndexSlot)

	// Get the indexes for _status, _owner, _validators, _stakedAmount, etc
	// Index for regular types is calculated as just the regular slot
	storageIndexes.StatusIndex = big.NewInt(vsStatusSlot).Bytes()
	storageIndexes.OwnerIndex = big.NewInt(vsOwnerSlot).Bytes()
	storageIndexes.ThresholdIndex = big.NewInt(vsThresholdSlot).Bytes()
	storageIndexes.MinimumIndex = big.NewInt(vsMinimumSlot).Bytes()
	storageIndexes.StakedAmountIndex = big.NewInt(vsStakedAmountSlot).Bytes()

	// Index for array types is calculated as keccak(slot) + index
	// The slot for the dynamic arrays that's put in the keccak needs to be in hex form (padded 64 chars)
	storageIndexes.ValidatorsIndex = getIndexWithOffset(
		crypto.Keccak256(PadLeftOrTrim(big.NewInt(vsValidatorsSlot).Bytes(), 32)),
		index,
	)

	// For any dynamic array in Solidity, the size of the actual array should be
	// located on slot x
	storageIndexes.ValidatorsArraySizeIndex = []byte{byte(vsValidatorsSlot)}

	return &storageIndexes
}

// validatorSetStorageIndexes is a wrapper for different storage indexes that
// need to be modified
type validatorSetStorageIndexes struct {
	StatusIndex                  []byte // uint256
	OwnerIndex                   []byte // address
	ThresholdIndex               []byte // uint256
	MinimumIndex                 []byte // uint256
	ValidatorsIndex              []byte // []address
	ValidatorsArraySizeIndex     []byte // []address size
	AddressToIsValidatorIndex    []byte // mapping(address => bool)
	AddressToStakedAmountIndex   []byte // mapping(address => uint256)
	AddressToValidatorIndexIndex []byte // mapping(address => uint256)
	StakedAmountIndex            []byte // uint256
}

// Slot definitions for SC storage
const (
	vsStatusSlot = int64(iota) // Slot 0
	vsOwnerSlot
	vsThresholdSlot
	vsMinimumSlot
	vsValidatorsSlot
	vsAddressToIsValidatorSlot
	vsAddressToStakedAmountSlot
	vsAddressToValidatorIndexSlot
	vsStakedAmountSlot
)

const (
	DefaultValidatorSetStakedBalance    = "0x84595161401484A000000" // 10_000_000 DC
	DefaultValidatorSetStatusNotEntered = 1                         // ReentrancyGuard status contant
)

// predeployValidatorSet is a helper method for setting up the ValidatorSet smart contract account,
// using the passed in validators as pre-staked validators
func predeployValidatorSet(owner common.Address, validators []common.Address) (*core.GenesisAccount, error) {
	stakingAccount := &core.GenesisAccount{
		Code: dccontracts.DCValidatorSetContractByteCode,
	}
	if owner == (common.Address{}) {
		return nil, errors.New("contract owner should not be empty")
	}

	// Generate the empty account storage map
	storageMap := make(map[common.Hash]common.Hash)
	bigOne := big.NewInt(1)
	bigTrueValue := big.NewInt(1)
	stakedAmount := big.NewInt(0)
	notEnteredStatus := big.NewInt(DefaultValidatorSetStatusNotEntered)

	for indx, validator := range validators {
		// Get the storage indexes
		storageIndexes := getValidatorSetStorageIndexes(validator, int64(indx))

		// Set the value for the owner
		storageMap[common.BytesToHash(storageIndexes.OwnerIndex)] =
			common.BytesToHash(owner.Bytes())

		// Set the value for the owner
		storageMap[common.BytesToHash(storageIndexes.MinimumIndex)] =
			common.BytesToHash(bigOne.Bytes())

		// Set the value for the validators array
		storageMap[common.BytesToHash(storageIndexes.ValidatorsIndex)] =
			common.BytesToHash(
				validator.Bytes(),
			)

		// Set the value for the address -> validator array index mapping
		storageMap[common.BytesToHash(storageIndexes.AddressToIsValidatorIndex)] =
			common.BytesToHash(bigTrueValue.Bytes())

		// Set the value for the address -> validator index mapping
		storageMap[common.BytesToHash(storageIndexes.AddressToValidatorIndexIndex)] =
			common.BigToHash(new(big.Int).SetUint64(uint64(indx)))

		// Set the value for the total staked amount
		storageMap[common.BytesToHash(storageIndexes.StakedAmountIndex)] =
			common.BytesToHash(stakedAmount.Bytes())

		// Set the value for the size of the validators array
		storageMap[common.BytesToHash(storageIndexes.ValidatorsArraySizeIndex)] =
			common.BigToHash(new(big.Int).SetUint64(uint64(indx + 1)))

		// Set the default status
		storageMap[common.BytesToHash(storageIndexes.StatusIndex)] =
			common.BytesToHash(notEnteredStatus.Bytes())
	}

	// Save the storage map
	stakingAccount.Storage = storageMap

	// Set the Staking SC balance to numValidators * defaultStakedBalance
	stakingAccount.Balance = stakedAmount

	return stakingAccount, nil
}
