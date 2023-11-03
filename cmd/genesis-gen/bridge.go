package main

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/dccontracts"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	DefaultBridgeThreshold = "0x56bc75e2d63100000" // 100 wDoge
	DefaultBridgeRate      = 100                   // 1%
)

// Slot definitions for SC storage
const (
	ownerSlot = int64(iota) // Slot 0
	minimumThresholdSlot
	signersSlot
	addressToIsSignerSlot
	addressToSignerIndexSlot
	// ordersSlot      // too complicated, would not be set
	// totalSupplySlot // would not be set
	rateSlot = int64(iota + 2)
)

// StorageIndexes is a wrapper for different storage indexes that
// need to be modified
type StorageIndexes struct {
	bridgeOwnerIndex                []byte // address
	bridgeMinimumThresholdIndex     []byte // uint256
	bridgeSignersIndex              []byte // []address
	bridgeSignersArraySizeIndex     []byte // []address size
	bridgeAddressToIsSignerIndex    []byte // mapping(address => bool)
	bridgeAddressToSignerIndexIndex []byte // mapping(address => uint256)
	bridgeRateIndex                 []byte // uint256
}

// getStorageIndexes is a helper function for getting the correct indexes
// of the storage slots which need to be modified during bootstrap.
//
// It is SC dependant, and based on the SC located at:
// https://github.com/dogechain-lab/dogechain-contracts/
func getStorageIndexes(address common.Address, index int64) *StorageIndexes {
	storageIndexes := StorageIndexes{}

	// Get the indexes for _owner, _minimumThreshold
	// Index for regular types is calculated as just the regular slot
	storageIndexes.bridgeOwnerIndex = big.NewInt(ownerSlot).Bytes()
	storageIndexes.bridgeMinimumThresholdIndex = big.NewInt(minimumThresholdSlot).Bytes()
	storageIndexes.bridgeRateIndex = big.NewInt(rateSlot).Bytes()

	// Get the indexes for the mappings
	// The index for the mapping is retrieved with:
	// keccak(address . slot)
	// . stands for concatenation (basically appending the bytes)
	storageIndexes.bridgeAddressToIsSignerIndex = getAddressMapping(address, addressToIsSignerSlot)
	storageIndexes.bridgeAddressToSignerIndexIndex = getAddressMapping(address, addressToSignerIndexSlot)

	// Index for array types is calculated as keccak(slot) + index
	// The slot for the dynamic arrays that's put in the keccak needs to be in hex form (padded 64 chars)
	storageIndexes.bridgeSignersIndex = getIndexWithOffset(
		crypto.Keccak256(PadLeftOrTrim(big.NewInt(signersSlot).Bytes(), 32)),
		index,
	)

	// For any dynamic array in Solidity, the size of the actual array should be
	// located on slot x
	storageIndexes.bridgeSignersArraySizeIndex = []byte{byte(signersSlot)}

	return &storageIndexes
}

// predeployBridgeSC is a helper method for setting up the bridge smart contract account,
// using the passed in owner and signers as pre-defined accounts.
func predeployBridgeSC(owner common.Address, signers []common.Address) *core.GenesisAccount {
	// Set the code for the bridge smart contract
	// Code retrieved from https://github.com/dogechain-lab/dogechain-contracts
	bridgeAccount := &core.GenesisAccount{
		Code:    dccontracts.DCBridgeContractByteCode,
		Balance: big.NewInt(0),
	}

	bigDefaultRate := big.NewInt(int64(DefaultBridgeRate))
	bigTrueValue := big.NewInt(1)

	// Generate the empty account storage map
	storageMap := make(map[common.Hash]common.Hash)

	for indx, signer := range signers {
		// Get the storage indexes
		storageIndexes := getStorageIndexes(signer, int64(indx))

		// Set the value for the owner
		storageMap[common.BytesToHash(storageIndexes.bridgeOwnerIndex)] =
			common.BytesToHash(owner.Bytes())

		// Set the value for the minimum threshold
		storageMap[common.BytesToHash(storageIndexes.bridgeMinimumThresholdIndex)] =
			common.HexToHash(DefaultBridgeThreshold)

		// Set the value for the signers array
		storageMap[common.BytesToHash(storageIndexes.bridgeSignersIndex)] =
			common.BytesToHash(signer.Bytes())

		// Set the value for the size of the signers array
		storageMap[common.BytesToHash(storageIndexes.bridgeSignersArraySizeIndex)] =
			common.BigToHash(new(big.Int).SetUint64(uint64(indx + 1)))

		// Set the value for the address -> is signer mapping
		storageMap[common.BytesToHash(storageIndexes.bridgeAddressToIsSignerIndex)] =
			common.BytesToHash(bigTrueValue.Bytes())

		// Set the value for the address -> signer array index mapping
		storageMap[common.BytesToHash(storageIndexes.bridgeAddressToSignerIndexIndex)] =
			common.BigToHash(new(big.Int).SetUint64(uint64(indx)))

		// Set the value for the rate
		storageMap[common.BytesToHash(storageIndexes.bridgeRateIndex)] =
			common.BytesToHash(bigDefaultRate.Bytes())
	}

	// Save the storage map
	bridgeAccount.Storage = storageMap

	return bridgeAccount
}
