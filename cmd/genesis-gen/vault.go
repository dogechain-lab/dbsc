package main

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/dccontracts"
)

// Slot definitions for SC storage
const (
	vaultOwnerSlot = int64(iota) // Slot 0
)

// StorageIndexes is a wrapper for different storage indexes that
// need to be modified
type vaultStorageIndexes struct {
	OwnerIndex []byte // address
}

// getStorageIndexes is a helper function for getting the correct indexes
// of the storage slots which need to be modified during bootstrap.
//
// It is SC dependant, and based on the SC located at:
// https://github.com/dogechain-lab/dogechain-contracts
func getVaultStorageIndexes() *vaultStorageIndexes {
	storageIndexes := vaultStorageIndexes{}

	// Get the indexes for _owner, _minimumThreshold
	// Index for regular types is calculated as just the regular slot
	storageIndexes.OwnerIndex = big.NewInt(vaultOwnerSlot).Bytes()

	return &storageIndexes
}

// predeployVaultSC is a helper method for setting up the vault smart contract account,
// using the passed in owner and signers as pre-defined accounts.
func predeployVaultSC(owner common.Address) *core.GenesisAccount {
	contractAccount := &core.GenesisAccount{
		Code: dccontracts.DCVaultContractByteCode,
	}

	// Generate the empty account storage map
	storageMap := make(map[common.Hash]common.Hash)
	// Set the value for the owner
	storageIndexes := getVaultStorageIndexes()
	storageMap[common.BytesToHash(storageIndexes.OwnerIndex)] =
		common.BytesToHash(owner.Bytes())

	// Save the storage map
	contractAccount.Storage = storageMap

	return contractAccount
}
