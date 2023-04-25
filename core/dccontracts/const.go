package dccontracts

import (
	_ "embed"
	"encoding/hex"
)

const (
	// Dogechain genesis contracts
	DCValidatorSetContract = "0x0000000000000000000000000000000000001001"
	DCBridgeContract       = "0x0000000000000000000000000000000000001002"
	DCVaultContract        = "0x0000000000000000000000000000000000001003"
)

//go:embed bytecode/00001001-ValidatorSet.bin
var _validatorSetContractByteCode string

var DCValidatorSetContractByteCode []byte

//go:embed bytecode/00001002-Bridge.bin
var _bridgeContractByteCode string

var DCBridgeContractByteCode []byte

//go:embed bytecode/00001003-Vault.bin
var _vaultContractByteCode string

var DCVaultContractByteCode []byte

func init() {
	var err error

	DCValidatorSetContractByteCode, err = hex.DecodeString(_validatorSetContractByteCode)
	if err != nil {
		panic("validatorSet contract bytecode error")
	}

	DCBridgeContractByteCode, err = hex.DecodeString(_bridgeContractByteCode)
	if err != nil {
		panic("bridge contract bytecode error")
	}

	DCVaultContractByteCode, err = hex.DecodeString(_vaultContractByteCode)
	if err != nil {
		panic("vault contract bytecode error")
	}
}
