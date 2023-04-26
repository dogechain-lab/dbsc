package dccontracts

const (
	// Dogechain genesis contracts
	DCValidatorSetContract = "0x0000000000000000000000000000000000001001"
	DCBridgeContract       = "0x0000000000000000000000000000000000001002"
	DCVaultContract        = "0x0000000000000000000000000000000000001003"
)

//go:generate go run codeembed/main.go -name DCValidatorSetContractByteCode  -output 1001_validator_set.go -input bytecode/1001-ValidatorSet.bin
//go:generate go run codeembed/main.go -name DCBridgeContractByteCode        -output 1002_bridge.go        -input bytecode/1002-Bridge.bin
//go:generate go run codeembed/main.go -name DCVaultContractByteCode         -output 1003_vault.go         -input bytecode/1003-Vault.bin

// Portland hard fork
//go:generate go run codeembed/main.go -name DCBridgeContractPortlandByteCode -output 1002_bridge_portland.go -input bytecode/1002-Bridge-Portland.bin

// Detroit hard fork
//go:generate go run codeembed/main.go -name DCValidatorSetContractDetroitByteCode -output 1001_validatorset_detroit.go -input bytecode/1001-ValidatorSet-Detroit.bin
//go:generate go run codeembed/main.go -name DCBridgeContractDetroitByteCode       -output 1002_bridge_detroit.go       -input bytecode/1002-Bridge-Detroit.bin
