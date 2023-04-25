package dccontracts

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

type Upgrade struct {
	UpgradeName string
	Configs     []*UpgradeConfig
}

type upgradeHook func(blockNumber *big.Int, contractAddr common.Address, statedb *state.StateDB) error

type UpgradeConfig struct {
	BeforeUpgrade      upgradeHook
	AfterUpgrade       upgradeHook
	ContractAddr       common.Address
	CommitURL          string
	Code               []byte
	DefaultInitStorage map[common.Hash]common.Hash // the initial storage must be backward compatible
	Rebalance          map[common.Address]*big.Int // deprecated, only active in test network
}

const (
	_mainNet = "Mainnet"
	_devNet  = "Devnet"
)

var (
	// for network matching
	GenesisHash common.Hash
	// upgrade config
	// preportland. deprecated in devnet
	_preportlandUpgrade = make(map[string]*Upgrade)
	// portland
	_portlandUpgrade = make(map[string]*Upgrade)
	// detroit
	_detroitUpgrade = make(map[string]*Upgrade)
)

func init() {
	// pre-portland upgrade, only devnet support this hard fork
	_testInt, _ := new(big.Int).SetString("55000000000000000000", 0)
	_preportlandUpgrade[_devNet] = &Upgrade{
		UpgradeName: "preportland",
		Configs: []*UpgradeConfig{
			{
				Rebalance: map[common.Address]*big.Int{
					common.HexToAddress("0x1b051e5D1548326284493BfA380E02C3C149Da4E"): _testInt,
					common.HexToAddress("0xa516CF76d083b4cBe93Ebdfb85FbE72aFfFb7a0c"): big.NewInt(0),
					common.HexToAddress("0xC7aD3276180f8dfb628d975473a81Af2836CDf2b"): big.NewInt(0),
					common.HexToAddress("0x521299a363f1847863e4a6c68c91df722d149c3b"): big.NewInt(0),
					common.HexToAddress("0x3a9185A6b49617cC2d5BE65aF199B73f24834F4f"): big.NewInt(0),
				},
			},
		},
	}

	// portland upgrade
	_portlandUpgradeCfg := &Upgrade{
		UpgradeName: "portland",
		Configs: []*UpgradeConfig{
			{
				ContractAddr: common.HexToAddress(DCBridgeContract),
				CommitURL:    "https://github.com/dogechain-lab/contracts/commit/bcaad0a8a050743855d294d58dac73f06fdc9585",
				Code:         DCBridgeContractByteCode,
			},
		},
	}
	// networks support portland upgrade
	_portlandUpgrade[_mainNet] = _portlandUpgradeCfg
	_portlandUpgrade[_devNet] = _portlandUpgradeCfg

	// detroit hardfork
	_detroitUpgradeContent := &Upgrade{
		UpgradeName: "detroit",
		Configs: []*UpgradeConfig{
			{
				ContractAddr: common.HexToAddress(DCValidatorSetContract),
				CommitURL:    "https://github.com/dogechain-lab/contracts/commit/675c539c5c06b85e3a9ddc060f14e8d12c97a22e",
				Code:         DCValidatorSetContractByteCode,
				DefaultInitStorage: map[common.Hash]common.Hash{
					common.HexToHash("0x000000000000000000000000000000000000000a"): common.HexToHash("0xde0b6b3a7640000"),     // rewardPerBlock
					common.HexToHash("0x000000000000000000000000000000000000000b"): common.HexToHash("0x19"),                  // activeValidatorsLength
					common.HexToHash("0x000000000000000000000000000000000000000c"): common.HexToHash("0x1c20"),                // epochBlockInterval
					common.HexToHash("0x000000000000000000000000000000000000000d"): common.HexToHash("0x12c"),                 // misdemeanorThreshold
					common.HexToHash("0x000000000000000000000000000000000000000e"): common.HexToHash("0x384"),                 // felonyThreshold
					common.HexToHash("0x000000000000000000000000000000000000000f"): common.HexToHash("0xc"),                   // validatorJailEpochLength
					common.HexToHash("0x0000000000000000000000000000000000000010"): common.HexToHash("0x6"),                   // minStakePeriod
					common.HexToHash("0x0000000000000000000000000000000000000011"): common.HexToHash("0x21e19e0c9bab2400000"), // minValidatorStakeAmount
					common.HexToHash("0x0000000000000000000000000000000000000012"): common.HexToHash("0x56bc75e2d63100000"),   // minDelegatorStakeAmount
				},
			},
			{
				ContractAddr: common.HexToAddress(DCBridgeContract),
				CommitURL:    "https://github.com/dogechain-lab/contracts/commit/675c539c5c06b85e3a9ddc060f14e8d12c97a22e",
				Code:         DCBridgeContractByteCode,
			},
		},
	}
	// network supports detroit upgrade
	_detroitUpgrade[_mainNet] = _detroitUpgradeContent
	_detroitUpgrade[_devNet] = _detroitUpgradeContent
}

func UpgradeBuildInSystemContract(config *params.ChainConfig, blockNumber *big.Int, statedb *state.StateDB) {
	// get current network
	if config == nil || blockNumber == nil || statedb == nil {
		return
	}
	var network string
	switch GenesisHash {
	/* Add mainnet genesis hash */
	case params.DCDevnetGenesisHash:
		network = _devNet
	case params.DCGenesisHash:
		fallthrough
	default:
		network = _mainNet
	}

	logger := log.New("system-contract-upgrade", network)
	if config.IsOnPrePortland(blockNumber) {
		applySystemContractUpgrade(_preportlandUpgrade[network], blockNumber, statedb, logger)
	}

	if config.IsOnPortland(blockNumber) {
		applySystemContractUpgrade(_portlandUpgrade[network], blockNumber, statedb, logger)
	}

	if config.IsOnDetorit(blockNumber) {
		applySystemContractUpgrade(_detroitUpgrade[network], blockNumber, statedb, logger)
	}
}

func applySystemContractUpgrade(upgrade *Upgrade, blockNumber *big.Int, statedb *state.StateDB, logger log.Logger) {
	if upgrade == nil {
		logger.Info("Empty upgrade config", "height", blockNumber.String())
		return
	}

	logger.Info(fmt.Sprintf("Apply upgrade %s at height %d", upgrade.UpgradeName, blockNumber.Int64()))

	for _, cfg := range upgrade.Configs {
		logger.Info(fmt.Sprintf("Upgrade contract %s to commit %s", cfg.ContractAddr.String(), cfg.CommitURL))

		if cfg.BeforeUpgrade != nil {
			err := cfg.BeforeUpgrade(blockNumber, cfg.ContractAddr, statedb)
			if err != nil {
				panic(fmt.Errorf("contract address: %s, execute beforeUpgrade error: %s", cfg.ContractAddr.String(), err.Error()))
			}
		}

		statedb.SetCode(cfg.ContractAddr, cfg.Code)

		// Initialize system contract storage if necessary
		for k, v := range cfg.DefaultInitStorage {
			statedb.SetState(cfg.ContractAddr, k, v)
		}

		// Deprecated. Reset account balance in test cases
		for account, balance := range cfg.Rebalance {
			statedb.SetBalance(account, balance)
		}

		if cfg.AfterUpgrade != nil {
			err := cfg.AfterUpgrade(blockNumber, cfg.ContractAddr, statedb)
			if err != nil {
				panic(fmt.Errorf("contract address: %s, execute afterUpgrade error: %s", cfg.ContractAddr.String(), err.Error()))
			}
		}
	}
}
