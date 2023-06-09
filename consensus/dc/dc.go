package dc

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dogechain-lab/dogechain/blockchain"
	"github.com/dogechain-lab/dogechain/consensus"
	"github.com/dogechain-lab/dogechain/consensus/ibft"

	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/params"

	"github.com/hashicorp/go-hclog"
	lru "github.com/hashicorp/golang-lru"

	itrie "github.com/dogechain-lab/dogechain/state/immutable-trie"
)

const (
	inMemorySnapshots  = 128  // Number of recent snapshots to keep in memory
	inMemorySignatures = 4096 // Number of recent block signatures to keep in memory

	targetBlockTime = 2 * time.Second

	checkpointInterval = 1024           // Number of blocks after which to save the snapshot to the database
	defaultEpochLength = uint64(100000) // Default number of blocks of checkpoint to update validatorSet from contract

	ExtraVanity = 32 // Fixed number of extra-data prefix bytes reserved for signer vanity
)

type DogeChain struct {
	chainConfig *params.ChainConfig // Chain config
	config      *params.DogeConfig
	epochSize   uint64

	blockchain   *blockchain.Blockchain
	consensus    consensus.Consensus
	stateStorage itrie.Storage
	state        *WrapDcState

	recentSnaps *lru.ARCCache // Snapshots for recent block to speed up
	signatures  *lru.ARCCache // Signatures of recent blocks to speed up mining

	db     ethdb.Database
	ethAPI *ethapi.PublicBlockChainAPI

	closeFlag atomic.Bool
	lock      sync.Mutex
}

func (dc *DogeChain) Close() error {
	if dc.closeFlag.CompareAndSwap(false, true) {
		// join error
		return JoinErrors(
			dc.consensus.Close(),
			dc.blockchain.Close(),
			dc.stateStorage.Close(),
		)
	}

	return nil
}

func New(
	chainConfig *params.ChainConfig,
	db ethdb.Database,
	ethAPI *ethapi.PublicBlockChainAPI,
) (*DogeChain, error) {
	logger := hclog.L()
	genesis, err := parseGenesis(chainConfig.Doge.GenesisFilePath)
	if err != nil {
		return nil, err
	}

	var epochSize uint64 = defaultEpochLength
	if genesis.Params.Engine["ibft"] != nil {
		if ibftCfg, ok := genesis.Params.Engine["ibft"].(map[string]interface{}); ok {
			if definedEpochSize, ok := ibftCfg[ibft.KeyEpochSize]; ok {
				// Epoch size is defined, use the passed in one
				readSize, ok := definedEpochSize.(float64)
				if !ok {
					return nil, errors.New("epochSize invalid type assertion")
				}

				epochSize = uint64(readSize)

				if epochSize == 0 {
					// epoch size should never be zero.
					epochSize = defaultEpochLength
				}
			}
		}
	}

	stateStorage, err := itrie.NewLevelDBStorage(
		newLevelDBBuilder(logger, filepath.Join(chainConfig.Doge.DataDir, "trie")))
	if err != nil {
		logger.Error("failed to create state storage")

		return nil, err
	}

	dcStateDb := itrie.NewStateDB(stateStorage, logger, itrie.NilMetrics())
	wrapDcStateDb := NewWrapDcState(dcStateDb)

	blockchain, consensus, err := createBlockchain(
		logger,
		genesis,
		wrapDcStateDb,
		chainConfig.Doge.DataDir,
	)
	if err != nil {
		stateStorage.Close()
		return nil, err
	}

	// Allocate the snapshot caches and create the engine
	recentSnaps, err := lru.NewARC(inMemorySnapshots)
	if err != nil {
		panic(err)
	}
	// Signatures
	signatures, err := lru.NewARC(inMemorySignatures)
	if err != nil {
		panic(err)
	}

	return &DogeChain{
		chainConfig:  chainConfig,
		config:       chainConfig.Doge,
		epochSize:    epochSize,
		blockchain:   blockchain,
		consensus:    consensus,
		recentSnaps:  recentSnaps,
		signatures:   signatures,
		stateStorage: stateStorage,
		state:        wrapDcStateDb,
		db:           db,
		ethAPI:       ethAPI,
	}, nil
}
