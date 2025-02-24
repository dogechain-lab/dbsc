package dc

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/hashicorp/go-hclog"

	"github.com/dogechain-lab/dogechain/blockchain"
	"github.com/dogechain-lab/dogechain/blockchain/storage/kvstorage"
	"github.com/dogechain-lab/dogechain/chain"
	"github.com/dogechain-lab/dogechain/consensus"
	"github.com/dogechain-lab/dogechain/helper/kvdb"
	"github.com/dogechain-lab/dogechain/network"
	"github.com/dogechain-lab/dogechain/secrets"
	"github.com/dogechain-lab/dogechain/server"
	"github.com/dogechain-lab/dogechain/state"
	"github.com/dogechain-lab/dogechain/state/runtime/evm"
	"github.com/dogechain-lab/dogechain/state/runtime/precompiled"
)

func newLevelDBBuilder(log hclog.Logger, path string) kvdb.LevelDBBuilder {
	leveldbBuilder := kvdb.NewLevelDBBuilder(
		log,
		path,
	)

	leveldbBuilder.
		SetBloomKeyBits(2048).
		SetCompactionTableSize(4).
		SetCompactionTotalSize(100).
		SetHandles(16384).
		SetCacheSize(512)

	return leveldbBuilder
}

func createConsensus(
	logger hclog.Logger,
	genesis *chain.Chain,
	blockchain *blockchain.Blockchain,
	executor *state.Executor,
	dataDir string,
	metrics *consensus.Metrics,
) (consensus.Consensus, error) {
	engineName := genesis.Params.GetEngine()
	engine, ok := server.GetConsensusBackend(engineName)

	if !ok {
		return nil, fmt.Errorf("consensus engine '%s' not found", engineName)
	}

	secretsManagerFactory, ok := server.GetSecretsManager(secrets.Local)
	if !ok {
		return nil, fmt.Errorf("secret manager '%s' not found", secrets.Local)
	}

	// Instantiate the secrets manager
	secretsManager, factoryErr := secretsManagerFactory(
		&secrets.SecretsManagerConfig{},
		&secrets.SecretsManagerParams{
			Logger: logger,
			Extra: map[string]interface{}{
				secrets.Path: dataDir,
			},
		},
	)

	if factoryErr != nil {
		return nil, factoryErr
	}

	engineConfig, ok := genesis.Params.Engine[engineName].(map[string]interface{})
	if !ok {
		engineConfig = map[string]interface{}{}
	}

	config := &consensus.Config{
		Params: genesis.Params,
		Config: engineConfig,
		Path:   filepath.Join(dataDir, "consensus"),
	}

	consensus, err := engine(
		&consensus.ConsensusParams{
			Context:        context.Background(),
			Seal:           false,
			Config:         config,
			Txpool:         nil,
			Network:        &network.NonetworkServer{},
			Blockchain:     blockchain,
			Executor:       executor,
			Grpc:           nil,
			Logger:         logger.Named("consensus"),
			Metrics:        metrics,
			SecretsManager: secretsManager,
			BlockTime:      2,
			BlockBroadcast: false,
		},
	)

	if err != nil {
		return nil, err
	}

	return consensus, nil
}

func createBlockchain(
	logger hclog.Logger,
	genesis *chain.Chain,
	st state.State,
	dataDir string,
	blockMetrics *blockchain.Metrics,
	consensusMetrics *consensus.Metrics,
) (*blockchain.Blockchain, *state.Executor, consensus.Consensus, error) {
	executor := state.NewExecutor(genesis.Params, st, logger)
	executor.SetRuntime(precompiled.NewPrecompiled())
	executor.SetRuntime(evm.NewEVM())

	genesisRoot, err := executor.WriteGenesis(genesis.Genesis.Alloc)
	if err != nil {
		return nil, nil, nil, err
	}

	genesis.Genesis.StateRoot = genesisRoot

	storageBuilder := newLevelDBBuilder(logger, filepath.Join(dataDir, "blockchain"))
	storageBuilder.SetCacheSize(1024)

	chain, err := blockchain.NewBlockchain(
		logger,
		genesis,
		0, // don't care price bottom limit when reverify.
		kvstorage.NewLevelDBStorageBuilder(
			logger,
			storageBuilder,
		),
		nil,
		executor,
		blockMetrics,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	executor.GetHash = chain.GetHashHelper

	consensus, err := createConsensus(logger, genesis, chain, executor, dataDir, consensusMetrics)
	if err != nil {
		return nil, nil, nil, err
	}

	chain.SetConsensus(consensus)

	if err := chain.ComputeGenesis(); err != nil {
		return nil, nil, nil, err
	}

	// initialize data in consensus layer
	if err := consensus.Initialize(); err != nil {
		return nil, nil, nil, err
	}

	if err := consensus.Start(); err != nil {
		return nil, nil, nil, err
	}

	return chain, executor, consensus, nil
}
