// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package ethconfig contains the configuration of the ETH and LES protocols.
package ethconfig

import (
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/clique"
	"github.com/ethereum/go-ethereum/consensus/dc"
	"github.com/ethereum/go-ethereum/consensus/drab"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/consensus/parlia"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/gasprice"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
)

// FullNodeGPO contains default gasprice oracle settings for full node.
var FullNodeGPO = gasprice.Config{
	Blocks:          20,
	Percentile:      60,
	MaxPrice:        gasprice.DefaultMaxPrice,
	OracleThreshold: 1000,
	IgnorePrice:     gasprice.DefaultIgnorePrice,
}

// LightClientGPO contains default gasprice oracle settings for light client.
var LightClientGPO = gasprice.Config{
	Blocks:      2,
	Percentile:  60,
	MaxPrice:    gasprice.DefaultMaxPrice,
	IgnorePrice: gasprice.DefaultIgnorePrice,
}

// Defaults contains default settings for use on the Ethereum main net.
var Defaults = Config{
	SyncMode: downloader.SnapSync,
	Ethash: ethash.Config{
		CacheDir:         "ethash",
		CachesInMem:      2,
		CachesOnDisk:     3,
		CachesLockMmap:   false,
		DatasetsInMem:    1,
		DatasetsOnDisk:   2,
		DatasetsLockMmap: false,
	},
	NetworkId:               1,
	TxLookupLimit:           2350000,
	LightPeers:              100,
	UltraLightFraction:      75,
	DatabaseCache:           512,
	TrieCleanCache:          154,
	TrieCleanCacheJournal:   "triecache",
	TrieCleanCacheRejournal: 60 * time.Minute,
	TrieDirtyCache:          256,
	TrieTimeout:             60 * time.Minute,
	TriesInMemory:           128,
	TriesVerifyMode:         core.LocalVerify,
	SnapshotCache:           102,
	DisableDiffProtocol:     true,
	DiffBlock:               uint64(86400),
	Miner: miner.Config{
		GasCeil:       30000000,
		GasPrice:      big.NewInt(250 * params.GWei),
		Recommit:      3 * time.Second,
		DelayLeftOver: 50 * time.Millisecond,
	},
	TxPool:        core.DefaultTxPoolConfig,
	RPCGasCap:     50000000,
	RPCEVMTimeout: 5 * time.Second,
	GPO:           FullNodeGPO,
	RPCTxFeeCap:   0, // no cap limit
}

func init() {
	home := os.Getenv("HOME")
	if home == "" {
		if user, err := user.Current(); err == nil {
			home = user.HomeDir
		}
	}
	if runtime.GOOS == "darwin" {
		Defaults.Ethash.DatasetDir = filepath.Join(home, "Library", "Ethash")
	} else if runtime.GOOS == "windows" {
		localappdata := os.Getenv("LOCALAPPDATA")
		if localappdata != "" {
			Defaults.Ethash.DatasetDir = filepath.Join(localappdata, "Ethash")
		} else {
			Defaults.Ethash.DatasetDir = filepath.Join(home, "AppData", "Local", "Ethash")
		}
	} else {
		Defaults.Ethash.DatasetDir = filepath.Join(home, ".ethash")
	}
}

//go:generate gencodec -type Config -formats toml -out gen_config.go

// Config contains configuration options for of the ETH and LES protocols.
type Config struct {
	// The genesis block, which is inserted if the database is empty.
	// If nil, the Ethereum main net block is used.
	Genesis *core.Genesis `toml:",omitempty"`

	// Protocol options
	NetworkId uint64 // Network ID to use for selecting peers to connect to
	SyncMode  downloader.SyncMode

	// DisablePeerTxBroadcast is an optional config and disabled by default, and usually you do not need it.
	// When this flag is enabled, you are requesting remote peers to stop broadcasting new transactions to you, and
	// it does not mean that your node will stop broadcasting transactions to remote peers.
	// If your node does care about new mempool transactions (e.g., running rpc services without the need of mempool
	// transactions) or is continuously under high pressure (e.g., mempool is always full), then you can consider
	// to turn it on.
	DisablePeerTxBroadcast bool

	// This can be set to list of enrtree:// URLs which will be queried for
	// for nodes to connect to.
	EthDiscoveryURLs   []string
	SnapDiscoveryURLs  []string
	TrustDiscoveryURLs []string

	NoPruning           bool // Whether to disable pruning and flush everything to disk
	DirectBroadcast     bool
	DisableSnapProtocol bool //Whether disable snap protocol
	DisableDiffProtocol bool //Whether disable diff protocol
	EnableTrustProtocol bool //Whether enable trust protocol
	DiffSync            bool // Whether support diff sync
	PipeCommit          bool
	RangeLimit          bool

	TxLookupLimit uint64 `toml:",omitempty"` // The maximum number of blocks from head whose tx indices are reserved.

	// Whitelist of required block number -> hash values to accept
	Whitelist map[uint64]common.Hash `toml:"-"`

	// Light client options
	LightServ          int  `toml:",omitempty"` // Maximum percentage of time allowed for serving LES requests
	LightIngress       int  `toml:",omitempty"` // Incoming bandwidth limit for light servers
	LightEgress        int  `toml:",omitempty"` // Outgoing bandwidth limit for light servers
	LightPeers         int  `toml:",omitempty"` // Maximum number of LES client peers
	LightNoPrune       bool `toml:",omitempty"` // Whether to disable light chain pruning
	LightNoSyncServe   bool `toml:",omitempty"` // Whether to serve light clients before syncing
	SyncFromCheckpoint bool `toml:",omitempty"` // Whether to sync the header chain from the configured checkpoint

	// Ultra Light client options
	UltraLightServers      []string `toml:",omitempty"` // List of trusted ultra light servers
	UltraLightFraction     int      `toml:",omitempty"` // Percentage of trusted servers to accept an announcement
	UltraLightOnlyAnnounce bool     `toml:",omitempty"` // Whether to only announce headers, or also serve them

	// Database options
	SkipBcVersionCheck bool `toml:"-"`
	DatabaseHandles    int  `toml:"-"`
	DatabaseCache      int
	DatabaseFreezer    string
	DatabaseDiff       string
	PersistDiff        bool
	DiffBlock          uint64
	// PruneAncientData is an optional config and disabled by default, and usually you do not need it.
	// When this flag is enabled, only keep the latest 9w blocks' data, the older blocks' data will be
	// pruned instead of being dumped to freezerdb, the pruned data includes CanonicalHash, Header, Block,
	// Receipt and TotalDifficulty.
	// Notice: the PruneAncientData once be turned on, the get/chaindata/ancient dir will be removed,
	// if restart without the pruneancient flag, the ancient data will start with the previous point that
	// the oldest unpruned block number.
	PruneAncientData bool

	TrieCleanCache          int
	TrieCleanCacheJournal   string        `toml:",omitempty"` // Disk journal directory for trie cache to survive node restarts
	TrieCleanCacheRejournal time.Duration `toml:",omitempty"` // Time interval to regenerate the journal for clean cache
	TrieDirtyCache          int
	TrieTimeout             time.Duration
	SnapshotCache           int
	TriesInMemory           uint64
	TriesVerifyMode         core.VerifyMode
	Preimages               bool

	// Mining options
	Miner miner.Config

	// Ethash options
	Ethash ethash.Config `toml:",omitempty"`

	// Transaction pool options
	TxPool core.TxPoolConfig

	// Gas Price Oracle options
	GPO gasprice.Config

	// Enables tracking of SHA3 preimages in the VM
	EnablePreimageRecording bool

	// Miscellaneous options
	DocRoot string `toml:"-"`

	// RPCGasCap is the global gas cap for eth-call variants.
	RPCGasCap uint64

	// RPCEVMTimeout is the global timeout for eth-call.
	RPCEVMTimeout time.Duration

	// RPCTxFeeCap is the global transaction fee(price * gaslimit) cap for
	// send-transction variants. The unit is ether.
	RPCTxFeeCap float64

	// Checkpoint is a hardcoded checkpoint which can be nil.
	Checkpoint *params.TrustedCheckpoint `toml:",omitempty"`

	// CheckpointOracle is the configuration for checkpoint oracle.
	CheckpointOracle *params.CheckpointOracleConfig `toml:",omitempty"`

	// Berlin block override (TODO: remove after the fork)
	OverrideBerlin *big.Int `toml:",omitempty"`

	// Arrow Glacier block override (TODO: remove after the fork)
	OverrideArrowGlacier *big.Int `toml:",omitempty"`

	// OverrideTerminalTotalDifficulty (TODO: remove after the fork)
	OverrideTerminalTotalDifficulty *big.Int `toml:",omitempty"`
}

// CreateConsensusEngine creates a consensus engine for the given chain configuration.
func CreateConsensusEngine(stack *node.Node, chainConfig *params.ChainConfig, config *ethash.Config, notify []string, noverify bool, db ethdb.Database, ee *ethapi.PublicBlockChainAPI, genesisHash common.Hash) (consensus.Engine, error) {
	// drab
	if chainConfig.Drab != nil {
		return drab.New(chainConfig, db, ee, genesisHash), nil
	}
	// dc, original dogechain data
	if chainConfig.Doge != nil {
		return dc.New(chainConfig, stack.Config(), db, ee)
	}
	// parlia
	if chainConfig.Parlia != nil {
		return parlia.New(chainConfig, db, ee, genesisHash), nil
	}
	// If proof-of-authority is requested, set it up
	var engine consensus.Engine
	if chainConfig.Clique != nil {
		engine = clique.New(chainConfig.Clique, db)
	} else {
		switch config.PowMode {
		case ethash.ModeFake:
			log.Warn("Ethash used in fake mode")
		case ethash.ModeTest:
			log.Warn("Ethash used in test mode")
		case ethash.ModeShared:
			log.Warn("Ethash used in shared mode")
		}
		engine = ethash.New(ethash.Config{
			PowMode:          config.PowMode,
			CacheDir:         stack.ResolvePath(config.CacheDir),
			CachesInMem:      config.CachesInMem,
			CachesOnDisk:     config.CachesOnDisk,
			CachesLockMmap:   config.CachesLockMmap,
			DatasetDir:       config.DatasetDir,
			DatasetsInMem:    config.DatasetsInMem,
			DatasetsOnDisk:   config.DatasetsOnDisk,
			DatasetsLockMmap: config.DatasetsLockMmap,
			NotifyFull:       config.NotifyFull,
		}, notify, noverify)
		engine.(*ethash.Ethash).SetThreads(-1) // Disable CPU mining
	}
	return beacon.New(engine), nil
}
