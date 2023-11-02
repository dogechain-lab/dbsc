package drab

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/sha3"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/gopool"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/dccontracts"
	"github.com/ethereum/go-ethereum/core/forkid"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
)

const (
	inMemorySnapshots  = 128  // Number of recent snapshots to keep in memory
	inMemorySignatures = 4096 // Number of recent block signatures to keep in memory

	checkpointInterval = 1024           // Number of blocks after which to save the snapshot to the database
	defaultEpochLength = uint64(100000) // Default number of blocks of checkpoint to update validatorSet from contract
	defaultBlockTime   = uint64(2)      // Default seconds between blocks

	// signature extra data

	extraVanity      = 32 // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal        = 65 // Fixed number of extra-data suffix bytes reserved for signer seal
	nextForkHashSize = 4  // Fixed number of extra-data suffix bytes reserved for nextForkHash.
)

var (
	systemContracts = map[common.Address]bool{
		common.HexToAddress(dccontracts.DCValidatorSetContract): true,
		common.HexToAddress(dccontracts.DCBridgeContract):       true,
		common.HexToAddress(dccontracts.DCVaultContract):        true,
	}

	diffInTurn = big.NewInt(2) // Block difficulty for in-turn signatures
	diffNoTurn = big.NewInt(1) // Block difficulty for out-of-turn signatures
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	// errUnknownBlock is returned when the list of validators is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte signature suffix missing")

	// errExtraValidators is returned if non-sprint-end block contain validator data in
	// their extra-data fields.
	errExtraValidators = errors.New("non-sprint-end block contains extra validator list")

	// errInvalidSpanValidators is returned if a block contains an
	// invalid list of validators (i.e. non divisible by 20 bytes).
	errInvalidSpanValidators = errors.New("invalid validator list on sprint end block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidCoinbase is returned when coinbase not match with block sealer(validator).
	errInvalidCoinbase = errors.New("invalid coinbase")

	// errValidatorNotAuthorized is returned when validator not authorized by community.
	errValidatorNotAuthorized = errors.New("validator is not authorized")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errMismatchingEpochValidators is returned if a sprint block contains a
	// list of validators different than the one the local node calculated.
	errMismatchingEpochValidators = errors.New("mismatching validator list on epoch block")

	// errInvalidDifficulty is returned if the difficulty of a block is missing.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errWrongDifficulty is returned if the difficulty of a block doesn't match the
	// turn of the signer.
	errWrongDifficulty = errors.New("wrong difficulty")

	// errOutOfRangeChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errOutOfRangeChain = errors.New("out of range or non-contiguous chain")

	// errBlockHashInconsistent is returned if an authorization list is attempted to
	// insert an inconsistent block.
	errBlockHashInconsistent = errors.New("the block hash is inconsistent")

	// errUnauthorizedValidator is returned if a header is signed by a non-authorized entity.
	errUnauthorizedValidator = errors.New("unauthorized validator")

	// errRecentlySigned is returned if a header is signed by an authorized entity
	// that already signed a header recently, thus is temporarily not allowed to.
	errRecentlySigned = errors.New("recently signed")
)

// SignerFn is a signer callback function to request a header to be signed by a
// backing account.
type SignerFn func(accounts.Account, string, []byte) ([]byte, error)
type SignerTxFn func(accounts.Account, *types.Transaction, *big.Int) (*types.Transaction, error)

func isToSystemContract(to common.Address) bool {
	return systemContracts[to]
}

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, sigCache *lru.ARCCache, chainId *big.Int) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigCache.Get(hash); known {
		return address.(common.Address), nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(SealHash(header, chainId).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigCache.Add(hash, signer)
	return signer, nil
}

// Drab is the consensus engine of DBSC
//
// It is similar to parlia, implementing PoSA, too.
type Drab struct {
	chainConfig *params.ChainConfig // Chain config
	config      *params.DrabConfig  // Consensus engine configuration parameters for drab consensus
	genesisHash common.Hash
	db          ethdb.Database // Database to store and retrieve snapshot checkpoints

	recentSnaps *lru.ARCCache // Snapshots for recent block to speed up
	signatures  *lru.ARCCache // Signatures of recent blocks to speed up mining

	signer types.Signer

	val      common.Address // Ethereum address of the signing key
	signFn   SignerFn       // Signer function to authorize hashes with
	signTxFn SignerTxFn

	lock sync.RWMutex // Protects the signer fields

	ethAPI          *ethapi.PublicBlockChainAPI
	validatorSetABI *abi.ABI
	bridgeABI       *abi.ABI
	vaultABI        *abi.ABI
}

// New creates a Drab consensus engine.
func New(
	chainConfig *params.ChainConfig,
	db ethdb.Database,
	ethAPI *ethapi.PublicBlockChainAPI,
	genesisHash common.Hash,
) *Drab {
	// get config
	cfg := chainConfig.Drab

	// Set any missing consensus parameters to their defaults
	if cfg != nil && cfg.EpochSize == 0 {
		cfg.EpochSize = defaultEpochLength
	}

	if cfg != nil && cfg.BlockTime == 0 {
		cfg.BlockTime = defaultBlockTime
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
	// ABI(s)
	vABI, err := abi.JSON(strings.NewReader(validatorSetABI))
	if err != nil {
		panic(err)
	}
	bABI, err := abi.JSON(strings.NewReader(bridgeABI))
	if err != nil {
		panic(err)
	}
	vaultABI, err := abi.JSON(strings.NewReader(vaultABI))
	if err != nil {
		panic(err)
	}

	c := &Drab{
		chainConfig:     chainConfig,
		config:          cfg,
		genesisHash:     genesisHash,
		db:              db,
		ethAPI:          ethAPI,
		recentSnaps:     recentSnaps,
		signatures:      signatures,
		validatorSetABI: &vABI,
		bridgeABI:       &bABI,
		vaultABI:        &vaultABI,
		signer:          types.NewEIP155Signer(chainConfig.ChainID),
	}

	return c
}

func (d *Drab) shouldWriteSystemTransactions(header *types.Header) bool {
	// Begin with detroit hard fork, we do get some "system transactions",
	// but we don't treat them as system transactions and make direct
	// contract call only after hawaii hard fork.
	return d.chainConfig.IsHawaii(header.Number)
}

func (d *Drab) IsSystemTransaction(tx *types.Transaction, header *types.Header) (bool, error) {
	// Ensures activeness
	if !d.shouldWriteSystemTransactions(header) {
		return false, nil
	}
	// Deploy a contract.
	if tx.To() == nil {
		return false, nil
	}
	// System transaction will not charge.
	if tx.GasPrice().Cmp(big.NewInt(0)) != 0 {
		return false, nil
	}
	// Check out the sender
	sender, err := types.Sender(d.signer, tx)
	if err != nil {
		return false, errors.New("unauthorized transaction")
	}
	// Ensures coinbase send this transaction.
	if sender != header.Coinbase {
		return false, nil
	}
	// Ensures to system contracts
	if !isToSystemContract(*tx.To()) {
		return false, nil
	}

	return true, nil
}

func (d *Drab) IsSystemContract(to *common.Address) bool {
	if to == nil {
		return false
	}
	return isToSystemContract(*to)
}

// Author implements consensus.Engine, returning the SystemAddress
func (d *Drab) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (d *Drab) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return d.verifyHeader(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (d *Drab) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	gopool.Submit(func() {
		for i, header := range headers {
			err := d.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	})
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (d *Drab) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}

	// Don't waste time checking blocks from the future
	if header.Time > uint64(time.Now().Unix()) {
		return consensus.ErrFutureBlock
	}

	// Check that the extra-data contains the vanity, validators and signature.
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}

	// check extra data
	number := header.Number.Uint64()
	isEpoch := number%d.config.EpochSize == 0

	// Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
	signersBytes := len(header.Extra) - extraVanity - extraSeal
	if !isEpoch && signersBytes != 0 {
		return errExtraValidators
	}
	if isEpoch && signersBytes%validatorBytesLength != 0 {
		return errInvalidSpanValidators
	}

	// Ensure that the mix digest is drab mix hash
	if header.MixDigest != types.DrapMixHash {
		return errInvalidMixDigest
	}

	// Ensure that the block doesn't contain any uncles which are meaningless in PoSA
	if header.UncleHash != types.EmptyUncleHash {
		return errInvalidUncleHash
	}

	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 {
		if header.Difficulty == nil {
			return errInvalidDifficulty
		}
	}

	// If all checks passed, validate any special fields for hard forks
	if err := misc.VerifyForkHashes(chain.Config(), header, false); err != nil {
		return err
	}

	parent, err := d.getParent(chain, header, parents)
	if err != nil {
		return err
	}

	// Verify the block's gas usage and (if applicable) verify the base fee.
	if !chain.Config().IsLondon(header.Number) {
		// Verify BaseFee not present before EIP-1559 fork.
		if header.BaseFee != nil {
			return fmt.Errorf("invalid baseFee before fork: have %d, expected 'nil'", header.BaseFee)
		}
	} else if err := misc.VerifyEip1559Header(chain.Config(), parent, header); err != nil {
		// Verify the header's EIP-1559 attributes.
		return err
	}

	// All basic checks passed, verify cascading fields
	return d.verifyCascadingFields(chain, header, parents)
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (d *Drab) verifyCascadingFields(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}

	parent, err := d.getParent(chain, header, parents)
	if err != nil {
		return err
	}

	snap, err := d.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}

	// Verify timestamp
	err = d.blockTimeVerifyForHawaiiFork(snap, header, parent)
	if err != nil {
		return err
	}

	// Verify that the gas limit is <= 2^63-1
	const capacity = uint64(0x7fffffffffffffff)
	if header.GasLimit > capacity {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, capacity)
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}

	// Verify that the gas limit remains within allowed bounds
	if err := d.verifyGasLimit(parent, header); err != nil {
		return err
	}

	// Verify the signer
	return d.verifySeal(chain, header, parents)
}

func (d *Drab) verifyGasLimit(parent, header *types.Header) error {
	if d.chainConfig.IsLondon(header.Number) {
		return misc.VerifyEip1559Header(d.chainConfig, parent, header)
	}
	return verifyGaslimit(parent.GasLimit, header.GasLimit)
}

// getParent returns the parent of a given block.
func (d *Drab) getParent(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) (*types.Header, error) {
	var parent *types.Header
	number := header.Number.Uint64()
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}

	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return nil, consensus.ErrUnknownAncestor
	}
	return parent, nil
}

func (d *Drab) verifySeal(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	// Recover validator first
	validator, err := ecrecover(header, d.signatures, d.chainConfig.ChainID)
	if err != nil {
		return err
	}
	// Ensure that coinbase is validator
	if header.Coinbase != validator {
		return errInvalidCoinbase
	}

	// Check validator in list
	snap, err := d.snapshot(chain, header.Number.Uint64()-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	if !snap.includeValidator(validator) {
		return errValidatorNotAuthorized
	}

	// Ensure that validator not sign recently
	for seen, recent := range snap.Recents {
		if recent == validator {
			// Validator is among recents, only fail if the current block doesn't shift it out
			if limit := uint64(snap.blockLimit()); seen+limit > number {
				log.Debug("verify validator found sealed recently", "seen", seen, "limit", limit, "number", number)
				return errRecentlySigned
			}
		}
	}

	// Ensure that the difficulty corresponds to the turn-ness of the validator
	inturn := snap.inturn(validator)
	if inturn && header.Difficulty.Cmp(diffInTurn) != 0 {
		return errWrongDifficulty
	}
	if !inturn && header.Difficulty.Cmp(diffNoTurn) != 0 {
		return errWrongDifficulty
	}

	return nil
}

// snapshot retrieves the authorization snapshot at a given point in time.
func (d *Drab) snapshot(chain consensus.ChainHeaderReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	var (
		headers []*types.Header
		snap    *Snapshot
	)

	for snap == nil {
		// If an in-memory snapshot was found, use that
		if s, ok := d.recentSnaps.Get(hash); ok {
			snap = s.(*Snapshot)
			break
		}

		// If an on-disk checkpoint snapshot can be found, use that
		if number%checkpointInterval == 0 {
			if s, err := loadSnapshot(d.config, d.signatures, d.db, hash, d.ethAPI); err == nil {
				snap = s
				log.Debug("Loaded snapshot from disk", "number", number, "hash", hash, "validatorsLen", len(s.Validators), "recentsLen", len(s.Recents), "recentForkHash", s.RecentForkHashes)

				// quick fix for not correctly saved recent validators
				if len(s.Recents) >= len(s.Validators) {
					s.Recents = make(map[uint64]common.Address)
				}
				break
			}
		}

		// If we're on hawaii hardfork block, we need to use dc snapshot and store it
		if d.chainConfig.IsOnHawaii(big.NewInt(int64(number + 1))) {
			// get checkpoint data
			checkpoint := chain.GetHeaderByNumber(number)
			if checkpoint == nil {
				return nil, errUnknownBlock
			}

			// get the extra part that contains the seal
			extra, err := types.GetIbftExtra(checkpoint.Extra)
			if err != nil {
				return nil, err
			}

			// new snapshot
			snap = newSnapshot(d.config, d.signatures, number, hash, extra.Validators, d.ethAPI)
			if err := snap.store(d.db); err != nil {
				return nil, err
			}

			log.Info("Stored hawaii hardfork checkpoint snapshot to disk",
				"number", number, "hash", hash, "validators", len(extra.Validators), "recents", len(snap.Recents))
			break
		}

		// If we're at the genesis, snapshot the initial state.
		if number == 0 {
			checkpoint := chain.GetHeaderByNumber(number)
			if checkpoint != nil {
				// get checkpoint data
				hash := checkpoint.Hash()

				if len(checkpoint.Extra) <= extraVanity+extraSeal {
					return nil, errors.New("invalid extra-data for genesis block, check the genesis.json file")
				}

				validatorBytes := checkpoint.Extra[extraVanity : len(checkpoint.Extra)-extraSeal]
				// get validators from headers
				validators, err := parseValidators(validatorBytes)
				if err != nil {
					return nil, err
				}

				// new snapshot
				snap = newSnapshot(d.config, d.signatures, number, hash, validators, d.ethAPI)
				if err := snap.store(d.db); err != nil {
					return nil, err
				}

				log.Info("Stored checkpoint snapshot to disk", "number", number, "hash", hash)
				break
			}
		}

		// No snapshot for this header, gather the header and move backward
		var header *types.Header
		if len(parents) > 0 {
			// If we have explicit parents, pick from there (enforced)
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			// No explicit parents (or no more left), reach out to the database
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}

	// check if snapshot is nil
	if snap == nil {
		return nil, fmt.Errorf("unknown error while retrieving snapshot at block number %v", number)
	}

	// Previous snapshot found, reverse header to ascending order
	reverse(headers)

	// Apply headers recently to get current snapshot
	snap, err := snap.apply(headers, chain, parents, d.chainConfig.ChainID)
	if err != nil {
		return nil, err
	}
	d.recentSnaps.Add(snap.Hash, snap)
	log.Debug("snap after applying headers", "number", number, "hash", snap.Hash, "validators", len(snap.Validators), "limit", snap.blockLimit(), "recents", snap.Recents)

	// If we've generated a new checkpoint snapshot, save to disk
	if snap.Number%checkpointInterval == 0 && len(headers) > 0 {
		if err = snap.store(d.db); err != nil {
			return nil, err
		}
		log.Trace("Stored snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

func reverse[S ~[]E, E any](s S) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (d *Drab) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (d *Drab) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	header.Coinbase = d.val
	header.Nonce = types.BlockNonce{}
	header.MixDigest = types.DrapMixHash
	header.UncleHash = types.EmptyRootHash // empty uncle

	number := header.Number.Uint64()
	snap, err := d.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}

	// Set the correct difficulty
	header.Difficulty = calcDifficulty(snap, d.val)

	// Ensure the extra data has all it's components
	if len(header.Extra) < extraVanity-nextForkHashSize {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-nextForkHashSize-len(header.Extra))...)
	}
	// reset to 28 bytes
	header.Extra = header.Extra[:extraVanity-nextForkHashSize]
	// append next fork hash (only 4 bytes)
	nextForkHash := forkid.NextForkHash(d.chainConfig, d.genesisHash, number)
	header.Extra = append(header.Extra, nextForkHash[:]...)

	// update validators on epoch block
	if number%d.config.EpochSize == 0 {
		newValidators, err := d.getCurrentValidators(header.ParentHash, new(big.Int).Sub(header.Number, common.Big1))
		if err != nil {
			return err
		}
		// Use original sequence which should be sorted
		for _, validator := range newValidators {
			header.Extra = append(header.Extra, validator.Bytes()...)
		}
	}

	// add extra seal space
	header.Extra = append(header.Extra, make([]byte, extraSeal)...)

	// Ensure the timestamp has the correct delay
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	// make sure timestamp matches current
	header.Time = d.blockTimeForHawaiiFork(snap, header, parent)
	if header.Time < uint64(time.Now().Unix()) {
		header.Time = uint64(time.Now().Unix())
	}

	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given, bridge logs are handled.
func (d *Drab) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs *[]*types.Transaction,
	uncles []*types.Header, receipts *[]*types.Receipt, systemTxs *[]*types.Transaction, usedGas *uint64) error {
	// warn if not in majority fork
	number := header.Number.Uint64()
	snap, err := d.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	nextForkHash := forkid.NextForkHash(d.chainConfig, d.genesisHash, number)
	if !snap.isMajorityFork(hex.EncodeToString(nextForkHash[:])) {
		log.Debug("there is a possible fork, and your client is not the majority. Please check...", "nextForkHash", hex.EncodeToString(nextForkHash[:]))
	}

	// If the block is an epoch end block, verify the validator list
	// The verification can only be done when the state is ready, it can't be done in VerifyHeader.
	if header.Number.Uint64()%d.config.EpochSize == 0 {
		newValidators, err := d.getCurrentValidators(header.ParentHash, new(big.Int).Sub(header.Number, common.Big1))
		if err != nil {
			return err
		}
		// Join validator addresses into one slice
		validatorsBytes := make([]byte, 0, len(newValidators)*validatorBytesLength)
		for _, validator := range newValidators {
			validatorsBytes = append(validatorsBytes, validator.Bytes()...)
		}

		extraSuffix := len(header.Extra) - extraSeal
		if !bytes.Equal(header.Extra[extraVanity:extraSuffix], validatorsBytes) {
			return errMismatchingEpochValidators
		}
	}

	// Apply system transactions at last.
	ctx := chainContext{Chain: chain, engine: d}
	if header.Difficulty.Cmp(diffInTurn) != 0 {
		// Some one need to be slashed
		spoiledVal := snap.supposeValidator()
		signedRecently := false
		for _, recent := range snap.Recents {
			if recent == spoiledVal {
				signedRecently = true
				break
			}
		}
		if !signedRecently {
			log.Trace("slash validator", "block hash", header.Hash(), "address", spoiledVal)
			err = d.slash(spoiledVal, state, header, ctx, txs, receipts, systemTxs, usedGas, false)
			if err != nil {
				// impossible failure
				log.Error("slash validator failed", "block hash", header.Hash(), "address", spoiledVal)
				return err
			}
		}
	}

	// Distribute incomes
	val := header.Coinbase
	if err := d.distributeToValidator(val, state, header, ctx, txs, receipts, systemTxs, usedGas, false); err != nil {
		return err
	}

	// not consider it a system transaction
	if len(*systemTxs) > 0 {
		return errors.New("the length of systemTxs do not match")
	}

	// Handle bridge events
	return d.handleBridgeEvents(state, *receipts)
}

// FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set,
// nor block rewards given, bridge logs are handled, and returns the final block.
func (d *Drab) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB,
	txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, []*types.Receipt, error) {
	// No block rewards in PoA, so the state remains as is and uncles are dropped
	cx := chainContext{Chain: chain, engine: d}
	if txs == nil {
		txs = make([]*types.Transaction, 0)
	}
	if receipts == nil {
		receipts = make([]*types.Receipt, 0)
	}

	// check out whether sealer is out of turn
	if header.Difficulty.Cmp(diffInTurn) != 0 {
		number := header.Number.Uint64()

		snap, err := d.snapshot(chain, number-1, header.ParentHash, nil)
		if err != nil {
			return nil, nil, err
		}

		// Expected validator in turn, but we don't care about every block
		// it must sign. It is OK to go, if it signed recently.
		spoiledVal := snap.supposeValidator()
		signedRecently := false
		for _, recent := range snap.Recents {
			if recent == spoiledVal {
				signedRecently = true
				break
			}
		}
		if !signedRecently {
			// Slash validator who didn't sign recently
			err = d.slash(spoiledVal, state, header, cx, &txs, &receipts, nil, &header.GasUsed, true)
			if err != nil {
				// Possible failure because of the slash channel is disabled.
				// DC contract not implement this feature, so it is only in case.
				log.Error("slash validator failed", "block hash", header.Hash(), "address", spoiledVal)
			}
		}
	}

	// system reward
	if err := d.distributeToValidator(d.val, state, header, cx, &txs, &receipts, nil, &header.GasUsed, true); err != nil {
		return nil, nil, err
	}

	// bridge events
	if err := d.handleBridgeEvents(state, receipts); err != nil {
		return nil, nil, err
	}

	// should not happen. Once happen, stop the node is better than broadcast the block
	if header.GasLimit < header.GasUsed {
		return nil, nil, errors.New("gas consumption of system txs exceed the gas limit")
	}

	// calculate root
	var blk *types.Block
	var rootHash common.Hash
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		rootHash = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
		wg.Done()
	}()
	go func() {
		blk = types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil))
		wg.Done()
	}()
	wg.Wait()
	blk.SetRoot(rootHash)

	// Assemble and return the final block for sealing
	return blk, receipts, nil
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (d *Drab) Authorize(val common.Address, signFn SignerFn, signTxFn SignerTxFn) {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.val = val
	d.signFn = signFn
	d.signTxFn = signTxFn
}

// Argument leftOver is the time reserved for block finalize(calculate root, distribute income...)
func (d *Drab) Delay(chain consensus.ChainReader, header *types.Header, leftOver *time.Duration) *time.Duration {
	number := header.Number.Uint64()
	snap, err := d.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return nil
	}

	delay := d.delayForHawaiiFork(snap, header)

	if *leftOver >= time.Duration(d.config.BlockTime)*time.Second {
		// ignore invalid leftOver
		log.Error("Delay invalid argument", "leftOver", leftOver.String(), "BlockTime", d.config.BlockTime)
	} else if *leftOver >= delay {
		// no left time
		delay = time.Duration(0)
		return &delay
	} else {
		// delay
		delay = delay - *leftOver
	}

	return &delay
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (d *Drab) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
	if d.config.BlockTime == 0 && len(block.Transactions()) == 0 {
		log.Info("Sealing paused, waiting for transactions")
		return nil
	}
	// Don't hold the val fields for the entire sealing procedure
	d.lock.RLock()
	val, signFn := d.val, d.signFn
	d.lock.RUnlock()

	snap, err := d.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}

	// Bail out if we're unauthorized to sign a block
	if !snap.includeValidator(val) {
		return errUnauthorizedValidator
	}

	// If we're amongst the recent signers, wait for the next block
	for seen, recent := range snap.Recents {
		if recent == val {
			// Signer is among recents, only wait if the current block doesn't shift it out
			if limit := uint64(snap.blockLimit()); number < limit || seen+limit > number {
				log.Info("Sealing found signed recently, must wait for others", "seen", seen, "limit", limit, "number", number)
				return nil
			}
		}
	}

	// Sweet, the protocol permits us to sign the block, wait for our time
	delay := d.delayForHawaiiFork(snap, header)

	log.Info("Sealing block with", "number", number, "delay", delay, "headerDifficulty", header.Difficulty, "val", val.Hex())

	// Sign all the things!
	sig, err := signFn(accounts.Account{Address: val}, accounts.MimetypeParlia, DrabRLP(header, d.chainConfig.ChainID))
	if err != nil {
		return err
	}
	copy(header.Extra[len(header.Extra)-extraSeal:], sig)

	// Wait until sealing is terminated or delay timeout.
	log.Trace("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay))
	go func() {
		select {
		case <-stop:
			return
		case <-time.After(delay):
		}
		if d.shouldWaitForCurrentBlockProcess(chain, header, snap) {
			log.Info("Waiting for received in turn block to process")
			select {
			case <-stop:
				log.Info("Received block process finished, abort block seal")
				return
			case <-time.After(time.Duration(processBackOffTime) * time.Second):
				log.Info("Process backoff time exhausted, start to seal block")
			}
		}

		select {
		case results <- block.WithSeal(header):
		default:
			log.Warn("Sealing result is not read by miner", "sealhash", SealHash(header, d.chainConfig.ChainID))
		}
	}()

	return nil
}

func (d *Drab) shouldWaitForCurrentBlockProcess(chain consensus.ChainHeaderReader, header *types.Header, snap *Snapshot) bool {
	if header.Difficulty.Cmp(diffInTurn) == 0 {
		return false
	}

	highestVerifiedHeader := chain.GetHighestVerifiedHeader()
	if highestVerifiedHeader == nil {
		return false
	}

	if header.ParentHash == highestVerifiedHeader.ParentHash {
		return true
	}
	return false
}

func (d *Drab) EnoughDistance(chain consensus.ChainReader, header *types.Header) bool {
	snap, err := d.snapshot(chain, header.Number.Uint64()-1, header.ParentHash, nil)
	if err != nil {
		return true
	}
	return snap.enoughDistance(d.val, header)
}

func (d *Drab) AllowLightProcess(chain consensus.ChainReader, currentHeader *types.Header) bool {
	snap, err := d.snapshot(chain, currentHeader.Number.Uint64()-1, currentHeader.ParentHash, nil)
	if err != nil {
		return true
	}
	// validator is not allowed to diff sync
	return !snap.includeValidator(d.val)
}

func (d *Drab) IsLocalBlock(header *types.Header) bool {
	return d.val == header.Coinbase
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have based on the previous blocks in the chain and the
// current signer.
func (d *Drab) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	snap, err := d.snapshot(chain, parent.Number.Uint64(), parent.Hash(), nil)
	if err != nil {
		return nil
	}
	return calcDifficulty(snap, d.val)
}

// calcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have based on the previous blocks in the chain and the
// current signer.
func calcDifficulty(snap *Snapshot, signer common.Address) *big.Int {
	if snap.inturn(signer) {
		return new(big.Int).Set(diffInTurn)
	}
	return new(big.Int).Set(diffNoTurn)
}

// SealHash returns the hash of a block prior to it being sealed.
func (d *Drab) SealHash(header *types.Header) common.Hash {
	return SealHash(header, d.chainConfig.ChainID)
}

// APIs implements consensus.Engine, returning the user facing RPC API to query snapshot.
func (d *Drab) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{{
		Namespace: "drab",
		Version:   "1.0",
		Service:   &API{chain: chain, drab: d},
		Public:    false,
	}}
}

// Close implements consensus.Engine. It's a noop for drab as there are no background threads.
func (d *Drab) Close() error {
	return nil
}

// ==========================  interaction with contract/account =========

// getCurrentValidators get current validators
func (d *Drab) getCurrentValidators(blockHash common.Hash, blockNumber *big.Int) ([]common.Address, error) {
	// block
	blockNr := rpc.BlockNumberOrHashWithHash(blockHash, false)

	// method
	method := "validators"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // cancel when we are finished consuming integers

	data, err := d.validatorSetABI.Pack(method)
	if err != nil {
		log.Error("Unable to pack tx for getValidators", "error", err)
		return nil, err
	}
	// call
	msgData := (hexutil.Bytes)(data)
	toAddress := common.HexToAddress(dccontracts.DCValidatorSetContract)
	gas := (hexutil.Uint64)(uint64(math.MaxUint64 / 2))
	result, err := d.ethAPI.Call(ctx, ethapi.TransactionArgs{
		Gas:  &gas,
		To:   &toAddress,
		Data: &msgData,
	}, blockNr, nil)
	if err != nil {
		return nil, err
	}

	var validators []common.Address
	if err := d.validatorSetABI.UnpackIntoInterface(&validators, method, result); err != nil {
		return nil, err
	}
	return validators, nil
}

// slash spoiled validators
func (d *Drab) slash(spoiledValidator common.Address, state *state.StateDB, header *types.Header, chain core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt, receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool) error {
	// method
	method := "slash"

	// get packed data
	data, err := d.validatorSetABI.Pack(method,
		spoiledValidator,
	)
	if err != nil {
		log.Error("Unable to pack tx for slash", "error", err)
		return err
	}
	// get system message
	msg := d.getSystemMessage(header.Coinbase, common.HexToAddress(dccontracts.DCValidatorSetContract), data, common.Big0)
	// apply message
	return d.applyTransaction(msg, state, header, chain, txs, receipts, receivedTxs, usedGas, mining)
}

// slash spoiled validators
func (d *Drab) distributeToValidator(validator common.Address,
	state *state.StateDB, header *types.Header, chain core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt, receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool) error {
	// method
	method := "deposit"

	// get packed data
	data, err := d.validatorSetABI.Pack(method)
	if err != nil {
		log.Error("Unable to pack tx for deposit", "error", err)
		return err
	}
	// get system message
	msg := d.getSystemMessage(header.Coinbase, common.HexToAddress(dccontracts.DCValidatorSetContract), data, common.Big0)
	// apply message
	return d.applyTransaction(msg, state, header, chain, txs, receipts, receivedTxs, usedGas, mining)
}

// get system message
func (d *Drab) getSystemMessage(from, toAddress common.Address, data []byte, value *big.Int) callmsg {
	return callmsg{
		ethereum.CallMsg{
			From:     from,
			Gas:      math.MaxUint64 / 2,
			GasPrice: big.NewInt(0),
			Value:    value,
			To:       &toAddress,
			Data:     data,
		},
	}
}

func (d *Drab) applyTransaction(
	msg callmsg,
	state *state.StateDB,
	header *types.Header,
	chainContext core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt,
	receivedTxs *[]*types.Transaction, usedGas *uint64, mining bool,
) (err error) {
	nonce := state.GetNonce(msg.From())
	expectedTx := types.NewTransaction(nonce, *msg.To(), msg.Value(), msg.Gas(), msg.GasPrice(), msg.Data())
	expectedHash := d.signer.Hash(expectedTx)

	if msg.From() == d.val && mining {
		expectedTx, err = d.signTxFn(accounts.Account{Address: msg.From()}, expectedTx, d.chainConfig.ChainID)
		if err != nil {
			return err
		}
	} else {
		if receivedTxs == nil || len(*receivedTxs) == 0 || (*receivedTxs)[0] == nil {
			return errors.New("supposed to get a actual transaction, but get none")
		}
		actualTx := (*receivedTxs)[0]
		if !bytes.Equal(d.signer.Hash(actualTx).Bytes(), expectedHash.Bytes()) {
			return fmt.Errorf("expected tx hash %v, get %v, nonce %d, to %s, value %s, gas %d, gasPrice %s, data %s", expectedHash.String(), actualTx.Hash().String(),
				expectedTx.Nonce(),
				expectedTx.To().String(),
				expectedTx.Value().String(),
				expectedTx.Gas(),
				expectedTx.GasPrice().String(),
				hex.EncodeToString(expectedTx.Data()),
			)
		}
		expectedTx = actualTx
		// move to next
		*receivedTxs = (*receivedTxs)[1:]
	}
	state.Prepare(expectedTx.Hash(), len(*txs))
	gasUsed, err := applyMessage(msg, state, header, d.chainConfig, chainContext)
	if err != nil {
		return err
	}
	*txs = append(*txs, expectedTx)
	var root []byte
	if d.chainConfig.IsByzantium(header.Number) {
		state.Finalise(true)
	} else {
		root = state.IntermediateRoot(d.chainConfig.IsEIP158(header.Number)).Bytes()
	}
	*usedGas += gasUsed
	receipt := types.NewReceipt(root, false, *usedGas)
	receipt.TxHash = expectedTx.Hash()
	receipt.GasUsed = gasUsed

	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = state.GetLogs(expectedTx.Hash(), header.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = header.Hash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(state.TxIndex())
	*receipts = append(*receipts, receipt)
	state.SetNonce(msg.From(), nonce+1)
	return nil
}

// ===========================     utility function        ==========================
// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header, chainId *big.Int) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header, chainId)
	hasher.Sum(hash[:0])
	return hash
}

// DrabRLP returns the rlp bytes which needs to be signed for the parlia
// sealing. The RLP to sign consists of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
func DrabRLP(header *types.Header, chainId *big.Int) []byte {
	b := new(bytes.Buffer)
	encodeSigHeader(b, header, chainId)
	return b.Bytes()
}

func encodeSigHeader(w io.Writer, header *types.Header, chainId *big.Int) {
	err := rlp.Encode(w, []interface{}{
		chainId,
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-65], // this will panic if extra is too short, should check before calling encodeSigHeader
		header.MixDigest,
		header.Nonce,
	})
	if err != nil {
		panic("can't encode: " + err.Error())
	}
}

// chain context
type chainContext struct {
	Chain  consensus.ChainHeaderReader
	engine consensus.Engine
}

func (c chainContext) Engine() consensus.Engine {
	return c.engine
}

func (c chainContext) GetHeader(hash common.Hash, number uint64) *types.Header {
	return c.Chain.GetHeader(hash, number)
}

// callmsg implements core.Message to allow passing it as a transaction simulator.
type callmsg struct {
	ethereum.CallMsg
}

func (m callmsg) From() common.Address { return m.CallMsg.From }
func (m callmsg) Nonce() uint64        { return 0 }
func (m callmsg) CheckNonce() bool     { return false }
func (m callmsg) To() *common.Address  { return m.CallMsg.To }
func (m callmsg) GasPrice() *big.Int   { return m.CallMsg.GasPrice }
func (m callmsg) Gas() uint64          { return m.CallMsg.Gas }
func (m callmsg) Value() *big.Int      { return m.CallMsg.Value }
func (m callmsg) Data() []byte         { return m.CallMsg.Data }

// apply message
func applyMessage(
	msg callmsg,
	state *state.StateDB,
	header *types.Header,
	chainConfig *params.ChainConfig,
	chainContext core.ChainContext,
) (uint64, error) {
	// Create a new context to be used in the EVM environment
	context := core.NewEVMBlockContext(header, chainContext, nil)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := vm.NewEVM(context, vm.TxContext{Origin: msg.From(), GasPrice: big.NewInt(0)}, state, chainConfig, vm.Config{})
	// Apply the transaction to the current state (included in the env)
	ret, returnGas, err := vmenv.Call(
		vm.AccountRef(msg.From()),
		*msg.To(),
		msg.Data(),
		msg.Gas(),
		msg.Value(),
	)
	if err != nil {
		log.Error("apply message failed", "msg", string(ret), "err", err)
	}
	return msg.Gas() - returnGas, err
}
