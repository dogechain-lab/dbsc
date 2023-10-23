package dc

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/gopool"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"

	lru "github.com/hashicorp/golang-lru"

	"golang.org/x/crypto/sha3"

	dcState "github.com/dogechain-lab/dogechain/state"
)

var (
	// errBlockHeaderNotExists is returned when block header not exists.
	errBlockHeaderNotExists = errors.New("block header not exists")

	// errBlockNotExists is returned when block not exists.
	errBlockNotExists = errors.New("block not exists")

	// errInvalidBlockTimestamp is returned when it is a future block.
	errInvalidBlockTimestamp = errors.New("invalid block timestamp")

	// errInvalidCommittedSeal is returned when committed seal not from valid validators.
	errInvalidCommittedSeal = errors.New("invalid committed seal")

	// errInvalidCoinbase is returned when coinbase not match with block sealer(validator).
	errInvalidCoinbase = errors.New("invalid coinbase")

	// errValidatorNotAuthorized is returned when validator not authorized by community.
	errValidatorNotAuthorized = errors.New("validator is not authorized")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block is missing.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errOutOfRangeChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errOutOfRangeChain = errors.New("out of range or non-contiguous chain")

	// errBlockHashInconsistent is returned if an authorization list is attempted to
	// insert an inconsistent block.
	errBlockHashInconsistent = errors.New("the block hash is inconsistent")

	// errUnauthorizedValidator is returned if a header is signed by a non-authorized entity.
	errUnauthorizedValidator = errors.New("unauthorized validator")

	errNotSupported = errors.New("not supported")
)

// SignerFn is a signer callback function to request a header to be signed by a
// backing account.
type SignerFn func(accounts.Account, string, []byte) ([]byte, error)
type SignerTxFn func(accounts.Account, *types.Transaction, *big.Int) (*types.Transaction, error)

type executionResult struct {
	gasUsed uint64
	data    []byte
	err     error
}

func (er *executionResult) UsedGas() uint64 {
	return er.gasUsed
}

func (er *executionResult) ReturnData() []byte {
	return er.data
}

func (er *executionResult) Error() error {
	return er.err
}

// Author implements consensus.Engine, returning the SystemAddress
func (dc *DogeChain) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (dc *DogeChain) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return dc.verifyHeader(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (dc *DogeChain) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	gopool.Submit(func() {
		for i, header := range headers {
			err := dc.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	})
	return abort, results
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (dc *DogeChain) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (dc *DogeChain) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	return nil
}

func (dc *DogeChain) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs *[]*types.Transaction,
	uncles []*types.Header, receipts *[]*types.Receipt, systemTxs *[]*types.Transaction, usedGas *uint64) error {
	// TODO: use DC consensus to finalize block
	return errNotSupported
}

// FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set,
// nor block rewards given, and returns the final block.
func (dc *DogeChain) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB,
	txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, []*types.Receipt, error) {
	return nil, nil, errNotSupported
}

func (dc *DogeChain) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	return nil
}

// SealHash returns the hash of a block prior to it being sealed.
func (dc *DogeChain) SealHash(header *types.Header) common.Hash {
	extra, _ := types.GetIbftExtra(header.Extra)
	return sealHash(header, dc.chainConfig.ChainID, extra)
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have based on the previous blocks in the chain and the
// current signer.
func (dc *DogeChain) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return difficultyByParentNumber(parent.Number)
}

// APIs implements consensus.Engine, returning the user facing RPC API to query snapshot.
func (dc *DogeChain) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{}
}

// Argument leftOver is the time reserved for block finalize(calculate root, distribute income...)
func (dc *DogeChain) Delay(chain consensus.ChainReader, header *types.Header, leftOver *time.Duration) *time.Duration {
	return nil
}

func (dc *DogeChain) DoCall(msg *consensus.DcTxnArgs, header *types.Header, globalGasCap uint64) (consensus.ExecutionResult, error) {
	dcHeader, exist := dc.blockchain.GetHeaderByHash(DbscHashToDcHash(header.Hash()))
	if !exist {
		return nil, errBlockHeaderNotExists
	}

	blockCreator, err := dc.consensus.GetBlockCreator(dcHeader)
	if err != nil {
		log.Error("failed to get block creator", "error", err)

		return nil, errBlockNotExists
	}

	transition, err := dc.executor.BeginTxn(dcHeader.StateRoot, dcHeader, blockCreator)
	if err != nil {
		log.Error("failed to begin transaction", "error", err)

		return nil, err
	}

	txn := TxnArgsToTx(msg)
	result, err := transition.Apply(txn)
	if err != nil {
		return nil, err
	}

	return &executionResult{
		gasUsed: result.GasUsed,
		data:    result.ReturnValue,
		err:     result.Err,
	}, err
}

func (dc *DogeChain) Process(block *types.Block, statedb *state.StateDB) (*state.StateDB, types.Receipts, []*types.Log, uint64, error) {
	dc.lock.Lock()
	defer dc.lock.Unlock()

	start := time.Now()
	defer func() {
		statedb.DCProcessBlock += time.Since(start)
	}()

	dcBlk := DbscBlockToDcBlock(dc.chainConfig, block)

	statedb.MarkFullProcessed()
	dc.state.SetCommitHook(func(objs []*dcState.Object) {
		start := time.Now()
		defer func() {
			statedb.DCCommitHooks += time.Since(start)
		}()

		for _, obj := range objs {
			// objstart := time.Now()
			address := DcAddressToDbscAddress(obj.Address)

			if obj.Deleted {
				// empty object may have transition, so we'll leave it to statedb jounal
				if obj.Nonce == 0 && obj.Balance.Sign() == 0 && bytes.Equal(obj.CodeHash.Bytes(), types.EmptyCodeHash) {
				} else {
					// is suicide object
					statedb.Suicide(address)
					// statedb.DCSetObjects += time.Since(objstart)
					// statedb.DCObjects++
					continue
				}
			}

			dbscObj := statedb.GetOrNewStateObject(address)
			// statedb.DCGetObjects += time.Since(objstart)

			// substart := time.Now()
			dbscObj.SetBalance(obj.Balance)
			dbscObj.SetNonce(obj.Nonce)
			dbscObj.SetCode(common.Hash(obj.CodeHash), obj.Code)
			// statedb.DCSetObjects += time.Since(substart)

			// update storage
			for _, kv := range obj.Storage {
				// storagestart := time.Now()
				if kv.Deleted {
					statedb.SetState(address, common.BytesToHash(kv.Key), common.Hash{})
				} else {
					statedb.SetState(
						address,
						common.BytesToHash(kv.Key),
						common.BytesToHash(kv.Val),
					)
				}
				// statedb.DCSetStorages += time.Since(storagestart)
				// statedb.DCStorages++
			}

			// statedb.DCObjects++
		}
	})

	substart := time.Now()

	// Do the initial block verification
	if err := dc.blockchain.VerifyFinalizedBlock(dcBlk); err != nil {
		return statedb, nil, nil, 0, err
	}
	// Update metrics
	statedb.DCVerifications += time.Since(substart)

	substart = time.Now()
	if err := dc.blockchain.WriteBlock(dcBlk, "dbsc"); err != nil {
		return statedb, nil, nil, 0, fmt.Errorf("failed to write block while bulk syncing: %w", err)
	}
	// Update metrics
	statedb.DCWriteBlocks += time.Since(substart)

	substart = time.Now()
	statedb.Finalise(true)
	// Update metrics
	statedb.DCFinaliseStates += time.Since(substart)

	substart = time.Now()
	// Handle bridge logs
	receipts, err := dc.blockchain.GetReceiptsByHash(dcBlk.Header.Hash)
	if err != nil {
		return statedb, nil, nil, 0, nil
	}
	// Update metrics
	statedb.DCGetReceipts += time.Since(substart)

	dbscReceipts := DcReceiptsToDbscReceipts(receipts)

	var allLogs []*types.Log

	for _, receipt := range dbscReceipts {
		allLogs = append(allLogs, receipt.Logs...)
	}

	return statedb, dbscReceipts, allLogs, dcBlk.Header.GasUsed, nil
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (dc *DogeChain) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// Ensure that the mix digest is ibft mix hash
	if header.MixDigest != types.IBFTMixHash {
		return types.ErrIBFTInvalidMixHash
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoS
	if header.UncleHash != types.EmptyUncleHash {
		return errInvalidUncleHash
	}
	// Difficulty has to match number for previous ibft consensus
	if header.Number.Cmp(header.Difficulty) != 0 {
		return errInvalidDifficulty
	}

	// Check timestamp after detroit hard fork
	if dc.chainConfig.IsDetorit(header.Number) {
		// Get parent
		var parent *types.Header
		if len(parents) > 0 {
			parent = parents[len(parents)-1]
		} else {
			parent = chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
		}
		// The diff between block timestamp and 'now' should not exceeds timeout.
		// Timestamp ascending array [parentTs, blockTs, now+blockTimeout]
		before, after := parent.Time, uint64(time.Now().Add(targetBlockTime).Unix())

		// header timestamp should not goes back
		if header.Time <= before || header.Time > after {
			log.Warn("future blocktime invalid",
				"before", before,
				"after", after,
				"current", header.Time,
			)

			return errInvalidBlockTimestamp
		}
	}

	// Verify the sealer
	return dc.verifySigner(chain, header, parents)
}

func (dc *DogeChain) verifySigner(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// Recover validator first
	validator, err := ecrecover(header, dc.signatures, dc.chainConfig.ChainID)
	if err != nil {
		return errInvalidCommittedSeal
	}
	// Ensure that coinbase is validator
	if header.Coinbase != validator {
		return errInvalidCoinbase
	}
	// check validator in list
	snap, err := dc.snapshot(chain, header.Number.Uint64()-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	if !snap.includeValidator(validator) {
		return errValidatorNotAuthorized
	}

	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (dc *DogeChain) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return nil
}

// old version ibft returns block number directly
func difficultyByParentNumber(num *big.Int) *big.Int {
	return new(big.Int).Add(num, big.NewInt(1))
}

func sealHash(header *types.Header, chainId *big.Int, extra *types.IBFTExtra) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	types.IBFTHeaderExtraRLPHash(hasher, header, extra)
	hasher.Sum(hash[:0])
	return hash
}

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, sigCache *lru.ARCCache, chainId *big.Int) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigCache.Get(hash); known {
		return address.(common.Address), nil
	}

	// get the extra part that contains the seal
	extra, err := types.GetIbftExtra(header.Extra)
	if err != nil {
		return common.Address{}, err
	}

	// Retrieve the signature from the header extra-data
	// Recover the public key and the Ethereum address
	// TODO: should be use different hash from IBFT for
	// not modified block hash?
	pubkey, err := crypto.Ecrecover(crypto.Keccak256(hash.Bytes()), extra.Seal)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	// save to cache
	sigCache.Add(hash, signer)

	return signer, nil
}
