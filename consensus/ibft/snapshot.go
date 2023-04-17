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

package ibft

import (
	"bytes"
	"encoding/json"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/params"
	lru "github.com/hashicorp/golang-lru"
)

// Snapshot is the state of the validatorSet at a given point.
type Snapshot struct {
	config       *params.IBFTConfig // Consensus engine parameters to fine tune behavior
	ethAPI       *ethapi.PublicBlockChainAPI
	sigCache     *lru.ARCCache               // Cache of recent block signatures to speed up ecrecover
	validatorSet map[common.Address]struct{} // validator set for quick query

	Number     uint64           `json:"number"`     // Block number where the snapshot was created
	Hash       common.Hash      `json:"hash"`       // Block hash where the snapshot was created
	Validators []common.Address `json:"validators"` // Sequenced slice of authorized validators at this moment
}

// newSnapshot creates a new snapshot with the specified startup parameters. This
// method does not initialize the set of recent validators, so only ever use it for
// the genesis block.
func newSnapshot(
	config *params.IBFTConfig,
	sigCache *lru.ARCCache,
	number uint64,
	hash common.Hash,
	validators []common.Address,
	ethAPI *ethapi.PublicBlockChainAPI,
) *Snapshot {
	snap := &Snapshot{
		config:       config,
		ethAPI:       ethAPI,
		sigCache:     sigCache,
		validatorSet: make(map[common.Address]struct{}),
		Number:       number,
		Hash:         hash,
		Validators:   validators,
	}
	for _, v := range validators {
		snap.validatorSet[v] = struct{}{}
	}
	return snap
}

// loadSnapshot loads an existing snapshot from the database.
func loadSnapshot(config *params.IBFTConfig, sigCache *lru.ARCCache, db ethdb.Database, hash common.Hash, ethAPI *ethapi.PublicBlockChainAPI) (*Snapshot, error) {
	blob, err := db.Get(append([]byte("ibft-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(Snapshot)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	snap.config = config
	snap.sigCache = sigCache
	snap.ethAPI = ethAPI
	// reset cache
	snap.validatorSet = make(map[common.Address]struct{})
	for _, val := range snap.Validators {
		snap.validatorSet[val] = struct{}{}
	}

	return snap, nil
}

// store inserts the snapshot into the database.
func (s *Snapshot) store(db ethdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append([]byte("ibft-"), s.Hash[:]...), blob)
}

func (s *Snapshot) copyValidators() []common.Address {
	v := make([]common.Address, len(s.Validators))
	copy(v, s.Validators)
	return v
}

// copy creates a deep copy of the snapshot
func (s *Snapshot) copy() *Snapshot {
	cpy := &Snapshot{
		config:       s.config,
		ethAPI:       s.ethAPI,
		sigCache:     s.sigCache,
		validatorSet: make(map[common.Address]struct{}),
		Number:       s.Number,
		Hash:         s.Hash,
		Validators:   make([]common.Address, len(s.Validators)),
	}

	for i, v := range s.Validators {
		cpy.Validators[i] = v
		cpy.validatorSet[v] = struct{}{}
	}
	return cpy
}

func (s *Snapshot) apply(headers []*types.Header, chain consensus.ChainHeaderReader, parents []*types.Header, chainId *big.Int) (*Snapshot, error) {
	// Allow passing in no headers for cleaner code
	if len(headers) == 0 {
		return s, nil
	}
	// Sanity check that the headers can be applied
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
			return nil, errOutOfRangeChain
		}
		if !bytes.Equal(headers[i+1].ParentHash.Bytes(), headers[i].Hash().Bytes()) {
			return nil, errBlockHashInconsistent
		}
	}
	if headers[0].Number.Uint64() != s.Number+1 {
		return nil, errOutOfRangeChain
	}
	if !bytes.Equal(headers[0].ParentHash.Bytes(), s.Hash.Bytes()) {
		return nil, errBlockHashInconsistent
	}
	// Iterate through the headers and create a new snapshot
	snap := s.copy()

	for _, header := range headers {
		number := header.Number.Uint64()
		// Resolve the authorization key and check against signers
		validator, err := ecrecover(header, s.sigCache, chainId)
		if err != nil {
			return nil, err
		}
		// Check whether it is in validator set
		if !snap.includeValidator(validator) {
			return nil, errUnauthorizedValidator
		}
		// change validator set
		if number > 0 && number%s.config.EpochSize == 0 {
			checkpointHeader := FindAncientHeader(header, uint64(len(snap.Validators)/2), chain, parents)
			if checkpointHeader == nil {
				return nil, consensus.ErrUnknownAncestor
			}
			// parse validators from extra
			extra, err := types.GetIbftExtra(checkpointHeader.Extra)
			if err != nil {
				return nil, err
			}
			// new set
			newValSet := make(map[common.Address]struct{}, len(extra.Validators))
			for _, val := range extra.Validators {
				newValSet[val] = struct{}{}
			}
			snap.Validators = extra.Validators
			snap.validatorSet = newValSet
		}
	}
	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()
	return snap, nil
}

func (s *Snapshot) validatorCount() int {
	return len(s.Validators)
}

func (s *Snapshot) includeValidator(validator common.Address) bool {
	_, exists := s.validatorSet[validator]
	return exists
}

// Is header number distance enough to do dirty flush
func (s *Snapshot) enoughDistance(validator common.Address, header *types.Header) bool {
	idx := s.indexOfVal(validator)
	if idx < 0 {
		return true
	}
	validatorNum := int64(s.validatorCount())
	if validatorNum == 1 {
		return true
	}
	if validator == header.Coinbase {
		return false
	}
	// It's meaningless when validators are less than 5, since we'll get true
	// most of the time.
	offset := (int64(s.Number) + 1) % validatorNum
	if int64(idx) >= offset {
		return int64(idx)-offset >= validatorNum-2
	} else {
		return validatorNum+int64(idx)-offset >= validatorNum-2
	}
}

func (s *Snapshot) indexOfVal(validator common.Address) int {
	for idx, val := range s.Validators {
		if val == validator {
			return idx
		}
	}
	return -1
}

func FindAncientHeader(header *types.Header, ite uint64, chain consensus.ChainHeaderReader, candidateParents []*types.Header) *types.Header {
	ancient := header
	for i := uint64(1); i <= ite; i++ {
		parentHash := ancient.ParentHash
		parentHeight := ancient.Number.Uint64() - 1
		found := false
		if len(candidateParents) > 0 {
			index := sort.Search(len(candidateParents), func(i int) bool {
				return candidateParents[i].Number.Uint64() >= parentHeight
			})
			if index < len(candidateParents) && candidateParents[index].Number.Uint64() == parentHeight &&
				candidateParents[index].Hash() == parentHash {
				ancient = candidateParents[index]
				found = true
			}
		}
		if !found {
			ancient = chain.GetHeader(parentHash, parentHeight)
			found = true
		}
		if ancient == nil || !found {
			return nil
		}
	}
	return ancient
}
