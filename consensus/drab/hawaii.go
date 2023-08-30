package drab

import (
	"math/rand"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

const (
	wiggleTime                 = uint64(1)              // second, Random delay (per signer) to allow concurrent signers
	initialBackOffTime         = uint64(1)              // second
	processBackOffTime         = uint64(1)              // second
	wiggleTimeBeforeFork       = 500 * time.Millisecond // Random delay (per signer) to allow concurrent signers
	fixedBackOffTimeBeforeFork = 200 * time.Millisecond
)

func (p *Drab) delayForHawaiiFork(snap *Snapshot, header *types.Header) time.Duration {
	delay := time.Until(time.Unix(int64(header.Time), 0)) // nolint: gosimple
	if header.Difficulty.Cmp(diffNoTurn) == 0 {
		// It's not our turn explicitly to sign, delay it a bit
		wiggle := time.Duration(len(snap.Validators)/2+1) * wiggleTimeBeforeFork
		delay += fixedBackOffTimeBeforeFork + time.Duration(rand.Int63n(int64(wiggle)))
	}
	return delay
}

func (p *Drab) blockTimeForHawaiiFork(snap *Snapshot, header, parent *types.Header) uint64 {
	blockTime := parent.Time + p.config.BlockTime
	if p.chainConfig.IsHawaii(header.Number) {
		blockTime = blockTime + p.backOffTime(snap, header, p.val)
	}
	return blockTime
}

func (p *Drab) blockTimeVerifyForHawaiiFork(snap *Snapshot, header, parent *types.Header) error {
	if p.chainConfig.IsHawaii(header.Number) {
		if header.Time < parent.Time+p.config.BlockTime+p.backOffTime(snap, header, header.Coinbase) {
			return consensus.ErrFutureBlock
		}
	}
	return nil
}

func (p *Drab) backOffTime(snap *Snapshot, header *types.Header, val common.Address) uint64 {
	if snap.inturn(val) {
		return 0
	} else {
		delay := initialBackOffTime
		validators := snap.Validators
		if p.chainConfig.IsHawaii(header.Number) {
			// reverse the key/value of snap.Recents to get recentsMap
			recentsMap := make(map[common.Address]uint64, len(snap.Recents))
			bound := uint64(0)
			if n, limit := header.Number.Uint64(), uint64(len(validators)/2+1); n > limit {
				bound = n - limit
			}
			for seen, recent := range snap.Recents {
				if seen <= bound {
					continue
				}
				recentsMap[recent] = seen
			}

			// The backOffTime does not matter when a validator has signed recently.
			if _, ok := recentsMap[val]; ok {
				return 0
			}

			inTurnAddr := validators[(snap.Number+1)%uint64(len(validators))]
			if _, ok := recentsMap[inTurnAddr]; ok {
				log.Debug("in turn validator has recently signed, skip initialBackOffTime",
					"inTurnAddr", inTurnAddr)
				delay = 0
			}

			// Exclude the recently signed validators
			temp := make([]common.Address, 0, len(validators))
			for _, addr := range validators {
				if _, ok := recentsMap[addr]; ok {
					continue
				}
				temp = append(temp, addr)
			}
			validators = temp
		}

		// get the index of current validator and its shuffled backoff time.
		idx := -1
		for index, itemAddr := range validators {
			if val == itemAddr {
				idx = index
			}
		}
		if idx < 0 {
			log.Info("The validator is not authorized", "addr", val)
			return 0
		}

		s := rand.NewSource(int64(snap.Number))
		r := rand.New(s)
		n := len(validators)
		backOffSteps := make([]uint64, 0, n)

		for i := uint64(0); i < uint64(n); i++ {
			backOffSteps = append(backOffSteps, i)
		}

		r.Shuffle(n, func(i, j int) {
			backOffSteps[i], backOffSteps[j] = backOffSteps[j], backOffSteps[i]
		})

		delay += backOffSteps[idx] * wiggleTime
		return delay
	}
}
