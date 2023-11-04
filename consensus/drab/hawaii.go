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
	wiggleTimeGranularity      = 3 * time.Microsecond   // Time granularity of the random delay
	wiggleTimeBeforeFork       = 900 * time.Millisecond // Random delay (per signer) to allow concurrent signers
	fixedBackOffTimeBeforeFork = 400 * time.Millisecond
)

var (
	randDelaySeed = rand.New(rand.NewSource(time.Now().UnixNano()))
)

func (d *Drab) delayForHawaiiFork(snap *Snapshot, header *types.Header) time.Duration {
	delay := time.Until(time.Unix(int64(header.Time), 0)) // nolint: gosimple
	if header.Difficulty.Cmp(diffNoTurn) == 0 {
		// It's not our turn explicitly to sign, delay it a bit
		wiggle := time.Duration(snap.blockLimit()) * wiggleTimeBeforeFork
		// range 4 validator [163us, 999842us]
		wiggle = wiggleTimeGranularity * time.Duration(1+randDelaySeed.Int63n(int64(wiggle/wiggleTimeGranularity)))

		delay += fixedBackOffTimeBeforeFork + wiggle
	}
	return delay
}

func (d *Drab) blockTimeForHawaiiFork(snap *Snapshot, header, parent *types.Header) uint64 {
	blockTime := parent.Time + d.config.BlockTime
	if d.chainConfig.IsHawaii(header.Number) {
		blockTime = blockTime + d.backOffTime(snap, header, d.val)
	}
	return blockTime
}

func (d *Drab) blockTimeVerifyForHawaiiFork(snap *Snapshot, header, parent *types.Header) error {
	if d.chainConfig.IsHawaii(header.Number) {
		if header.Time < parent.Time+d.config.BlockTime+d.backOffTime(snap, header, header.Coinbase) {
			return consensus.ErrFutureBlock
		}
	}
	return nil
}

func (d *Drab) backOffTime(snap *Snapshot, header *types.Header, val common.Address) uint64 {
	if snap.inturn(val) {
		return 0
	} else {
		delay := initialBackOffTime
		validators := snap.Validators
		if d.chainConfig.IsHawaii(header.Number) {
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
