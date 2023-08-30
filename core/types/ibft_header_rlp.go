package types

import (
	"bytes"
	"errors"
	"io"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	// IBFTExtraVanity (Istanbul BFT Vanity) represents a fixed number of extra-data bytes reserved for proposer vanity
	IBFTExtraVanity = 32
)

var (
	ErrIBFTInvalidMixHash     = errors.New("invalid ibft mix hash")
	ErrInvalidIBFTExtraLength = errors.New("invalid ibft extra length")
	ErrNotIBFTExtraPrefix     = errors.New("not ibft extra prefix")
)

var (
	// IBFTMixHash represents a hash of "Istanbul practical byzantine fault tolerance"
	// to identify whether the block is from Istanbul consensus engine
	IBFTMixHash = common.HexToHash("0x63746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365")

	// IBFTExtraPrefix represents extra hash prefix of "Istanbul practical byzantine fault tolerance".
	// The difference of extra between geth, bsc and dogechain (ibft) is that ibft uses zero instead of
	// client version on prefix
	IBFTExtraPrefix = common.Hash{}

	// DrapMixHash represents a hash of drap consensus
	// to identify whether the block reaches specific
	// hard fork.
	//
	// Keccak256("Dogechain drab consensus")
	DrapMixHash = common.HexToHash("0x13912b8b1e9f8bfbe6744f894d9ab0eb74ab0abb35049115b4b618961f4ec26f")
)

// IBFTExtra defines the structure of the extra field for I(stanbul)BFT
type IBFTExtra struct {
	Validators    []common.Address
	Seal          []byte
	CommittedSeal [][]byte
}

// GetIbftExtra returns the istanbul extra data field from the passed in header
func GetIbftExtra(extradata []byte) (*IBFTExtra, error) {
	// must longer than ibft extra prefix
	if len(extradata) < IBFTExtraVanity {
		return nil, ErrInvalidIBFTExtraLength
	}

	// must be ibft extra prefix
	if !bytes.Equal(extradata[:IBFTExtraVanity], IBFTExtraPrefix[:]) {
		return nil, ErrNotIBFTExtraPrefix
	}

	realdata := extradata[IBFTExtraVanity:]
	extra := &IBFTExtra{}

	if err := rlp.DecodeBytes(realdata, extra); err != nil {
		return nil, err
	}

	return extra, nil
}

// putIBFTExtraValidators is a helper method that adds validators to the extra field in the header
func putIBFTExtraValidators(h *Header, validators []common.Address) error {
	ibftExtra := &IBFTExtra{
		Validators:    validators,
		Seal:          []byte{},
		CommittedSeal: [][]byte{},
	}

	extra, err := rlp.EncodeToBytes(ibftExtra)
	if err != nil {
		return err
	}

	var zeroBytes = make([]byte, 32)
	h.Extra = append(zeroBytes, extra...)

	return nil
}

func IBFTHeaderExtraRLPHash(_w io.Writer, obj *Header, extra *IBFTExtra) error {
	// this function replaces extra so we need to make a copy
	h := CopyHeader(obj) // Remove later

	putIBFTExtraValidators(h, extra.Validators)

	w := rlp.NewEncoderBuffer(_w)
	_tmp0 := w.List()
	w.WriteBytes(h.ParentHash[:])
	w.WriteBytes(h.UncleHash[:])
	w.WriteBytes(h.Coinbase[:])
	w.WriteBytes(h.Root[:])
	w.WriteBytes(h.TxHash[:])
	w.WriteBytes(h.ReceiptHash[:])
	w.WriteBytes(h.Bloom[:])
	if h.Difficulty == nil {
		w.Write(rlp.EmptyString)
	} else {
		if h.Difficulty.Sign() == -1 {
			return rlp.ErrNegativeBigInt
		}
		w.WriteBigInt(h.Difficulty)
	}
	if h.Number == nil {
		w.Write(rlp.EmptyString)
	} else {
		if h.Number.Sign() == -1 {
			return rlp.ErrNegativeBigInt
		}
		w.WriteBigInt(h.Number)
	}
	w.WriteUint64(h.GasLimit)
	w.WriteUint64(h.GasUsed)
	w.WriteUint64(h.Time)
	w.WriteBytes(h.Extra)
	w.ListEnd(_tmp0)
	return w.Flush()
}

func IBFTHeaderHashRLP(_w io.Writer, obj *Header) error {
	// genesis will not check ibft mix hash
	if obj.Number.Sign() > 0 && obj.MixDigest != IBFTMixHash {
		return ErrIBFTInvalidMixHash
	}

	// when hashing the block for signing we have to remove from
	// the extra field the seal and committed seal items
	extra, err := GetIbftExtra(obj.Extra)
	if err != nil {
		return err
	}

	return IBFTHeaderExtraRLPHash(_w, obj, extra)
}
