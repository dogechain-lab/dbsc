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
)

// IBFTExtra defines the structure of the extra field for I(stanbul)BFT
type IBFTExtra struct {
	Validators    []common.Address
	Seal          []byte
	CommittedSeal [][]byte
}

// getIbftExtra returns the istanbul extra data field from the passed in header
func getIbftExtra(h *Header) (*IBFTExtra, error) {
	// must longer than ibft extra prefix
	if len(h.Extra) < IBFTExtraVanity {
		return nil, ErrInvalidIBFTExtraLength
	}

	// must be ibft extra prefix
	if !bytes.Equal(h.Extra[:IBFTExtraVanity], IBFTExtraPrefix[:]) {
		return nil, ErrNotIBFTExtraPrefix
	}

	data := h.Extra[IBFTExtraVanity:]
	extra := &IBFTExtra{}

	if err := rlp.DecodeBytes(data, extra); err != nil {
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

func ibftHeaderHashRLP(_w io.Writer, obj *Header) error {
	if obj.MixDigest != IBFTMixHash {
		return ErrIBFTInvalidMixHash
	}

	// when hashing the block for signing we have to remove from
	// the extra field the seal and committed seal items
	extra, err := getIbftExtra(obj)
	if err != nil {
		return err
	}

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
