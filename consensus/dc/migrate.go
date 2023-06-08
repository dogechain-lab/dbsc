package dc

import (
	"math/big"

	"github.com/dogechain-lab/dogechain/types"

	dbscCommon "github.com/ethereum/go-ethereum/common"
	dbscTypes "github.com/ethereum/go-ethereum/core/types"
)

func DcHashToDbscHash(hash types.Hash) dbscCommon.Hash {
	return dbscCommon.BytesToHash(hash.Bytes())
}

func DcHashsToDbscHashs(hashs []types.Hash) []dbscCommon.Hash {
	dbscHashs := make([]dbscCommon.Hash, len(hashs))

	for i, hash := range hashs {
		dbscHashs[i] = DcHashToDbscHash(hash)
	}

	return dbscHashs
}

func DbscHashToDcHash(hash dbscCommon.Hash) types.Hash {
	return types.BytesToHash(hash.Bytes())
}

func DcAddressToDbscAddress(address types.Address) dbscCommon.Address {
	return dbscCommon.BytesToAddress(address.Bytes())
}

func DbscAddressToDcAddress(address dbscCommon.Address) types.Address {
	return types.BytesToAddress(address.Bytes())
}

func DcTxToDbscTx(tx *types.Transaction) *dbscTypes.Transaction {
	var toAddress *dbscCommon.Address = nil

	if tx.To != nil {
		add := DcAddressToDbscAddress(*tx.To)
		toAddress = &add
	}

	return dbscTypes.NewTx(&dbscTypes.LegacyTx{
		Nonce:    tx.Nonce,
		GasPrice: tx.GasPrice,
		Gas:      tx.Gas,
		To:       toAddress,
		Value:    tx.Value,
		Data:     tx.Input,
		V:        tx.V,
		R:        tx.R,
		S:        tx.S,
	})
}

func DbscTxToDcTx(signer dbscTypes.Signer, tx *dbscTypes.Transaction) (*types.Transaction, error) {
	var toAddress *types.Address = nil

	if tx.To() != nil {
		add := types.Address(*tx.To())
		toAddress = &add
	}

	v, r, s := tx.RawSignatureValues()
	send, err := dbscTypes.Sender(signer, tx)

	if err != nil {
		return nil, err
	}

	return &types.Transaction{
		Nonce:        tx.Nonce(),
		GasPrice:     tx.GasPrice(),
		Gas:          tx.Gas(),
		To:           toAddress,
		Value:        tx.Value(),
		Input:        tx.Data(),
		V:            v,
		R:            r,
		S:            s,
		From:         types.Address(send),
		ReceivedTime: tx.Time(),
	}, nil
}

func DcTxsToDbscTxs(txs []*types.Transaction) []*dbscTypes.Transaction {
	result := make([]*dbscTypes.Transaction, 0, len(txs))

	for _, tx := range txs {
		result = append(result, DcTxToDbscTx(tx))
	}

	return result
}

func DcBloomToDbscBloom(bloom types.Bloom) dbscTypes.Bloom {
	return dbscTypes.BytesToBloom(bloom[:])
}

func DbscBloomToDcBloom(bloom dbscTypes.Bloom) types.Bloom {
	var dcBloom types.Bloom
	copy(dcBloom[:], bloom.Bytes()[:types.BloomByteLength])

	return dcBloom
}

func DbscHeaderToDcHeader(header *dbscTypes.Header) *types.Header {
	dcHeader := &types.Header{
		ParentHash:   DbscHashToDcHash(header.ParentHash),
		Sha3Uncles:   DbscHashToDcHash(header.UncleHash),
		Miner:        DbscAddressToDcAddress(header.Coinbase),
		StateRoot:    DbscHashToDcHash(header.Root),
		TxRoot:       DbscHashToDcHash(header.TxHash),
		ReceiptsRoot: DbscHashToDcHash(header.ReceiptHash),
		LogsBloom:    DbscBloomToDcBloom(header.Bloom),
		Difficulty:   header.Difficulty.Uint64(),
		Number:       header.Number.Uint64(),
		GasLimit:     header.GasLimit,
		GasUsed:      header.GasUsed,
		Timestamp:    header.Time,
		ExtraData:    header.Extra,
		MixHash:      DbscHashToDcHash(header.MixDigest),
	}
	dcHeader.SetNonce(header.Nonce.Uint64())

	return dcHeader.ComputeHash()
}

func DcHeaderToDbscHeader(header *types.Header) *dbscTypes.Header {
	return &dbscTypes.Header{
		ParentHash:  DcHashToDbscHash(header.ParentHash),
		UncleHash:   DcHashToDbscHash(header.Sha3Uncles),
		Coinbase:    DcAddressToDbscAddress(header.Miner),
		Root:        DcHashToDbscHash(header.StateRoot),
		TxHash:      DcHashToDbscHash(header.TxRoot),
		ReceiptHash: DcHashToDbscHash(header.ReceiptsRoot),
		Bloom:       dbscTypes.BytesToBloom(header.LogsBloom[:]),
		Difficulty:  new(big.Int).SetUint64(header.Difficulty),
		Number:      new(big.Int).SetUint64(header.Number),
		GasLimit:    header.GasLimit,
		GasUsed:     header.GasUsed,
		Time:        header.Timestamp,
		Extra:       header.ExtraData,
		MixDigest:   DcHashToDbscHash(header.MixHash),
		Nonce:       dbscTypes.BlockNonce(header.Nonce),
	}
}

func DcLogToDbscLog(log *types.Log) *dbscTypes.Log {
	return &dbscTypes.Log{
		Address: DcAddressToDbscAddress(log.Address),
		Topics:  DcHashsToDbscHashs(log.Topics),
		Data:    log.Data,
	}
}

func DcLogsToDbscLogs(logs []*types.Log) []*dbscTypes.Log {
	result := make([]*dbscTypes.Log, 0, len(logs))

	for _, log := range logs {
		result = append(result, DcLogToDbscLog(log))
	}

	return result
}

func DcReceiptToDbscReceipt(receipt *types.Receipt) *dbscTypes.Receipt {
	return &dbscTypes.Receipt{
		Type:              dbscTypes.LegacyTxType,
		PostState:         receipt.Root[:],
		Status:            (uint64)(*receipt.Status),
		CumulativeGasUsed: receipt.CumulativeGasUsed,
		Bloom:             dbscTypes.BytesToBloom(receipt.LogsBloom[:]),
		Logs:              DcLogsToDbscLogs(receipt.Logs),
		TxHash:            DcHashToDbscHash(receipt.TxHash),
		ContractAddress:   DcAddressToDbscAddress(*receipt.ContractAddress),
		GasUsed:           receipt.GasUsed,
	}
}

func DcReceiptsToDbscReceipts(receipts []*types.Receipt) []*dbscTypes.Receipt {
	result := make([]*dbscTypes.Receipt, 0, len(receipts))

	for _, receipt := range receipts {
		result = append(result, DcReceiptToDbscReceipt(receipt))
	}

	return result
}
