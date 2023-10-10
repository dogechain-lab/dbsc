package dc

import (
	"math/big"

	"github.com/dogechain-lab/dogechain/types"
	"github.com/ethereum/go-ethereum/log"

	dbscCommon "github.com/ethereum/go-ethereum/common"
	dbscConsensus "github.com/ethereum/go-ethereum/consensus"
	dbscTypes "github.com/ethereum/go-ethereum/core/types"
	dbscParams "github.com/ethereum/go-ethereum/params"
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

func TxnArgsToTx(arg *dbscConsensus.DcTxnArgs) *types.Transaction {
	from := DbscAddressToDcAddress(*arg.From)

	txn := &types.Transaction{
		From:     from,
		Gas:      uint64(*arg.Gas),
		GasPrice: arg.GasPrice.ToInt(),
		Value:    arg.Value.ToInt(),
		Input:    *arg.Input,
		Nonce:    uint64(*arg.Nonce),
	}

	txn.Hash()

	return txn
}

func DbscTxToDcTx(signer dbscTypes.Signer, tx *dbscTypes.Transaction) (*types.Transaction, error) {
	var toAddress *types.Address = nil

	if tx.To() != nil {
		add := types.Address(*tx.To())
		toAddress = &add
	}

	v, r, s := tx.RawSignatureValues()
	sender, err := dbscTypes.Sender(signer, tx)

	if err != nil {
		log.Debug("sender is nil", sender)
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
		From:         types.Address(sender),
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
	var contractAddress dbscCommon.Address
	if receipt.ContractAddress == nil {
		contractAddress = dbscCommon.Address{}
	} else {
		contractAddress = DcAddressToDbscAddress(*receipt.ContractAddress)
	}

	postState := []byte{}
	status := dbscTypes.ReceiptStatusFailed

	if receipt.Status != nil {
		switch *receipt.Status {
		case types.ReceiptSuccess:
			status = dbscTypes.ReceiptStatusSuccessful
		case types.ReceiptFailed:
			status = dbscTypes.ReceiptStatusFailed
		}
	} else {
		postState = receipt.Root.Bytes()
	}

	return &dbscTypes.Receipt{
		Type:              dbscTypes.LegacyTxType,
		PostState:         postState,
		Status:            status,
		CumulativeGasUsed: receipt.CumulativeGasUsed,
		Bloom:             dbscTypes.BytesToBloom(receipt.LogsBloom[:]),
		Logs:              DcLogsToDbscLogs(receipt.Logs),
		TxHash:            DcHashToDbscHash(receipt.TxHash),
		ContractAddress:   contractAddress,
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

func DbscBlockToDcBlock(cfg *dbscParams.ChainConfig, block *dbscTypes.Block) *types.Block {
	blk := &types.Block{
		Header:       DbscHeaderToDcHeader(block.Header()),
		Transactions: make([]*types.Transaction, 0, len(block.Transactions())),
		Uncles:       make([]*types.Header, 0, len(block.Uncles())),
	}

	signer := dbscTypes.MakeSigner(
		cfg,
		block.Number(),
	)

	// copy tx
	for _, tx := range block.Transactions() {
		dcTx, err := DbscTxToDcTx(signer, tx)
		if err != nil {
			panic(err)
		}
		blk.Transactions = append(blk.Transactions, dcTx)
	}

	// copy uncles
	for _, uncle := range block.Uncles() {
		blk.Uncles = append(blk.Uncles, DbscHeaderToDcHeader(uncle))
	}

	return blk
}

func DcBlockToDbscBlock(block *types.Block) *dbscTypes.Block {
	dbscUncles := make([]*dbscTypes.Header, 0, len(block.Uncles))

	for _, uncle := range block.Uncles {
		dbscUncles = append(dbscUncles, DcHeaderToDbscHeader(uncle))
	}

	blk := dbscTypes.NewBlockWithHeader(
		DcHeaderToDbscHeader(block.Header),
	).WithBody(
		DcTxsToDbscTxs(block.Transactions),
		dbscUncles,
	)

	return blk
}
