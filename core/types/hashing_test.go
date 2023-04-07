// Copyright 2021 The go-ethereum Authors
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

package types_test

import (
	"bytes"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

func TestDeriveSha(t *testing.T) {
	txs, err := genTxs(0)
	if err != nil {
		t.Fatal(err)
	}
	for len(txs) < 1000 {
		exp := types.DeriveSha(txs, new(trie.Trie))
		got := types.DeriveSha(txs, trie.NewStackTrie(nil))
		if !bytes.Equal(got[:], exp[:]) {
			t.Fatalf("%d txs: got %x exp %x", len(txs), got, exp)
		}
		newTxs, err := genTxs(uint64(len(txs) + 1))
		if err != nil {
			t.Fatal(err)
		}
		txs = append(txs, newTxs...)
	}
}

// TestEIP2718DeriveSha tests that the input to the DeriveSha function is correct.
func TestEIP2718DeriveSha(t *testing.T) {
	for _, tc := range []struct {
		rlpData string
		exp     string
	}{
		{
			rlpData: "0xb8a701f8a486796f6c6f763380843b9aca008262d4948a8eafb1cf62bfbeb1741769dae1a9dd479961928080f838f7940000000000000000000000000000000000001337e1a0000000000000000000000000000000000000000000000000000000000000000080a0775101f92dcca278a56bfe4d613428624a1ebfc3cd9e0bcc1de80c41455b9021a06c9deac205afe7b124907d4ba54a9f46161498bd3990b90d175aac12c9a40ee9",
			exp:     "01 01f8a486796f6c6f763380843b9aca008262d4948a8eafb1cf62bfbeb1741769dae1a9dd479961928080f838f7940000000000000000000000000000000000001337e1a0000000000000000000000000000000000000000000000000000000000000000080a0775101f92dcca278a56bfe4d613428624a1ebfc3cd9e0bcc1de80c41455b9021a06c9deac205afe7b124907d4ba54a9f46161498bd3990b90d175aac12c9a40ee9\n80 01f8a486796f6c6f763380843b9aca008262d4948a8eafb1cf62bfbeb1741769dae1a9dd479961928080f838f7940000000000000000000000000000000000001337e1a0000000000000000000000000000000000000000000000000000000000000000080a0775101f92dcca278a56bfe4d613428624a1ebfc3cd9e0bcc1de80c41455b9021a06c9deac205afe7b124907d4ba54a9f46161498bd3990b90d175aac12c9a40ee9\n",
		},
	} {
		d := &hashToHumanReadable{}
		var t1, t2 types.Transaction
		rlp.DecodeBytes(common.FromHex(tc.rlpData), &t1)
		rlp.DecodeBytes(common.FromHex(tc.rlpData), &t2)
		txs := types.Transactions{&t1, &t2}
		types.DeriveSha(txs, d)
		if tc.exp != string(d.data) {
			t.Fatalf("Want\n%v\nhave:\n%v", tc.exp, string(d.data))
		}
	}
}

func BenchmarkDeriveSha200(b *testing.B) {
	txs, err := genTxs(200)
	if err != nil {
		b.Fatal(err)
	}
	var exp common.Hash
	var got common.Hash
	b.Run("std_trie", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			exp = types.DeriveSha(txs, new(trie.Trie))
		}
	})

	b.Run("stack_trie", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			got = types.DeriveSha(txs, trie.NewStackTrie(nil))
		}
	})
	if got != exp {
		b.Errorf("got %x exp %x", got, exp)
	}
}

func TestFuzzDeriveSha(t *testing.T) {
	// increase this for longer runs -- it's set to quite low for travis
	rndSeed := mrand.Int()
	for i := 0; i < 10; i++ {
		seed := rndSeed + i
		exp := types.DeriveSha(newDummy(i), new(trie.Trie))
		got := types.DeriveSha(newDummy(i), trie.NewStackTrie(nil))
		if !bytes.Equal(got[:], exp[:]) {
			printList(newDummy(seed))
			t.Fatalf("seed %d: got %x exp %x", seed, got, exp)
		}
	}
}

// TestDerivableList contains testcases found via fuzzing
func TestDerivableList(t *testing.T) {
	type tcase []string
	tcs := []tcase{
		{
			"0xc041",
		},
		{
			"0xf04cf757812428b0763112efb33b6f4fad7deb445e",
			"0xf04cf757812428b0763112efb33b6f4fad7deb445e",
		},
		{
			"0xca410605310cdc3bb8d4977ae4f0143df54a724ed873457e2272f39d66e0460e971d9d",
			"0x6cd850eca0a7ac46bb1748d7b9cb88aa3bd21c57d852c28198ad8fa422c4595032e88a4494b4778b36b944fe47a52b8c5cd312910139dfcb4147ab8e972cc456bcb063f25dd78f54c4d34679e03142c42c662af52947d45bdb6e555751334ace76a5080ab5a0256a1d259855dfc5c0b8023b25befbb13fd3684f9f755cbd3d63544c78ee2001452dd54633a7593ade0b183891a0a4e9c7844e1254005fbe592b1b89149a502c24b6e1dca44c158aebedf01beae9c30cabe16a",
			"0x14abd5c47c0be87b0454596baad2",
			"0xca410605310cdc3bb8d4977ae4f0143df54a724ed873457e2272f39d66e0460e971d9d",
		},
	}
	for i, tc := range tcs[1:] {
		exp := types.DeriveSha(flatList(tc), new(trie.Trie))
		got := types.DeriveSha(flatList(tc), trie.NewStackTrie(nil))
		if !bytes.Equal(got[:], exp[:]) {
			t.Fatalf("case %d: got %x exp %x", i, got, exp)
		}
	}
}

func genTxs(num uint64) (types.Transactions, error) {
	key, err := crypto.HexToECDSA("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	if err != nil {
		return nil, err
	}
	var addr = crypto.PubkeyToAddress(key.PublicKey)
	newTx := func(i uint64) (*types.Transaction, error) {
		signer := types.NewEIP155Signer(big.NewInt(18))
		utx := types.NewTransaction(i, addr, new(big.Int), 0, new(big.Int).SetUint64(10000000), nil)
		tx, err := types.SignTx(utx, signer, key)
		return tx, err
	}
	var txs types.Transactions
	for i := uint64(0); i < num; i++ {
		tx, err := newTx(i)
		if err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}
	return txs, nil
}

type dummyDerivableList struct {
	len  int
	seed int
}

func newDummy(seed int) *dummyDerivableList {
	d := &dummyDerivableList{}
	src := mrand.NewSource(int64(seed))
	// don't use lists longer than 4K items
	d.len = int(src.Int63() & 0x0FFF)
	d.seed = seed
	return d
}

func (d *dummyDerivableList) Len() int {
	return d.len
}

func (d *dummyDerivableList) EncodeIndex(i int, w *bytes.Buffer) {
	src := mrand.NewSource(int64(d.seed + i))
	// max item size 256, at least 1 byte per item
	size := 1 + src.Int63()&0x00FF
	io.CopyN(w, mrand.New(src), size)
}

func printList(l types.DerivableList) {
	fmt.Printf("list length: %d\n", l.Len())
	fmt.Printf("{\n")
	for i := 0; i < l.Len(); i++ {
		var buf bytes.Buffer
		l.EncodeIndex(i, &buf)
		fmt.Printf("\"0x%x\",\n", buf.Bytes())
	}
	fmt.Printf("},\n")
}

type flatList []string

func (f flatList) Len() int {
	return len(f)
}
func (f flatList) EncodeIndex(i int, w *bytes.Buffer) {
	w.Write(hexutil.MustDecode(f[i]))
}

type hashToHumanReadable struct {
	data []byte
}

func (d *hashToHumanReadable) Reset() {
	d.data = make([]byte, 0)
}

func (d *hashToHumanReadable) Update(i []byte, i2 []byte) {
	l := fmt.Sprintf("%x %x\n", i, i2)
	d.data = append(d.data, []byte(l)...)
}

func (d *hashToHumanReadable) Hash() common.Hash {
	return common.Hash{}
}

func TestHeader_Hasher(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    *types.Header
		expHash common.Hash
	}{
		{
			name: "clique genesis header",
			data: &types.Header{
				ParentHash:  common.Hash{},
				UncleHash:   common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
				Coinbase:    common.Address{},
				Root:        common.HexToHash("0x804a07455284a0617ca98be637aa753ecf3b8fa742dd5dff2089c709454586c3"),
				TxHash:      common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
				ReceiptHash: common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
				Bloom:       types.BytesToBloom(common.Hex2Bytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
				Difficulty:  big.NewInt(1),
				Number:      big.NewInt(0),
				GasLimit:    0x47b760,
				GasUsed:     0,
				Time:        0x58ee40ba,
				Extra:       common.Hex2Bytes("52657370656374206d7920617574686f7269746168207e452e436172746d616e42eb768f2244c8811c63729a21a3569731535f067ffc57839b00206d1ad20c69a1981b489f772031b279182d99e65703f0076e4812653aab85fca0f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
				MixDigest:   common.Hash{},
				Nonce:       types.BlockNonce{},
			},
			expHash: common.HexToHash("0x41216dd5455205ce4182dfff13369a53fda71aa8b81a52c0383b4c8de36b7f3c"),
		},
		{
			name: "clique chain header",
			data: &types.Header{
				ParentHash:  common.HexToHash("0xa1d9eda6cbed736ccd96e6c9ac497f5f668141765d819b6e4054001d67134239"),
				UncleHash:   common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
				Coinbase:    common.HexToAddress("0x70f657164e5b75689b64b7fd1fa275f334f28e18"),
				Root:        common.HexToHash("0xbad93e9bda0b01f91abff7e29ae2bf215a265bf04b86f3d04b187ad3c920b4ef"),
				TxHash:      common.HexToHash("0x42a8532a659ba9ddffa9308995c93b872fa18d4782318b176ae4502c158faa8c"),
				ReceiptHash: common.HexToHash("0x32732e389ad883eacfe7d270492a544181cf7a015daca3de9368288a66b5e599"),
				Bloom:       types.BytesToBloom(common.Hex2Bytes("09750269321014196e08b0528120948373cc4a199e198f58783a60ec04926214f3291d5050051964a7603679141a65824a8bc32116ae3fa47e3c2a393d2e20a3a6609c30e14520e2856fce29a1b460a8fab9c0008bf63a37e00464278e17c0072724d13ecec3b59d96d35ae40784b9dd990083edc9f944e01770481cb8da441ad0c329a59c15b24a78ed5608ac00302e343c34957c4c768b3d8e05f98c49d8f487d984445c1ea309223663e7065e442c34ae20e3ce184104133c6231d612c0ec210414969017eb1611947ca912b93071a145cd64c5ae0b9d0f1211324021e77376f6d5435f57041a4da51a9227a51ca9cdc4742f502d4fdc22865dd39ae22e02")),
				Difficulty:  big.NewInt(0x2),
				Number:      big.NewInt(0x19d9ef3),
				GasLimit:    0x8583b00,
				GasUsed:     0xd23185,
				Time:        0x642e7bdf,
				Extra:       common.Hex2Bytes("00000000000000000000000000000000000000000000000000000000000000000291d5050051964a7603679141a65824a8bc32116ae3fa47e3c2a393d2e20a3a6609c30e14520e2856fce29a1b460a8fab9c0008bf63a37e00464278e17c0072724d13ecec3b59d96d35ae40784b9dd990083edc9f944e01770481cb8da441ad0c329a59c15b24a78ed5608ac00302e343c34957c4c768b3d8e05f98c49d8f487d984445c1ea309223663e7065e442c34ae20e3ce184104133c6231d612c0ec210414969017eb1611947ca912b93071a145cd64c5ae0b9d0f1211324021e77376f6d5435f57041a4da51a9227a51ca9cdc4742f502d4fdc22865dd39ae22e02"),
				MixDigest:   common.Hash{},
				Nonce:       types.BlockNonce{},
			},
			expHash: common.HexToHash("0x3b96d403aa885d8b83ee54fdebcb8a63e85ca1b9284ef1f8b1eccf777c0104ad"),
		},
		{
			name: "bsc genesis header",
			data: &types.Header{
				ParentHash:  common.Hash{},
				UncleHash:   common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
				Coinbase:    common.HexToAddress("0xfffffffffffffffffffffffffffffffffffffffe"),
				Root:        common.HexToHash("0x919fcc7ad870b53db0aa76eb588da06bacb6d230195100699fc928511003b422"),
				TxHash:      common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
				ReceiptHash: common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
				Bloom:       types.BytesToBloom(common.Hex2Bytes("0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
				Difficulty:  big.NewInt(1),
				Number:      big.NewInt(0),
				GasLimit:    0x2625a00,
				GasUsed:     0,
				Time:        0x5e9da7ce,
				Extra:       common.Hex2Bytes("00000000000000000000000000000000000000000000000000000000000000002a7cdd959bfe8d9487b2a43b33565295a698f7e26488aa4d1955ee33403f8ccb1d4de5fb97c7ade29ef9f4360c606c7ab4db26b016007d3ad0ab86a0ee01c3b1283aa067c58eab4709f85e99d46de5fe685b1ded8013785d6623cc18d214320b6bb6475978f3adfc719c99674c072166708589033e2d9afec2be4ec20253b8642161bc3f444f53679c1f3d472f7be8361c80a4c1e7e9aaf001d0877f1cfde218ce2fd7544e0b2cc94692d4a704debef7bcb61328b8f7166496996a7da21cf1f1b04d9b3e26a3d0772d4c407bbe49438ed859fe965b140dcf1aab71a96bbad7cf34b5fa511d8e963dbba288b1960e75d64430b3230294d12c6ab2aac5c2cd68e80b16b581ea0a6e3c511bbd10f4519ece37dc24887e11b55d7ae2f5b9e386cd1b50a4550696d957cb4900f03a82012708dafc9e1b880fd083b32182b869be8e0922b81f8e175ffde54d797fe11eb03f9e3bf75f1d68bf0b8b6fb4e317a0f9d6f03eaf8ce6675bc60d8c4d90829ce8f72d0163c1d5cf348a862d55063035e7a025f4da968de7e4d7e4004197917f4070f1d6caa02bbebaebb5d7e581e4b66559e635f805ff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
				MixDigest:   common.Hash{},
				Nonce:       types.BlockNonce{},
			},
			expHash: common.HexToHash("0x0d21840abff46b96c84b2ac9e10e4f5cdaeb5693cb665db62a2f3b02d2d57b5b"),
		},
		{
			name: "bsc chain header",
			data: &types.Header{
				ParentHash:  common.HexToHash("0xa1d9eda6cbed736ccd96e6c9ac497f5f668141765d819b6e4054001d67134239"),
				UncleHash:   common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
				Coinbase:    common.HexToAddress("0x70f657164e5b75689b64b7fd1fa275f334f28e18"),
				Root:        common.HexToHash("0xbad93e9bda0b01f91abff7e29ae2bf215a265bf04b86f3d04b187ad3c920b4ef"),
				TxHash:      common.HexToHash("0x42a8532a659ba9ddffa9308995c93b872fa18d4782318b176ae4502c158faa8c"),
				ReceiptHash: common.HexToHash("0x32732e389ad883eacfe7d270492a544181cf7a015daca3de9368288a66b5e599"),
				Bloom:       types.BytesToBloom(common.Hex2Bytes("09750269321014196e08b0528120948373cc4a199e198f58783a60ec04926214f3291d5050051964a7603679141a65824a8bc32116ae3fa47e3c2a393d2e20a3a6609c30e14520e2856fce29a1b460a8fab9c0008bf63a37e00464278e17c0072724d13ecec3b59d96d35ae40784b9dd990083edc9f944e01770481cb8da441ad0c329a59c15b24a78ed5608ac00302e343c34957c4c768b3d8e05f98c49d8f487d984445c1ea309223663e7065e442c34ae20e3ce184104133c6231d612c0ec210414969017eb1611947ca912b93071a145cd64c5ae0b9d0f1211324021e77376f6d5435f57041a4da51a9227a51ca9cdc4742f502d4fdc22865dd39ae22e02")),
				Difficulty:  big.NewInt(2),
				Number:      big.NewInt(0x19d9ef3),
				GasLimit:    0x8583b00,
				GasUsed:     0xd23185,
				Time:        0x642e7bdf,
				Extra:       common.Hex2Bytes("d883010115846765746888676f312e31392e37856c696e7578000000f98d107232553b5676d8dcdd9f73b2689f63fe37a709ce1f5d71d7166d58a088ad4530835d45872be4789f15e14cd3bf0bb7d1d5a029e3f0b15095c5e91564d35bb949c100"),
				MixDigest:   common.Hash{},
				Nonce:       types.BlockNonce{},
			},
			expHash: common.HexToHash("0x21e7c0e3322a45292bae14f8e4ce5bea537908766397d43fabb32e03970a249e"),
		},
		{
			name: "ibft genesis header",
			data: &types.Header{
				ParentHash:  common.Hash{},
				UncleHash:   common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
				Coinbase:    common.Address{},
				Root:        common.HexToHash("0x804a07455284a0617ca98be637aa753ecf3b8fa742dd5dff2089c709454586c3"),
				TxHash:      common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
				ReceiptHash: common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
				Bloom:       types.BytesToBloom(common.Hex2Bytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
				Difficulty:  big.NewInt(1),
				Number:      big.NewInt(0),
				GasLimit:    0x1c9c380,
				GasUsed:     0x70000,
				Time:        0,
				Extra:       common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000f858f8549474c8ab07501014c3c58f6529d9bd966a02548b44945f66fe5430613154a9b82e382d400fb4475f8ab7949c5d3e328515636e0564b2ba3becac32f972657f948a5207bdd70cedde5ca6124fca0de772acf3ccfc80c0"),
				MixDigest:   common.Hash{},
				Nonce:       types.BlockNonce{},
			},
			expHash: common.HexToHash("0x75d36607ff0e081d53cf9999d3abd2050f1865e443fe2197236e0ab76aad4443"),
		},
		{
			name: "ibft chain header",
			data: &types.Header{
				ParentHash:  common.HexToHash("0x98295ad58f5ccab9d79efc55d15ecbf1f06dfc30f0cfd0125a28d5d7ee2270e6"),
				UncleHash:   common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
				Coinbase:    common.HexToAddress("0x92bB5D1A856E54157232b43Fe1C9C7e89eE36ABE"),
				Root:        common.HexToHash("0xf096fcfe18f104b080b40aea0d925b43c77265cc9af978183ed17933d7042c66"),
				TxHash:      common.HexToHash("0x6e6cadced99ed9ca7e587ce6ecb164913f99d6faebe12add39dc8bfc5a67110c"),
				ReceiptHash: common.HexToHash("0xcdb9f10980cf5502a35c0a26433f59b4883a3d7022d627c9e575348648ea386f"),
				Bloom:       types.BytesToBloom(common.Hex2Bytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
				Difficulty:  big.NewInt(10290979),
				Number:      big.NewInt(10290979),
				GasLimit:    30000000,
				GasUsed:     568092,
				Time:        1680769939,
				Extra:       common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000f90164f85494d668bba507d0438ff22ee8ceb341323765669a24947175996ff9dcb8fbb83b68e2b88f1a029014555b9492bb5d1a856e54157232b43fe1c9c7e89ee36abe9464f2686e3ac7492c3b3f662d32ecb8b6bfa548feb8416f304ad7974ff598142d561335bef9d2cf081260c432127ef80e910c57269ef61d24f439e7aac71869b8b014d11ae0b4fec5bb41ef5876aa51f751d7c02d2ae600f8c9b841837ab7e53839529eafb8f6fc96886bd43050bd130b2036b07634489b47cab0193b133543941d1a3e6483f20c771573da3450f8f746c3afb2396d577e51655fe801b8419a63a2e97f544c7e4633f2c1e858ced5338aebd4b105a31ba39dfb710c6df0520ce5d23e4c87c69c3b5dbc32540a7cd954835758ed5897f498ddca80f58d1fa301b841fbd43d90202965e7f0a9de6018261661925d611810c6d0be606dc274476f5d00177175159cc57f184b8cc965d074516b46d3a8a9a1e962305229ef8f140c7c0501"),
				MixDigest:   types.IBFTMixHash,
				Nonce:       types.BlockNonce{},
			},
			expHash: common.HexToHash("0x9b84a2811d55ec8fe72d223b81554a109c3591aa9e4330bc80078921009f0b94"),
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			h := tc.data.Hash()
			if h != tc.expHash {
				t.Errorf("header hash mismatch, want %s, got %s", tc.expHash, h)
			}
		})
	}
}
