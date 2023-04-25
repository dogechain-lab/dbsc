// Copyright 2023 The go-ethereum Authors and BSC Authors and DBSC Authors
// This file is part of DBSC.
//
// DBSC is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// DBSC is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with DBSC. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/consensus/ibft"
	"github.com/ethereum/go-ethereum/core/dccontracts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"gopkg.in/urfave/cli.v1"
)

var (
	// Git SHA1 commit hash of the release (set via linker flags)
	gitCommit = ""
	gitDate   = ""

	app *cli.App

	// Flags needed by genesis-gen
	chainIDFlag = cli.Uint64Flag{
		Name:  "chain-id",
		Usage: "Chain ID of the genesis block",
		Value: 668,
	}
	epochSizeFlag = cli.Uint64Flag{
		Name:  "epoch-size",
		Usage: "The epoch size for the chain",
		Value: 7200,
	}
	gasLimitFlag = cli.Uint64Flag{
		Name:  "gas-limit",
		Usage: "The maximum amount of gas used by all transactions in a block",
		Value: 5242880, // 0x500000
	}
	gasUsedFlag = cli.Uint64Flag{
		Name:  "gas-used",
		Usage: "Gas used of the block",
		Value: 458752, // 0x70000
	}
	validatorFlags = cli.StringSliceFlag{
		Name:  "validator",
		Usage: "The validator address and public key, This flag can be used multiple times",
	}
	premineFlags = cli.StringSliceFlag{
		Name:  "premine",
		Usage: "The premine address and amount formatted as address:amount, This flag can be used multiple times",
	}
	validatorsetOwnerFlag = cli.StringFlag{
		Name:  "validatorset-owner",
		Usage: "The system ValidatorSet contract owner address",
	}
	bridgeOwnerFlag = cli.StringFlag{
		Name:  "bridge-owner",
		Usage: "The system bridge contract owner address",
	}
	bridgeSignersFlag = cli.StringSliceFlag{
		Name:  "bridge-signer",
		Usage: "The system bridge contract signer address. This flag can be used multiple times",
	}
	vaultOwnerFlag = cli.StringFlag{
		Name:  "vault-owner",
		Usage: "The system vault contract owner address",
	}
	outputFileFlag = cli.StringFlag{
		Name:  "output",
		Usage: "The output file to write the genesis.json to",
		Value: "genesis.json",
	}
)

func init() {
	app = flags.NewApp(gitCommit, gitDate, "Generate genesis block for DBSC")
	app.Flags = []cli.Flag{
		chainIDFlag,
		epochSizeFlag,
		gasLimitFlag,
		gasUsedFlag,
		validatorFlags,
		premineFlags,
		validatorsetOwnerFlag,
		bridgeOwnerFlag,
		bridgeSignersFlag,
		vaultOwnerFlag,
		outputFileFlag,
	}
	app.Action = utils.MigrateFlags(genesisGen)
	cli.CommandHelpTemplate = flags.OriginCommandHelpTemplate
}

func genesisGen(c *cli.Context) error {
	var (
		validators    = c.GlobalStringSlice(validatorFlags.Name)
		premines      = c.GlobalStringSlice(premineFlags.Name)
		bridgeSigners = c.GlobalStringSlice(bridgeSignersFlag.Name)
	)

	if len(validators) == 0 {
		return fmt.Errorf("no validators specified")
	}
	if len(premines) == 0 {
		log.Warn("no premine specified")
	}
	if !c.GlobalIsSet(validatorsetOwnerFlag.Name) {
		return fmt.Errorf("system ValidatorSet contract owner address is not specified")
	}

	bridgeOwner := common.Address{}
	if c.GlobalIsSet(bridgeOwnerFlag.Name) {
		bridgeOwner = common.HexToAddress(c.GlobalString(bridgeOwnerFlag.Name))
	} else {
		log.Warn("system bridge contract owner address is not specified")
	}

	vaultOwner := common.Address{}
	if c.GlobalIsSet(vaultOwnerFlag.Name) {
		vaultOwner = common.HexToAddress(c.GlobalString(vaultOwnerFlag.Name))
	} else {
		log.Warn("system vault contract owner address is not specified")
	}

	if len(bridgeSigners) == 0 {
		log.Warn("no bridge signers specified")
	}

	chainConfig := &params.ChainConfig{
		ChainID:             new(big.Int).SetUint64(c.GlobalUint64(chainIDFlag.Name)),
		HomesteadBlock:      big.NewInt(0),
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		IBFTBlock:           nil, // this is dogechain v1 network block, new network should not use this
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		PreportlandBlock:    big.NewInt(0),
		PortlandBlock:       big.NewInt(0),
		DetroitBlock:        big.NewInt(0),
		// TODO: Add hawaii hard fork
		// HawaiiBlock:      big.NewInt(0),
		IBFT: &params.IBFTConfig{
			EpochSize: c.GlobalUint64(epochSizeFlag.Name),
			Type:      params.IBFTPoS,
		},
	}

	genesis := &core.Genesis{
		Config:     chainConfig,
		Nonce:      0,
		Timestamp:  uint64(time.Now().Unix()),
		GasLimit:   c.GlobalUint64(gasLimitFlag.Name),
		GasUsed:    c.GlobalUint64(gasUsedFlag.Name),
		Difficulty: big.NewInt(1),
		ParentHash: common.Hash{},
		Mixhash:    common.Hash{},
		Coinbase:   common.Address{},
	}

	// GenesisAlloc
	genesis.Alloc = make(core.GenesisAlloc)

	validatorsAddress := make([]common.Address, 0, len(validators))
	for _, validator := range validators {
		validatorsAddress = append(validatorsAddress, common.HexToAddress(validator))
	}

	validatorsAlloc, err := predeployValidatorSet(
		common.HexToAddress(c.GlobalString(validatorsetOwnerFlag.Name)),
		validatorsAddress,
	)
	if err != nil {
		return err
	}

	bridgeSignersAddress := make([]common.Address, 0, len(bridgeSigners))
	for _, signer := range bridgeSigners {
		bridgeSignersAddress = append(bridgeSignersAddress, common.HexToAddress(signer))
	}

	genesis.Alloc[common.HexToAddress(dccontracts.DCBridgeContract)] = *(predeployBridgeSC(bridgeOwner, bridgeSignersAddress))
	genesis.Alloc[common.HexToAddress(dccontracts.DCValidatorSetContract)] = *validatorsAlloc
	genesis.Alloc[common.HexToAddress(dccontracts.DCVaultContract)] = *(predeployVaultSC(vaultOwner))

	for _, premine := range premines {
		var addr common.Address
		var val string

		if indx := strings.Index(premine, ":"); indx != -1 {
			// <addr>:<balance>
			addr, val = common.HexToAddress(premine[:indx]), premine[indx+1:]
		} else {
			log.Error(fmt.Sprintf("premine format error: %s", premine))
		}

		amount, err := ParseUint256orHex(&val)
		if err != nil {
			return fmt.Errorf("failed to parse amount %s: %w", val, err)
		}

		genesis.Alloc[addr] = core.GenesisAccount{
			Balance: amount,
		}
	}

	genesis.ExtraData = make([]byte, ibft.ExtraVanity)
	ibftExtra := &types.IBFTExtra{
		Validators:    validatorsAddress,
		Seal:          []byte{},
		CommittedSeal: [][]byte{},
	}

	extraData, err := rlp.EncodeToBytes(ibftExtra)
	if err != nil {
		return err
	}
	genesis.ExtraData = append(genesis.ExtraData, extraData...)

	// Write genesis to file
	data, err := json.MarshalIndent(genesis, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to generate genesis: %w", err)
	}

	//nolint:gosec
	if err := os.WriteFile(c.GlobalString(outputFileFlag.Name), data, 0644); err != nil {
		return fmt.Errorf("failed to write genesis: %w", err)
	}

	return nil
}

func main() {
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, log.StreamHandler(os.Stderr, log.TerminalFormat(true))))

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
