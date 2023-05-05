package vm

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

var (
	ibftOpCreate  = ibftOpCreateImpl(CREATE)
	ibftOpCreate2 = ibftOpCreateImpl(CREATE2)
)

func ibftGetMemory(scope *ScopeContext, offset, size *uint256.Int) ([]byte, error) {
	// Short-circuit
	if size.IsZero() {
		return nil, nil
	}
	// Calculate memory consumption once again, and "swallow" the error
	memSize, overflow := ibftCalcMemSize64(offset, size)
	if overflow {
		return nil, ErrGasUintOverflow
	}
	// Memory is expanded in words of 32 bytes. Gas
	// is also calculated in words.
	memSize = toWordSize(memSize)
	memSize *= 32
	// Extend memory gas cost
	cost, err := ibftMemoryGasCost(scope.Memory, memSize)
	if err != nil {
		return nil, err
	}
	// Consume memory gas
	if !scope.Contract.UseGas(cost) {
		return nil, ErrOutOfGas
	}
	// Resize the memory
	if memSize > 0 {
		scope.Memory.Resize(memSize)
	}

	// Contract code
	var input = scope.Memory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))

	return input, nil
}

// ibftBuildCreateContract charges memory gas step by step
func ibftBuildCreateContract(op OpCode, interpreter *EVMInterpreter, scope *ScopeContext) (ret *ibftInnerCreateContract, shouldContinue bool, err error) {
	var (
		value           = scope.Stack.pop()
		offset, size    = scope.Stack.pop(), scope.Stack.pop()
		salt            uint256.Int
		currentContract = scope.Contract
		gas             = scope.Contract.Gas
	)
	if op == CREATE2 {
		salt = scope.Stack.pop()
	}

	// Get contract code to memory
	input, getMemoryErr := ibftGetMemory(scope, &offset, &size)
	if getMemoryErr != nil {
		log.Warn("get code to memory failed", "err", getMemoryErr)
		// for outside break
		return nil, true, getMemoryErr
	}

	// Assure transfer value
	//TODO: use uint256.Int instead of converting with toBig()
	var bigVal = big0
	if value.Sign() > 0 { // need to transfer value
		bigVal = value.ToBig()
		// Checks whether balance is enough to pay value.
		v := interpreter.evm.StateDB.GetBalance(currentContract.Caller())
		if v.Cmp(bigVal) < 0 {
			return nil, false, ErrInsufficientBalance
		}
	}

	// Consume sha3 gas cost
	if op == CREATE2 {
		words := toWordSize(size.Uint64())
		if !scope.Contract.UseGas(words * params.Keccak256WordGas) {
			return nil, true, ErrOutOfGas
		}
	}

	// CREATE2 uses by default EIP150
	if interpreter.evm.chainRules.IsEIP150 || op == CREATE2 {
		gas -= gas / 64
	}
	if !scope.Contract.UseGas(gas) {
		return nil, true, ErrOutOfGas
	}

	// reuse size int for stackvalue
	var addr common.Address

	if op == CREATE2 {
		// New contract address
		codeAndHash := &codeAndHash{code: input}
		addr = crypto.CreateAddress2(currentContract.Address(), salt.Bytes32(), codeAndHash.Hash().Bytes())
	} else {
		addr = crypto.CreateAddress(currentContract.Address(),
			interpreter.evm.StateDB.GetNonce(scope.Contract.Address()),
		)
	}

	return &ibftInnerCreateContract{
		Code:        input,
		Type:        op,
		CodeAddress: addr,
		Value:       bigVal,
		Gas:         gas,
	}, true, nil
}

type ibftInnerCreateContract struct {
	Code        []byte
	Type        OpCode
	CodeAddress common.Address
	Value       *big.Int
	Gas         uint64
}

func ibftOpCreateImpl(op OpCode) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		if interpreter.readOnly {
			return nil, ErrWriteProtection
		}

		ret, shouldContinue, buildErr := ibftBuildCreateContract(op, interpreter, scope)
		if !shouldContinue { // could not go on here
			var emptyVal uint256.Int
			scope.Stack.push(&emptyVal)
			return nil, buildErr
		}
		if ret == nil {
			return nil, buildErr
		}

		// Create contract
		res, addr, returnGas, suberr := interpreter.evm.CreateWithOpCode(scope.Contract, &codeAndHash{code: ret.Code}, ret.Gas, ret.Value, ret.CodeAddress, op)

		// No matter what happen, we need to set stack
		var stackvalue uint256.Int
		if op == CREATE && interpreter.evm.chainRules.IsHomestead && errors.Is(suberr, ErrOutOfGas) {
			stackvalue.Clear()
		} else if suberr != nil && !errors.Is(suberr, ErrCodeStoreOutOfGas) {
			stackvalue.Clear()
		} else {
			// We might get code store out of gas, but still return contract address here.
			stackvalue.SetBytes(addr.Bytes())
		}
		scope.Stack.push(&stackvalue)
		// Refund gas
		scope.Contract.Gas += returnGas

		// Handle revert error
		if suberr == ErrExecutionReverted {
			interpreter.returnData = res // set REVERT data to return data buffer
			return res, nil
		}
		interpreter.returnData = nil // clear dirty return data buffer
		return nil, nil
	}
}

func ibftOpMload(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// Pop element to consume
	v := scope.Stack.pop()
	offset := int64(v.Uint64())
	// check memory store
	value := scope.Memory.GetPtr(offset, 32)
	// Memory should not be nil here, otherwise we will drop the instruction.
	if value == nil {
		return nil, nil
	}
	// Push back to stack.
	vv := v.SetBytes(value)
	scope.Stack.push(vv)

	return nil, nil
}

func ibftOpMstore(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// pop value of the stack
	mStart, val := scope.Stack.pop(), scope.Stack.pop()
	scope.Memory.Set32(mStart.Uint64(), &val)
	return nil, nil
}
