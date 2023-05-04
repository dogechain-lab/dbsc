package vm

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

var (
	ibftOpCreate  = ibftOpCreateImpl(CREATE)
	ibftOpCreate2 = ibftOpCreateImpl(CREATE2)
)

func ibftOpCreateImpl(op OpCode) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		if interpreter.readOnly {
			return nil, ErrWriteProtection
		}

		var (
			value           = scope.Stack.pop()
			offset, size    = scope.Stack.pop(), scope.Stack.pop()
			salt            uint256.Int
			input           = scope.Memory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))
			currentContract = scope.Contract
			gas             = scope.Contract.Gas
		)
		if op == CREATE2 {
			salt = scope.Stack.pop()
		}

		if interpreter.evm.chainRules.IsEIP150 || op == CREATE2 {
			gas -= gas / 64
		}
		// reuse size int for stackvalue
		stackvalue := size

		scope.Contract.UseGas(gas)
		//TODO: use uint256.Int instead of converting with toBig()
		var bigVal = big0
		if value.Sign() > 0 { // need to transfer value
			bigVal = value.ToBig()
			// Checks whether balance is enough to pay value.
			v := interpreter.evm.StateDB.GetBalance(currentContract.Caller())
			if v.Cmp(bigVal) < 0 {
				return nil, ErrInsufficientBalance
			}
		}

		var (
			res       []byte
			addr      common.Address
			returnGas uint64
			suberr    error
		)

		if op == CREATE2 {
			// New contract address
			codeAndHash := &codeAndHash{code: input}
			addr = crypto.CreateAddress2(currentContract.Address(), salt.Bytes32(), codeAndHash.Hash().Bytes())
			res, addr, returnGas, suberr = interpreter.evm.CreateWithOpCode(scope.Contract, codeAndHash, gas, bigVal, addr, CREATE2)
			// Push item on the stack based on the returned error.
			// IBFT use a strange Create2 opcode stack calling sequence, which is not
			// EVM compatible. So we need to return address even though it failed due
			// to not enough gas during running the construction.
			// But we'll make this unknown issue back to normal after the hard fork
			stackvalue.SetBytes(addr.Bytes())
		} else {
			addr = crypto.CreateAddress(currentContract.Address(),
				interpreter.evm.StateDB.GetNonce(scope.Contract.Address()),
			)
			res, addr, returnGas, suberr = interpreter.evm.CreateWithOpCode(scope.Contract, &codeAndHash{code: input}, gas, bigVal, addr, CREATE)
			// Push item on the stack based on the returned error. If the ruleset is
			// homestead we must check for CodeStoreOutOfGasError (homestead only
			// rule) and treat as an error, if the ruleset is frontier we must
			// ignore this error and pretend the operation was successful.
			if interpreter.evm.chainRules.IsHomestead && suberr == ErrCodeStoreOutOfGas {
				stackvalue.Clear()
			} else if suberr != nil && suberr != ErrCodeStoreOutOfGas {
				stackvalue.Clear()
			} else {
				stackvalue.SetBytes(addr.Bytes())
			}
		}

		scope.Stack.push(&stackvalue)
		scope.Contract.Gas += returnGas

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
