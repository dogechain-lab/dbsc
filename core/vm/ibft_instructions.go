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

var (
	ibftOpCall         = ibftOpCallImpl(CALL)
	ibftOpCallCode     = ibftOpCallImpl(CALLCODE)
	ibftOpDelegateCall = ibftOpCallImpl(DELEGATECALL)
	ibftOpStaticCall   = ibftOpCallImpl(STATICCALL)
)

func ibftExtendMemory(scope *ScopeContext, offset, size *uint256.Int) error {
	// Calculate memory consumption once again, and "swallow" the error
	memSize, overflow := ibftCalcMemSize64(offset, size)
	if overflow {
		return ErrGasUintOverflow
	}
	// Memory is expanded in words of 32 bytes. Gas
	// is also calculated in words.
	memSize = toWordSize(memSize)
	memSize *= 32
	// Extend memory gas cost
	cost, err := ibftMemoryGasCost(scope.Memory, memSize)
	if err != nil {
		return err
	}
	// Consume memory gas
	if !scope.Contract.UseGas(cost) {
		return ErrOutOfGas
	}
	// Resize the memory
	if memSize > 0 {
		scope.Memory.Resize(memSize)
	}

	return nil
}

func ibftGetMemory(scope *ScopeContext, offset, size *uint256.Int) ([]byte, error) {
	// Short-circuit
	if size.IsZero() {
		return nil, nil
	}

	if err := ibftExtendMemory(scope, offset, size); err != nil {
		return nil, err
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
			// Refund gas if necessary
			if ret != nil {
				scope.Contract.Gas += ret.Gas
			}
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
	offset := scope.Stack.pop()
	size := uint256.NewInt(32)
	// Extend memory if necessary
	value, err := ibftGetMemory(scope, &offset, size)
	if err != nil {
		return nil, err
	}

	// Push back to stack.
	vv := offset.SetBytes(value)
	scope.Stack.push(vv)

	return nil, nil
}

func ibftOpMstore(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// pop value of the stack
	mStart, val := scope.Stack.pop(), scope.Stack.pop()
	size := uint256.NewInt(32)
	// extend memory
	err := ibftExtendMemory(scope, &mStart, size)
	if err != nil {
		return nil, err
	}

	scope.Memory.Set32(mStart.Uint64(), &val)
	return nil, nil
}

func ibftOpMstore8(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	off, val := scope.Stack.pop(), scope.Stack.pop()
	size := uint256.NewInt(1)
	err := ibftExtendMemory(scope, &off, size)
	if err != nil {
		return nil, err
	}
	scope.Memory.store[off.Uint64()] = byte(val.Uint64()) & 0xff
	return nil, nil
}

func ibftOpSload(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	loc := scope.Stack.peek()
	hash := common.Hash(loc.Bytes32())
	val := interpreter.evm.StateDB.GetState(scope.Contract.Address(), hash)
	loc.SetBytes(val.Bytes())
	return nil, nil
}

func ibftOpSstore(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection
	}

	// If we fail the minimum gas availability invariant, fail (0)
	if scope.Contract.Gas <= params.SstoreSentryGasEIP2200 {
		return nil, errors.New("not enough gas for reentrancy sentry")
	}
	// Gas sentry honoured, do the actual gas calculation based on the stored value
	var (
		x, y       = scope.Stack.pop(), scope.Stack.pop()
		key, value = common.Hash(x.Bytes32()), common.Hash(y.Bytes32())
		cost       = uint64(0)
	)

	status := interpreter.evm.StateDB.SetStorageStatus(scope.Contract.Address(), key, value)

	switch status {
	case common.StorageUnchanged:
		cost = 800
	case common.StorageModified:
		cost = 5000
	case common.StorageModifiedAgain:
		cost = 800
	case common.StorageAdded:
		cost = 20000
	case common.StorageDeleted:
		cost = 5000
	}

	if !scope.Contract.UseGas(cost) {
		return nil, ErrOutOfGas
	}

	return nil, nil
}

// ibftBuildCallContract charges memory gas step by step
func ibftBuildCallContract(op OpCode, interpreter *EVMInterpreter, scope *ScopeContext) (ret *ibftInnerCallContract, writeEmptyStackWhenFail bool, err error) {
	var (
		initialGas = scope.Stack.pop()
		rawAddr    = scope.Stack.pop()
		addr       = common.Address(rawAddr.Bytes20())
	)

	var value *big.Int
	if op == CALL || op == CALLCODE {
		v := scope.Stack.pop()
		value = v.ToBig()
	}

	// input range
	inOffset, inSize := scope.Stack.pop(), scope.Stack.pop()
	// output range
	outOffset, outSize := scope.Stack.pop(), scope.Stack.pop()

	// Get contract code to memory
	input, getMemoryErr := ibftGetMemory(scope, &inOffset, &inSize)
	if getMemoryErr != nil {
		log.Warn("get code to memory failed", "err", getMemoryErr)
		// for outside break
		return nil, writeEmptyStackWhenFail, getMemoryErr
	}

	// Check if the memory return offsets are out of bounds
	if err := ibftExtendMemory(scope, &outOffset, &outSize); err != nil {
		return nil, writeEmptyStackWhenFail, err
	}

	var gasCost uint64
	if interpreter.evm.chainRules.IsEIP150 {
		gasCost = params.CallGasEIP150
	} else {
		gasCost = params.CallGasFrontier
	}

	needTransferValue := (op == CALL || op == CALLCODE) && value != nil && value.Sign() != 0

	if op == CALL {
		if interpreter.evm.chainRules.IsEIP158 {
			if needTransferValue && interpreter.evm.StateDB.Empty(addr) {
				gasCost += params.CallNewAccountGas
			}
		} else if !interpreter.evm.StateDB.Exist(addr) { // It shouldn't be, but just in case
			gasCost += params.CallNewAccountGas
		}
	}

	if needTransferValue {
		gasCost += params.CallValueTransferGas
	}

	var (
		gas uint64
		ok  = initialGas.IsUint64()
	)

	if interpreter.evm.chainRules.IsEIP150 {
		availableGas := scope.Contract.Gas - gasCost
		availableGas = availableGas - availableGas/64

		if !ok || availableGas < initialGas.Uint64() {
			gas = availableGas
		} else {
			gas = initialGas.Uint64()
		}
	} else { // It shouldn't be, but just in case.
		if !ok {
			return nil, writeEmptyStackWhenFail, ErrOutOfGas
		}
		// use all of it
		gas = initialGas.Uint64()
	}

	gasCost += gas

	if !scope.Contract.UseGas(gasCost) {
		return nil, writeEmptyStackWhenFail, ErrOutOfGas
	}

	if needTransferValue {
		gas += params.CallStipend
	}

	parent := scope.Contract

	contract := &ibftInnerCallContract{
		Type:    op,
		Caller:  parent.Address(),
		Address: addr,
		Value:   value,
		Gas:     gas,
		Code:    interpreter.evm.StateDB.GetCode(addr),
		Input:   input,
	}

	if op == STATICCALL || interpreter.readOnly {
		contract.ReadOnly = true
	}

	if op == CALLCODE || op == DELEGATECALL {
		contract.Address = parent.Address()
		if op == DELEGATECALL {
			contract.Value = parent.Value()
			contract.Caller = parent.Caller()
		}
	}

	if needTransferValue {
		if interpreter.evm.StateDB.GetBalance(scope.Contract.Address()).Cmp(value) < 0 {
			writeEmptyStackWhenFail = true
			return contract, writeEmptyStackWhenFail, ErrInsufficientBalance
		}
	}

	contract.OutputOffset = outOffset.Uint64()
	contract.OutputSize = outSize.Uint64()

	return contract, writeEmptyStackWhenFail, nil
}

type ibftInnerCallContract struct {
	Type         OpCode
	Caller       common.Address // from address
	Address      common.Address // to address
	Value        *big.Int
	Gas          uint64
	Code         []byte
	Input        []byte
	ReadOnly     bool
	OutputOffset uint64
	OutputSize   uint64
}

func ibftOpCallImpl(op OpCode) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		if op == CALL && interpreter.readOnly {
			if val := scope.Stack.Back(2); val.Sign() > 0 {
				return nil, ErrWriteProtection
			}
		}

		buildRet, writeEmptyStackWhenFail, buildErr := ibftBuildCallContract(op, interpreter, scope)
		if buildErr != nil && writeEmptyStackWhenFail {
			// Push empty value back to stack
			var emptyVal uint256.Int
			scope.Stack.push(&emptyVal)
			// Refund gas if necessary
			if buildRet != nil {
				scope.Contract.Gas += buildRet.Gas
			}
			return nil, buildErr
		}
		if buildRet == nil {
			return nil, buildErr
		}

		var temp uint256.Int
		ret, returnGas, err := interpreter.evm.Callx(op, AccountRef(buildRet.Caller), buildRet.Address, buildRet.Code, buildRet.Input, buildRet.Gas, buildRet.Value)
		// Set results back to stack
		if err != nil {
			temp.Clear()
		} else {
			temp.SetOne()
		}
		scope.Stack.push(&temp)

		// Set reverted value
		if err == nil || errors.Is(err, ErrExecutionReverted) {
			ret = common.CopyBytes(ret) // replace with new copy
			scope.Memory.Set(buildRet.OutputOffset, buildRet.OutputSize, ret)
		}

		// Refund gas
		scope.Contract.Gas += returnGas
		// Set return data
		interpreter.returnData = ret
		return ret, nil
	}
}
