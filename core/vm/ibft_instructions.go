package vm

func ibftOpCreate2(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection
	}
	var (
		endowment    = scope.Stack.pop()
		offset, size = scope.Stack.pop(), scope.Stack.pop()
		salt         = scope.Stack.pop()
		input        = scope.Memory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))
		gas          = scope.Contract.Gas
	)

	// Apply EIP150
	gas -= gas / 64
	scope.Contract.UseGas(gas)

	// reuse size int for stackvalue
	stackvalue := size

	//NOTE: use uint256.Int instead of converting with toBig()
	bigEndowment := big0
	if !endowment.IsZero() {
		bigEndowment = endowment.ToBig()
	}

	res, addr, returnGas, suberr := interpreter.evm.Create2(scope.Contract, input, gas,
		bigEndowment, &salt)

	// Push item on the stack based on the returned error.
	// IBFT use a strange Create2 opcode stack calling sequence, which is not
	// EVM compatible. So we need to return address even though it failed due
	// to not enough gas during running the construction.
	// But we'll make this unknown issue back to normal after the hard fork
	stackvalue.SetBytes(addr.Bytes())

	scope.Stack.push(&stackvalue)
	scope.Contract.Gas += returnGas

	if suberr == ErrExecutionReverted {
		interpreter.returnData = res // set REVERT data to return data buffer
		return res, nil
	}
	interpreter.returnData = nil // clear dirty return data buffer
	return nil, nil
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
