package vm

import (
	"github.com/ethereum/go-ethereum/params"
)

// pure moemory cost instructions
var (
	ibftGasReturn = ibftPureMemoryGasCost
	ibftGasRevert = ibftPureMemoryGasCost
)

// copy instructions
var (
	ibftGasCallDataCopy   = ibftMemoryDynamicWordGas(2, params.CopyGas)
	ibftGasCodeCopy       = ibftMemoryDynamicWordGas(2, params.CopyGas)
	ibftGasExtCodeCopy    = ibftMemoryDynamicWordGas(3, params.CopyGas)
	ibftGasReturnDataCopy = ibftMemoryDynamicWordGas(2, params.CopyGas)
)

// other dynamic instructions
var (
	ibftGasKeccak256 = ibftMemoryDynamicWordGas(1, params.Keccak256WordGas)
)

// ibftEmptyMemoryGasCost does nothing and its calculation and memory sizing
// take place in the execution
func ibftEmptyMemoryGasCost(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return 0, nil
}

// ibftMemoryGasCost calculates the quadratic gas for memory expansion. It does
// so only for the memory region that is expanded, not the total memory.
func ibftMemoryGasCost(mem *Memory, newMemSize uint64) (uint64, error) {
	if newMemSize == 0 {
		return 0, nil
	}
	// Currently ibft calculates the gas which can be exceeded
	// uint64. Do not care about the acient block bug here. We
	// should dismiss those instructions and gas calculations
	// after such hard forks.
	// The judgement is already done when calculating the gas,
	// we'll just ignore here.

	newMemSizeWords := toWordSize(newMemSize)
	newMemSize = newMemSizeWords * 32

	if newMemSize > uint64(mem.Len()) {
		square := newMemSizeWords * newMemSizeWords
		linCoef := newMemSizeWords * params.MemoryGas
		quadCoef := square / params.QuadCoeffDiv
		newTotalFee := linCoef + quadCoef

		fee := newTotalFee - mem.lastGasCost
		mem.lastGasCost = newTotalFee

		return fee, nil
	}
	return 0, nil
}

// ibftPureMemoryGasCost is used by several operations, which aside from
// their static cost have a dynamic cost which is solely based on the memory
// expansion.
func ibftPureMemoryGasCost(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return ibftMemoryGasCost(mem, memorySize)
}

// ibftMemoryDynamicWordGas creates the gas functions for all
// dynamic gas opcodes
//
// It takes the stack position of the operand which determines
// the size of the data to copy as argument.
//
// # Examples:
//
//	CALLDATACOPY (stack position 2, 3 per word)
//	KECCAK256 (stack position 1, 6 per word)
func ibftMemoryDynamicWordGas(stackpos int, gasPerWord uint64) gasFunc {
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		// Gas for expanding the memory
		gas, err := ibftMemoryGasCost(mem, memorySize)
		if err != nil {
			return 0, err
		}
		// And gas for copying data, charged per word at param.CopyGas
		// Length is already verified.
		words := stack.Back(stackpos).Uint64()
		// Don't care about overflow here may cause its
		// strange behavior.
		words = toWordSize(words)
		words *= gasPerWord
		gas += words
		return gas, nil
	}
}

func ibftMakeGasLog(n uint64) gasFunc {
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		if evm.interpreter.readOnly {
			return 0, ErrWriteProtection
		}
		// make sure not charge gas if stack underflow
		if uint64(stack.len()) < 2+n {
			return 0, &ErrStackUnderflow{
				stackLen: stack.len(),
				required: int(2 + n),
			}
		}

		requestedSize, overflow := stack.Back(1).Uint64WithOverflow()
		if overflow {
			return 0, ErrGasUintOverflow
		}
		// memory extension gas
		gas, err := ibftMemoryGasCost(mem, memorySize)
		if err != nil {
			return 0, err
		}
		// dynamic cost
		gas += n * params.LogGas
		// memory copy counting
		memorySizeGas := requestedSize * params.LogDataGas
		gas += memorySizeGas

		return gas, nil
	}
}
