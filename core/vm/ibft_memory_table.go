package vm

import "github.com/holiman/uint256"

const (
	_ibftGasUintOverflowLimit = 0xffffffffe0
)

// ibftCalcMemSize64 calculates the required memory size, and returns
// the size and whether the result overflowed uint64
func ibftCalcMemSize64(off, l *uint256.Int) (uint64, bool) {
	if !l.IsUint64() {
		return 0, true
	}
	return ibftCalcMemSize64WithUint(off, l.Uint64())
}

// ibftCalcMemSize64WithUint calculates the required memory size,
// and returns the size and whether the result overflowed uint64
//
// Identical to calcMemSize64, but length is a uint64
func ibftCalcMemSize64WithUint(off *uint256.Int, length64 uint64) (uint64, bool) {
	// Check that offset doesn't overflow
	offset64, overflow := off.Uint64WithOverflow()
	if overflow {
		return 0, true
	}
	// If length is zero, memsize is always zero
	if length64 == 0 {
		return 0, false
	}
	// Assures offset and limit not exceed hard code limit
	if offset64 > _ibftGasUintOverflowLimit || length64 > _ibftGasUintOverflowLimit {
		return 0, true
	}

	val := offset64 + length64
	return val, false
}

func ibftMemoryKeccak256(stack *Stack) (uint64, bool) {
	return ibftCalcMemSize64(stack.Back(0), stack.Back(1))
}

func ibftMemoryCallDataCopy(stack *Stack) (uint64, bool) {
	return ibftCalcMemSize64(stack.Back(0), stack.Back(2))
}

func ibftMemoryReturnDataCopy(stack *Stack) (uint64, bool) {
	return ibftCalcMemSize64(stack.Back(0), stack.Back(2))
}

func ibftMemoryCodeCopy(stack *Stack) (uint64, bool) {
	return ibftCalcMemSize64(stack.Back(0), stack.Back(2))
}

func ibftMemoryExtCodeCopy(stack *Stack) (uint64, bool) {
	return ibftCalcMemSize64(stack.Back(1), stack.Back(3))
}

func ibftEmptyMemorySize(stack *Stack) (uint64, bool) {
	return 0, false
}

func ibftMemoryReturn(stack *Stack) (uint64, bool) {
	return ibftCalcMemSize64(stack.Back(0), stack.Back(1))
}

func ibftMemoryRevert(stack *Stack) (uint64, bool) {
	return ibftCalcMemSize64(stack.Back(0), stack.Back(1))
}

func ibftMemoryLog(stack *Stack) (uint64, bool) {
	return ibftCalcMemSize64(stack.Back(0), stack.Back(1))
}
