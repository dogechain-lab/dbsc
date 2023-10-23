package dc

import (
	"github.com/dogechain-lab/dogechain/state"
	"github.com/dogechain-lab/dogechain/types"
)

type StateObjectHook func([]*state.Object)

type WrapDcState struct {
	state state.State

	hook StateObjectHook
}

func (w *WrapDcState) SetCommitHook(hook StateObjectHook) {
	w.hook = hook
}

func (w *WrapDcState) NewSnapshotAt(hash types.Hash) (state.Snapshot, error) {
	snap, err := w.state.NewSnapshotAt(hash)

	return &WrapDcSnapshot{
		wrapState: w,
		snap:      snap,
	}, err
}

func (w *WrapDcState) NewSnapshot() state.Snapshot {
	return &WrapDcSnapshot{
		wrapState: w,
		snap:      w.state.NewSnapshot(),
	}
}

func (w *WrapDcState) GetCode(hash types.Hash) ([]byte, bool) {
	return w.state.GetCode(hash)
}

type WrapDcSnapshot struct {
	wrapState *WrapDcState

	snap state.Snapshot
}

func (w *WrapDcSnapshot) GetStorage(addr types.Address, root types.Hash, key types.Hash) (types.Hash, error) {
	return w.snap.GetStorage(addr, root, key)
}

func (w *WrapDcSnapshot) GetAccount(addr types.Address) (*state.Account, error) {
	return w.snap.GetAccount(addr)
}

func (w *WrapDcSnapshot) GetCode(hash types.Hash) ([]byte, bool) {
	return w.snap.GetCode(hash)
}

func (w *WrapDcSnapshot) Commit(objs []*state.Object) (state.Snapshot, []byte, error) {
	if w.wrapState.hook != nil {
		w.wrapState.hook(objs)
	}

	return w.snap.Commit(objs)
}

func NewWrapDcState(state state.State) *WrapDcState {
	return &WrapDcState{
		state: state,
	}
}
