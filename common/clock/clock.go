package clock

import "time"

type Timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(d time.Duration) bool
}

func NewTimer(d time.Duration) Timer {
	return &realTimer{time.NewTimer(d)}
}

var _ = Timer(&realTimer{})

type realTimer struct {
	timer *time.Timer
}

// C returns the underlying timer's channel.
func (r *realTimer) C() <-chan time.Time {
	return r.timer.C
}

// Stop calls Stop() on the underlying timer.
func (r *realTimer) Stop() bool {
	return r.timer.Stop()
}

// Reset calls Reset() on the underlying timer.
func (r *realTimer) Reset(d time.Duration) bool {
	// why not just call r.timer.Reset(d)?
	// from time.Timer.Reset() docs:
	// """
	// For a Timer created with NewTimer, Reset should be invoked only on
	// stopped or expired timers with drained channels.
	// """
	// if we don't drain the channel, the timer has blocked
	r.timer.Stop()
	select {
	case <-r.timer.C:
	default:
	}
	return r.timer.Reset(d)
}
