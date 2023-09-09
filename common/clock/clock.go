package clock

import "time"

type Timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(d time.Duration) bool
}

// ClampDuration returns d if n <= d <= m, n if d < n, and m if d > m.
func ClampDuration(d, n, m time.Duration) time.Duration {
	if d < n {
		return n
	}
	if d > m {
		return m
	}
	return d
}

func NewTimer(d time.Duration) Timer {
	return &realTimer{timer: time.NewTimer(d)}
}

// https://go.dev/doc/faq#guarantee_satisfies_interface
var _ = Timer(&realTimer{})

// `go vet` gives a warning if this struct is copied.
// https://github.com/golang/go/issues/8005#issuecomment-190753527
type noCopy struct{}

func (*noCopy) Lock() {}

type realTimer struct {
	noCopy noCopy
	timer  *time.Timer
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
