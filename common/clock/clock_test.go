package clock

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestClampDuration(t *testing.T) {
	timer := NewTimer(0)
	<-timer.C()

	t.Cleanup(func() {
		timer.Stop()
	})

	// clamp duration to 1 second
	timer.Reset(ClampDuration(0, 1, 1))
	startT := time.Now()
	<-timer.C()
	endT := time.Now()

	if endT.Sub(startT) > (1*time.Second + 10*time.Millisecond) {
		t.Errorf("ClampDuration failed to clamp duration to 1 second")
	}
}

func TestClampDurationToMin(t *testing.T) {
	timer := NewTimer(0)
	<-timer.C()

	t.Cleanup(func() {
		timer.Stop()
	})

	// clamp duration to 1 second
	timer.Reset(ClampDuration(0, 1, 2))
	startT := time.Now()
	<-timer.C()
	endT := time.Now()

	if endT.Sub(startT) > (1*time.Second + 10*time.Millisecond) {
		t.Errorf("ClampDuration failed to clamp duration to 1 second")
	}
}

func TestClampDurationToMax(t *testing.T) {
	timer := NewTimer(0)
	<-timer.C()

	t.Cleanup(func() {
		timer.Stop()
	})

	// clamp duration to 2 seconds
	timer.Reset(ClampDuration(3, 1, 2))
	startT := time.Now()
	<-timer.C()
	endT := time.Now()

	if endT.Sub(startT) > (2*time.Second + 10*time.Millisecond) {
		t.Errorf("ClampDuration failed to clamp duration to 2 seconds")
	}
}

func TestTimerReset(t *testing.T) {
	timer := NewTimer(0)
	<-timer.C()

	t.Cleanup(func() {
		timer.Stop()
	})

	// reset timer to 1 second
	timer.Reset(1 * time.Second)
	// reset timer to 2 seconds
	timer.Reset(2 * time.Second)

	// but the timer should fire after 2 second
	startT := time.Now()
	<-timer.C()
	endT := time.Now()

	diffT := endT.Sub(startT)

	if !(diffT > 1*time.Second && diffT < (2*time.Second+10*time.Millisecond)) {
		t.Errorf("Timer failed to reset timer to 2 seconds")
	}

	// blocking on timer.C() never returns because the timer has already fired
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()

		select {
		case <-timer.C():
			t.Errorf("Timer triggered twice")
			return
		case <-ctx.Done():
			return
		}
	}()

	wg.Wait()
}
