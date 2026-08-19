package ike

import (
	"context"
	"testing"
	"time"
)

func TestSessionRunStopsOnContextCancellation(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	s := &Session{mux: mux}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Session.Run did not stop after context cancellation")
	}
}

func TestNextDueRekeyPreservesChildPriority(t *testing.T) {
	child := &rekeySchedule{name: "Child SA", due: true}
	ike := &rekeySchedule{name: "IKE SA", due: true}
	if got := nextDueRekey([]*rekeySchedule{child, ike}, nil); got != child {
		t.Fatalf("first due schedule = %v, want Child SA", got)
	}
	if got := nextDueRekey([]*rekeySchedule{child, ike}, child); got != nil {
		t.Fatalf("selected %v while another rekey was running", got)
	}
	if got := nextDueRekey([]*rekeySchedule{child, ike}, nil); got != ike {
		t.Fatalf("second due schedule = %v, want IKE SA", got)
	}
}

func TestSupportedPayloadTypeRejectsUnknownCriticalType(t *testing.T) {
	if supportedPayloadType(PayloadType(250)) {
		t.Fatal("unknown payload type reported as supported")
	}
	if !supportedPayloadType(PayloadSA) {
		t.Fatal("SA payload type reported as unsupported")
	}
}

func TestRekeyRetryDelay(t *testing.T) {
	s := &Session{rekeyRetryInitial: 5 * time.Second, rekeyRetryMax: time.Minute}
	for _, test := range []struct {
		failures uint
		want     time.Duration
	}{
		{1, 5 * time.Second},
		{2, 10 * time.Second},
		{3, 20 * time.Second},
		{4, 40 * time.Second},
		{5, time.Minute},
		{6, time.Minute},
	} {
		if got := s.rekeyRetryDelay(test.failures); got != test.want {
			t.Errorf("retry delay after %d failures = %s, want %s", test.failures, got, test.want)
		}
	}
}

func TestSetRekeyRetry(t *testing.T) {
	s := new(Session)
	if err := s.SetRekeyRetry(5*time.Second, time.Minute); err != nil {
		t.Fatal(err)
	}
	if s.rekeyRetryInitial != 5*time.Second || s.rekeyRetryMax != time.Minute {
		t.Fatalf("retry delays = %s, %s", s.rekeyRetryInitial, s.rekeyRetryMax)
	}
	for _, delays := range [][2]time.Duration{{0, time.Second}, {time.Second, 0}, {time.Minute, time.Second}} {
		if err := s.SetRekeyRetry(delays[0], delays[1]); err == nil {
			t.Fatalf("SetRekeyRetry(%s, %s) succeeded", delays[0], delays[1])
		}
	}
}
