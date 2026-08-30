package main

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Unrelated rooms must progress concurrently.
func TestUnrelatedRoomsRunConcurrently(t *testing.T) {
	r := NewLockRegistry()
	var inFlight, maxSeen int32
	var wg sync.WaitGroup
	for i, key := range []string{"~a\x00r1", "~b\x00r2", "~c\x00r3"} {
		wg.Add(1)
		go func(i int, k string) {
			defer wg.Done()
			rel := r.Acquire(k)
			defer rel()
			n := atomic.AddInt32(&inFlight, 1)
			for {
				m := atomic.LoadInt32(&maxSeen)
				if n <= m || atomic.CompareAndSwapInt32(&maxSeen, m, n) {
					break
				}
			}
			time.Sleep(120 * time.Millisecond)
			atomic.AddInt32(&inFlight, -1)
		}(i, key)
	}
	wg.Wait()
	if maxSeen < 2 {
		t.Fatalf("unrelated rooms serialized: max concurrent = %d, want >= 2", maxSeen)
	}
}

// The same [host,room] must serialize.
func TestSameRoomSerializes(t *testing.T) {
	r := NewLockRegistry()
	var inFlight, maxSeen int32
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel := r.Acquire("~a\x00sameroom")
			defer rel()
			n := atomic.AddInt32(&inFlight, 1)
			for {
				m := atomic.LoadInt32(&maxSeen)
				if n <= m || atomic.CompareAndSwapInt32(&maxSeen, m, n) {
					break
				}
			}
			time.Sleep(40 * time.Millisecond)
			atomic.AddInt32(&inFlight, -1)
		}()
	}
	wg.Wait()
	if maxSeen != 1 {
		t.Fatalf("same room ran concurrently: max = %d, want 1", maxSeen)
	}
}

// The keyed-lock map must not grow without bound.
func TestLockRegistryDoesNotLeak(t *testing.T) {
	r := NewLockRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rel := r.Acquire(string(rune('a'+i%26)) + "\x00room")
			time.Sleep(time.Millisecond)
			rel()
		}(i)
	}
	wg.Wait()
	if s := r.Size(); s != 0 {
		t.Fatalf("lock registry leaked %d keys", s)
	}
}

// Per-host semaphores are reclaimed when idle.
func TestHostSemaphoresDoNotLeak(t *testing.T) {
	h := NewHostSemaphores(2)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rel, ok := h.Acquire(ctx, string(rune('a'+i%10)), time.Second)
			if !ok {
				return
			}
			time.Sleep(time.Millisecond)
			rel()
		}(i)
	}
	wg.Wait()
	if s := h.Size(); s != 0 {
		t.Fatalf("host semaphore map leaked %d hosts", s)
	}
}

// A saturated semaphore rejects at the boundary instead of queueing.
func TestSemaphoreRejectsWhenSaturated(t *testing.T) {
	s := NewSemaphore(1)
	ctx := context.Background()
	if !s.Acquire(ctx, 50*time.Millisecond) {
		t.Fatal("first acquire should succeed")
	}
	if s.Acquire(ctx, 50*time.Millisecond) {
		t.Fatal("second acquire should have been rejected")
	}
	s.Release()
	if !s.Acquire(ctx, 50*time.Millisecond) {
		t.Fatal("acquire after release should succeed")
	}
}

// Admission order is host -> global -> room. Acquiring in one fixed order
// is what prevents deadlock; this exercises the full nesting under load.
func TestAdmissionOrderNoDeadlock(t *testing.T) {
	g := NewSemaphore(4)
	h := NewHostSemaphores(2)
	r := NewLockRegistry()
	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for i := 0; i < 60; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				rel, ok := h.Acquire(ctx, string(rune('a'+i%3)), 2*time.Second)
				if !ok {
					return
				}
				defer rel()
				if !g.Acquire(ctx, 2*time.Second) {
					return
				}
				defer g.Release()
				rr := r.Acquire(string(rune('a'+i%3)) + "\x00" + string(rune('x'+i%2)))
				time.Sleep(time.Millisecond)
				rr()
			}(i)
		}
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("deadlock or starvation under nested admission")
	}
	if g.InUse() != 0 || h.Size() != 0 || r.Size() != 0 {
		t.Fatalf("resources leaked: global=%d hosts=%d rooms=%d",
			g.InUse(), h.Size(), r.Size())
	}
}

// Lease TTL clamping must respect configured bounds.
func TestClampTTL(t *testing.T) {
	if got := clampTTL(0); got != leaseDefaultTTL {
		t.Fatalf("zero should mean default, got %v", got)
	}
	if got := clampTTL(1); got != leaseMinTTL {
		t.Fatalf("below min should clamp up, got %v", got)
	}
	if got := clampTTL(int(leaseMaxTTL.Seconds()) * 10); got != leaseMaxTTL {
		t.Fatalf("above max should clamp down, got %v", got)
	}
}

// Namespace derivation: same room key, different hosts -> different groups.
func TestNamespaceIsolation(t *testing.T) {
	a := groupFor("~dolten-dilpun", "sharedroomkey01")
	b := groupFor("~mignes-magtel", "sharedroomkey01")
	if a == b {
		t.Fatal("two hosts collided on one group name")
	}
	if !isManaged(a) || !isManaged(b) {
		t.Fatal("derived group escaped the managed namespace")
	}
}

// The fingerprint must change when any field changes, so a reused request
// id with a different body is detectable.
func TestFingerprintSensitivity(t *testing.T) {
	base := Command{Req: "r", Op: "ensure-room", Room: "roomkey01", Subject: "~a"}
	f0 := fingerprint(base)
	for _, mut := range []func(*Command){
		func(c *Command) { c.Op = "end-room" },
		func(c *Command) { c.Room = "roomkey02" },
		func(c *Command) { c.Participant = "~zod" },
		func(c *Command) { c.TTL = 60 },
		func(c *Command) { c.Subject = "~b" },
	} {
		c := base
		mut(&c)
		if fingerprint(c) == f0 {
			t.Fatalf("fingerprint insensitive to a changed field: %+v", c)
		}
	}
}

// A host queueing behind its own limit must not occupy global capacity.
// This is the availability-isolation property: with the old order (global
// first) host A's waiters held global slots and host B was rejected.
func TestSaturatedHostDoesNotConsumeGlobalSlots(t *testing.T) {
	g := NewSemaphore(4)
	h := NewHostSemaphores(2)
	ctx := context.Background()
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// 8 requests from host A, whose per-host limit is 2. Only 2 may ever
	// hold a global slot; the other 6 must wait on the HOST semaphore.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, ok := h.Acquire(ctx, "A", 3*time.Second)
			if !ok {
				return
			}
			defer rel()
			if !g.Acquire(ctx, 3*time.Second) {
				return
			}
			defer g.Release()
			<-stop
		}()
	}
	time.Sleep(250 * time.Millisecond)

	if used := g.InUse(); used > 2 {
		close(stop)
		wg.Wait()
		t.Fatalf("host A occupies %d global slots; its per-host limit is 2", used)
	}

	// An unrelated host must still be admitted.
	relB, ok := h.Acquire(ctx, "B", time.Second)
	if !ok {
		close(stop)
		wg.Wait()
		t.Fatal("host B was refused its own host slot")
	}
	if !g.Acquire(ctx, time.Second) {
		relB()
		close(stop)
		wg.Wait()
		t.Fatal("host B could not get a global slot: host A consumed global capacity")
	}
	g.Release()
	relB()
	close(stop)
	wg.Wait()
}
