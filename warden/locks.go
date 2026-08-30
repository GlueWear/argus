package main

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Admission is applied in ONE documented order, always:
//
//	1. per-host concurrency semaphore
//	2. global concurrency semaphore
//	3. per-[host,room] mutex
//
// Per-host comes FIRST so that a host queueing behind its own limit never
// occupies global capacity. Reversing these two starves unrelated hosts.
//
// Acquiring in a fixed order is what makes deadlock impossible: no
// goroutine ever holds a later resource while waiting for an earlier one.
// Nothing here is held across an HTTP response, and no SQLite transaction
// is ever open while any of these are held during network work.

type keyedLock struct {
	mu  sync.Mutex
	ref int
}

// LockRegistry hands out per-key mutexes and reclaims them when the last
// waiter leaves, so the map cannot grow without bound.
type LockRegistry struct {
	mu   sync.Mutex
	keys map[string]*keyedLock
}

func NewLockRegistry() *LockRegistry {
	return &LockRegistry{keys: map[string]*keyedLock{}}
}

// Acquire blocks until the key is held. The returned func releases it.
// The registry mutex is held only while adjusting the refcount, never
// while the caller does work.
func (r *LockRegistry) Acquire(key string) func() {
	r.mu.Lock()
	kl, ok := r.keys[key]
	if !ok {
		kl = &keyedLock{}
		r.keys[key] = kl
	}
	kl.ref++
	r.mu.Unlock()

	kl.mu.Lock()

	return func() {
		kl.mu.Unlock()
		r.mu.Lock()
		kl.ref--
		if kl.ref == 0 {
			delete(r.keys, key) // bounded growth
		}
		r.mu.Unlock()
	}
}

// Size reports live keys; used by tests to prove the map does not leak.
func (r *LockRegistry) Size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.keys)
}

// Semaphore is a counting semaphore with a bounded wait. It also records a
// high-water mark so occupancy can be reported without sampling races.
type Semaphore struct {
	ch chan struct{}
	hw int64 // atomic
}

func NewSemaphore(n int) *Semaphore { return &Semaphore{ch: make(chan struct{}, n)} }

// Acquire returns false if the wait budget expires, so a saturated system
// rejects at the boundary rather than queueing without limit.
func (s *Semaphore) Acquire(ctx context.Context, wait time.Duration) bool {
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case s.ch <- struct{}{}:
		s.bump()
		return true
	case <-t.C:
		return false
	case <-ctx.Done():
		return false
	}
}

func (s *Semaphore) Release() { <-s.ch }

func (s *Semaphore) InUse() int { return len(s.ch) }

func (s *Semaphore) bump() {
	n := int64(len(s.ch))
	for {
		old := atomic.LoadInt64(&s.hw)
		if n <= old || atomic.CompareAndSwapInt64(&s.hw, old, n) {
			return
		}
	}
}

// HighWater is the greatest occupancy seen since process start.
func (s *Semaphore) HighWater() int { return int(atomic.LoadInt64(&s.hw)) }

// HostSemaphores gives each authenticated host its own bounded slot count,
// reclaimed when idle so an unbounded set of hosts cannot grow the map.
type HostSemaphores struct {
	mu    sync.Mutex
	n     int
	hosts map[string]*hostSlot
}

type hostSlot struct {
	sem *Semaphore
	ref int
}

func NewHostSemaphores(n int) *HostSemaphores {
	return &HostSemaphores{n: n, hosts: map[string]*hostSlot{}}
}

func (h *HostSemaphores) Acquire(ctx context.Context, host string, wait time.Duration) (func(), bool) {
	h.mu.Lock()
	hs, ok := h.hosts[host]
	if !ok {
		hs = &hostSlot{sem: NewSemaphore(h.n)}
		h.hosts[host] = hs
	}
	hs.ref++
	h.mu.Unlock()

	if !hs.sem.Acquire(ctx, wait) {
		h.release(host, hs)
		return nil, false
	}
	return func() {
		hs.sem.Release()
		h.release(host, hs)
	}, true
}

func (h *HostSemaphores) release(host string, hs *hostSlot) {
	h.mu.Lock()
	hs.ref--
	if hs.ref == 0 {
		delete(h.hosts, host)
	}
	h.mu.Unlock()
}

func (h *HostSemaphores) Size() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.hosts)
}

// Snapshot reports occupancy across hosts: the largest number of slots any
// single host currently holds, the largest it has ever held, and how many
// hosts are tracked right now.
func (h *HostSemaphores) Snapshot() (curMax, hwMax, hosts int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, hs := range h.hosts {
		if n := hs.sem.InUse(); n > curMax {
			curMax = n
		}
		if n := hs.sem.HighWater(); n > hwMax {
			hwMax = n
		}
	}
	return curMax, hwMax, len(h.hosts)
}
