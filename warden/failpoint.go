//go:build failpoints

package main

// TEST-ONLY build. Compiled only with `-tags failpoints` into a separate
// binary that is never deployed. Each failpoint aborts the process without
// unwinding -- the point is to leave exactly the durable state a real
// SIGKILL would leave at that instruction.

import (
	"log"
	"os"
	"syscall"
)

const failpointsCompiledIn = true

// failpoint kills the process immediately when WARDEN_FAILPOINT names it.
func failpoint(name string) {
	if os.Getenv("WARDEN_FAILPOINT") != name {
		return
	}
	log.Printf("event=failpoint-kill name=%s", name)
	// SIGKILL to self: no deferred work, no flush, no graceful shutdown.
	syscall.Kill(os.Getpid(), syscall.SIGKILL)
	select {}
}
