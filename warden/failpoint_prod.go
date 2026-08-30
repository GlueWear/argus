//go:build !failpoints

package main

// Production build: failpoints do not exist. This no-op is inlined away, so
// the shipped binary contains neither failpoint logic nor failpoint names,
// and no environment variable can enable one.
func failpoint(string) {}

const failpointsCompiledIn = false
