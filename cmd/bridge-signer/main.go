//go:build !windows

// bridge-signer is the gRPC remote signing daemon. The build is gated on
// Unix: the signer relies on POSIX file mode bits for key file secrecy
// (NTFS ACLs are not reflected by os.FileMode) and on SIGTERM for
// graceful service stop. Refusing to build on Windows avoids shipping
// a binary with silently weakened guarantees.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
