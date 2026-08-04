//go:build linux

package discover

import "syscall"

// Linux SO_REUSEPORT (not always present in the syscall package).
const soReusePort = 15

func reusePortControl(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		if opErr != nil {
			return
		}
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
	})
	if err != nil {
		return err
	}
	return opErr
}
