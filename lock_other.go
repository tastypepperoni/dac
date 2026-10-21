//go:build !unix

package dac

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// lockFile takes an exclusive lock by creating path with O_EXCL and removes it
// when the returned function is called.  Without flock(2), a lock left by a
// crashed process must be removed by hand; the error message says so.
func lockFile(path string) (func(), error) {
	deadline := time.Now().Add(60 * time.Second)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%s is held by another process; if none is running, delete it", path)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
