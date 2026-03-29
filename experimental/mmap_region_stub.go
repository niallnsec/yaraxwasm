//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris)

package experimental

import (
	"errors"
	"io"
	"unsafe"

	"github.com/niallnsec/yaraxwasm"
)

func newMmapRegion(reserveBytes uint64) (reservedRegion, error) {
	return nil, describeAllocationFailure(reserveBytes, errors.New("mmap-backed guest memory is unsupported on this platform"))
}

func mapFileToGuest(addr unsafe.Pointer, mappedLength uint32, path string) (yaraxwasm.GuestMappedRegion, error) {
	_ = addr
	_ = mappedLength
	_ = path
	return nil, errors.New("mmap-backed guest file mapping is unsupported on this platform")
}

func mapReaderAtToGuest(addr unsafe.Pointer, mappedLength uint32, src io.ReaderAt, size int64) (yaraxwasm.GuestMappedRegion, error) {
	_ = addr
	_ = mappedLength
	_ = src
	_ = size
	return nil, errors.New("userfaultfd-backed guest reader mapping is unsupported on this platform")
}
