package experimental

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/wazero/experimental/wazerotest"
)

func TestMmapMemoryAllocatorKeepsStableBackingAcrossGrowth(t *testing.T) {
	allocator := NewMmapMemoryAllocator()
	mem := allocator.Allocate(64<<10, 256<<10)
	t.Cleanup(mem.Free)

	first := mem.Reallocate(64 << 10)
	require.Len(t, first, 64<<10)
	first[0] = 0x7a

	second := mem.Reallocate(128 << 10)
	require.Len(t, second, 128<<10)
	require.Equal(t, byte(0x7a), second[0])
	require.Equal(t, unsafe.SliceData(first), unsafe.SliceData(second))
}

type fakeReservedRegion struct {
	data         []byte
	reportMemory bool
}

func (r *fakeReservedRegion) slice(size uint64) []byte {
	sizeLen, err := intBytes(size)
	if err != nil || sizeLen > len(r.data) {
		return nil
	}
	return r.data[:sizeLen:sizeLen]
}

func (r *fakeReservedRegion) free() {
	r.data = nil
}

func (r *fakeReservedRegion) mappingInfo() (uintptr, uintptr, bool) {
	if !r.reportMemory || len(r.data) == 0 {
		return 0, 0, false
	}
	return uintptr(unsafe.Pointer(unsafe.SliceData(r.data))), uintptr(len(r.data)), true
}

type fakeReservedRegionBackend struct {
	region reservedRegion
	err    error
}

func (b fakeReservedRegionBackend) allocateRegion(uint64) (reservedRegion, error) {
	if b.err != nil {
		return nil, b.err
	}
	return b.region, nil
}

func TestSliceRegionAndAllocationHelpers(t *testing.T) {
	region, err := newSliceRegion(32)
	require.NoError(t, err)

	view := region.slice(16)
	require.Len(t, view, 16)
	require.Nil(t, region.slice(64))

	start, length, ok := region.mappingInfo()
	require.False(t, ok)
	require.Zero(t, start)
	require.Zero(t, length)

	region.free()
	require.Nil(t, region.slice(1))

	require.NoError(t, describeAllocationFailure(64, nil))
	require.EqualError(t, describeAllocationFailure(64, io.EOF), "reserve 64 bytes for guest memory: EOF")
}

func TestReserveLengthNormalizesCapacityAndMaxCapacity(t *testing.T) {
	require.Equal(t, uint64(16), reserveLength(16, 0))
	require.Equal(t, uint64(16), reserveLength(16, 8))
	require.Equal(t, uint64(32), reserveLength(16, 32))
	require.Equal(t, uint64(1), reserveLength(0, 0))
}

func TestMmapMemoryAllocatorFallsBackToSliceRegion(t *testing.T) {
	allocator := &MmapMemoryAllocator{
		backend: fakeReservedRegionBackend{err: errors.New("reserve failed")},
	}

	mem := allocator.Allocate(32, 64)
	linear, ok := mem.(*linearMemory)
	require.True(t, ok)
	_, ok = linear.region.(*sliceRegion)
	require.True(t, ok)

	view := mem.Reallocate(48)
	require.Len(t, view, 48)

	mem.Free()
	require.Nil(t, linear.region)
}

func TestGuestWindowAddressHandlesEdgeCases(t *testing.T) {
	allocator := &MmapMemoryAllocator{}
	memory := wazerotest.NewFixedMemory(wazerotest.PageSize)

	ptr, err := allocator.guestWindowAddress(memory, 0, 0)
	require.NoError(t, err)
	require.Nil(t, ptr)

	_, err = allocator.guestWindowAddress(memory, wazerotest.PageSize-4, 8)
	require.EqualError(t, err, "guest mapping window [65532,65540) is out of bounds")

	region := &fakeReservedRegion{
		data:         make([]byte, wazerotest.PageSize),
		reportMemory: true,
	}
	memory.Bytes = region.data
	allocator.registerRegion(region)

	ptr, err = allocator.guestWindowAddress(memory, 8, 16)
	require.NoError(t, err)
	view, ok := memory.Read(8, 16)
	require.True(t, ok)
	require.Equal(t, uintptr(unsafe.Pointer(unsafe.SliceData(view))), uintptr(ptr))

	allocator.unregisterRegion(region)
	_, err = allocator.guestWindowAddress(memory, 8, 16)
	require.EqualError(t, err, "guest memory is not backed by an mmap-reserved region")
}

func TestMapReaderAtToGuestZeroLength(t *testing.T) {
	allocator := NewMmapMemoryAllocator()
	region, err := allocator.MapReaderAtToGuest(wazerotest.NewFixedMemory(wazerotest.PageSize), 0, 0, bytes.NewReader(nil), 0)
	require.NoError(t, err)
	require.NoError(t, region.Close())
}
