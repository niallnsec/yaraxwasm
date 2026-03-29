package yaraxwasm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental/wazerotest"
	"google.golang.org/protobuf/types/known/emptypb"
)

type testProfilingBuffer struct {
	ptr    uint32
	length uint32
}

type testProfilingGuest struct {
	memory  *wazerotest.Memory
	nextPtr uint32

	nextHandle uint32
	buffers    map[uint32]testProfilingBuffer

	slowest func(handle, count uint64) uint64
	clear   func(handle uint64) uint64
}

func newTestProfilingScanner(t *testing.T) (*Scanner, *testProfilingGuest) {
	t.Helper()

	guest := &testProfilingGuest{
		memory:     wazerotest.NewFixedMemory(64 * 1024),
		nextPtr:    1024,
		nextHandle: 1,
		buffers:    map[uint32]testProfilingBuffer{},
	}

	realloc := wazerotest.NewFunction(func(_ context.Context, _ api.Module, _, _, align, newSize uint64) uint64 {
		return uint64(guest.alloc(
			mustTestU32FromUint64(t, newSize, "profiling realloc size"),
			mustTestU32FromUint64(t, align, "profiling realloc align"),
		))
	})
	realloc.ExportNames = []string{"cabi_realloc"}

	slowest := wazerotest.NewFunction(func(_ context.Context, _ api.Module, handle, count uint64) uint64 {
		if guest.slowest == nil {
			return packTestCallResult(yrxSuccess, 0)
		}
		return guest.slowest(handle, count)
	})
	slowest.ExportNames = []string{"go_yrx_scanner_slowest_rules_json"}

	clearProfiling := wazerotest.NewFunction(func(_ context.Context, _ api.Module, handle uint64) uint64 {
		if guest.clear == nil {
			return packTestCallResult(yrxSuccess, 0)
		}
		return guest.clear(handle)
	})
	clearProfiling.ExportNames = []string{"go_yrx_scanner_clear_profiling_data"}

	bufferPtr := wazerotest.NewFunction(func(_ context.Context, _ api.Module, handle uint64) uint64 {
		return uint64(guest.buffers[mustTestU32FromUint64(t, handle, "profiling buffer handle")].ptr)
	})
	bufferPtr.ExportNames = []string{guestExportBufferPtr}

	bufferLen := wazerotest.NewFunction(func(_ context.Context, _ api.Module, handle uint64) uint64 {
		return uint64(guest.buffers[mustTestU32FromUint64(t, handle, "profiling buffer handle")].length)
	})
	bufferLen.ExportNames = []string{guestExportBufferLen}

	bufferDestroy := wazerotest.NewFunction(func(_ context.Context, _ api.Module, handle uint64) {
		delete(guest.buffers, mustTestU32FromUint64(t, handle, "profiling buffer handle"))
	})
	bufferDestroy.ExportNames = []string{guestExportBufferDestroy}

	module := wazerotest.NewModule(guest.memory, realloc, slowest, clearProfiling, bufferPtr, bufferLen, bufferDestroy)
	client := &guestClient{
		ctx:     t.Context(),
		guest:   module,
		realloc: module.ExportedFunction("cabi_realloc"),
		exports: map[string]api.Function{},
	}

	return &Scanner{
		client: client,
		handle: 77,
	}, guest
}

func (g *testProfilingGuest) alloc(size, align uint32) uint32 {
	if align == 0 {
		align = 1
	}
	if size == 0 {
		size = 1
	}
	mask := align - 1
	ptr := (g.nextPtr + mask) &^ mask
	g.nextPtr = ptr + size
	return ptr
}

func (g *testProfilingGuest) addBuffer(t *testing.T, data []byte) uint32 {
	t.Helper()

	dataLen := mustTestU32FromLen(t, len(data), "profiling buffer length")
	ptr := g.alloc(dataLen, 1)
	if len(data) > 0 {
		require.True(t, g.memory.Write(ptr, data))
	}
	handle := g.nextHandle
	g.nextHandle++
	g.buffers[handle] = testProfilingBuffer{
		ptr:    ptr,
		length: dataLen,
	}
	return handle
}

func packTestCallResult(code int32, payload uint32) uint64 {
	codeBits := *(*uint32)(unsafe.Pointer(&code))
	return (uint64(codeBits) << 32) | uint64(payload)
}

func TestScanner1(t *testing.T) {
	r, _ := Compile("rule t { condition: true }")
	s := NewScanner(r)
	scanResults, _ := s.Scan([]byte{})
	matchingRules := scanResults.MatchingRules()

	assert.Len(t, matchingRules, 1)
	assert.Equal(t, "t", matchingRules[0].Identifier())
	assert.Equal(t, "default", matchingRules[0].Namespace())
	assert.Len(t, matchingRules[0].Patterns(), 0)

	scanResults, _ = s.Scan(nil)
	matchingRules = scanResults.MatchingRules()

	assert.Len(t, matchingRules, 1)
	assert.Equal(t, "t", matchingRules[0].Identifier())
	assert.Equal(t, "default", matchingRules[0].Namespace())
	assert.Len(t, matchingRules[0].Patterns(), 0)
}

func TestScanner2(t *testing.T) {
	r, _ := Compile(`rule t { strings: $bar = "bar" condition: $bar }`)
	s := NewScanner(r)
	scanResults, _ := s.Scan([]byte("foobar"))
	matchingRules := scanResults.MatchingRules()

	assert.Len(t, matchingRules, 1)
	assert.Equal(t, "t", matchingRules[0].Identifier())
	assert.Equal(t, "default", matchingRules[0].Namespace())

	assert.Len(t, matchingRules[0].Patterns(), 1)
	assert.Equal(t, "$bar", matchingRules[0].Patterns()[0].Identifier())
	assert.Equal(t, uint64(3), matchingRules[0].Patterns()[0].Matches()[0].Offset())
	assert.Equal(t, uint64(3), matchingRules[0].Patterns()[0].Matches()[0].Length())

	s.Destroy()
	runtime.GC()
}

func TestScanResultsPreserveStaticRuleData(t *testing.T) {
	r, err := Compile(`rule t : tag_a tag_b {
		meta:
			some_int = 7
			some_string = "hello"
		strings:
			$a = "foo"
			$b = "bar"
		condition:
			$a and not $b
	}`)
	if !assert.NoError(t, err) {
		return
	}
	defer r.Destroy()

	scanners := map[string]func(*Scanner) (*ScanResults, error){
		"scan": func(s *Scanner) (*ScanResults, error) {
			return s.Scan([]byte("foo"))
		},
		"scan_reader": func(s *Scanner) (*ScanResults, error) {
			return s.ScanReader(bytes.NewBufferString("foo"))
		},
	}

	for name, run := range scanners {
		t.Run(name, func(t *testing.T) {
			s := NewScanner(r)
			defer s.Destroy()

			results, err := run(s)
			assert.NoError(t, err)
			if !assert.Len(t, results.MatchingRules(), 1) {
				return
			}

			rule := results.MatchingRules()[0]
			assert.Equal(t, "default", rule.Namespace())
			assert.Equal(t, "t", rule.Identifier())
			assert.Equal(t, []string{"tag_a", "tag_b"}, rule.Tags())

			metadata := rule.Metadata()
			if assert.Len(t, metadata, 2) {
				assert.Equal(t, "some_int", metadata[0].Identifier())
				assert.Equal(t, int64(7), metadata[0].Value())
				assert.Equal(t, "some_string", metadata[1].Identifier())
				assert.Equal(t, "hello", metadata[1].Value())
			}

			patterns := rule.Patterns()
			if assert.Len(t, patterns, 2) {
				assert.Equal(t, "$a", patterns[0].Identifier())
				if assert.Len(t, patterns[0].Matches(), 1) {
					assert.Equal(t, uint64(0), patterns[0].Matches()[0].Offset())
					assert.Equal(t, uint64(3), patterns[0].Matches()[0].Length())
				}

				assert.Equal(t, "$b", patterns[1].Identifier())
				assert.Empty(t, patterns[1].Matches())
			}
		})
	}
}

func TestScanner3(t *testing.T) {
	r, _ := Compile(
		`rule t { condition: var_bool }`,
		Globals(map[string]any{"var_bool": true}))

	s := NewScanner(r)
	scanResults, _ := s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	assert.NoError(t, s.SetGlobal("var_bool", false))
	scanResults, _ = s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 0)
}

func TestScanner4(t *testing.T) {
	r, _ := Compile(
		`rule t { condition: var_int == 1}`,
		Globals(map[string]any{"var_int": 0}))

	s := NewScanner(r)
	scanResults, _ := s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 0)

	assert.NoError(t, s.SetGlobal("var_int", 1))
	scanResults, _ = s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	assert.NoError(t, s.SetGlobal("var_int", int32(1)))
	scanResults, _ = s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	assert.NoError(t, s.SetGlobal("var_int", int64(1)))
	scanResults, _ = s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)
}

func TestScanFile(t *testing.T) {
	r, _ := Compile(`rule t { strings: $bar = "bar" condition: $bar }`)
	s := NewScanner(r)

	// Create a temporary file with some content
	f, err := os.CreateTemp(t.TempDir(), "example")
	assert.NoError(t, err)

	_, err = f.WriteString("foobar")
	assert.NoError(t, err)
	f.Close()

	scanResults, _ := s.ScanFile(f.Name())
	matchingRules := scanResults.MatchingRules()
	assert.Len(t, matchingRules, 1)
}

func TestScanReader(t *testing.T) {
	r, err := Compile(`rule t { strings: $bar = "bar" condition: $bar }`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	scanResults, err := s.ScanReader(bytes.NewBufferString("foobar"))
	assert.NoError(t, err)
	assert.Len(t, scanResults.MatchingRules(), 1)

	scanResults, err = s.Scan([]byte("foobar"))
	assert.NoError(t, err)
	assert.Len(t, scanResults.MatchingRules(), 1)
}

func TestRulesScanReader(t *testing.T) {
	r, err := Compile(`rule t { strings: $foo = "foo" condition: $foo }`)
	assert.NoError(t, err)
	defer r.Destroy()

	results, err := r.ScanReader(bytes.NewBufferString("foo"))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)
}

func TestScanReaderAt(t *testing.T) {
	r, err := Compile(`rule t { strings: $bar = "bar" condition: $bar }`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	scanResults, err := s.ScanReaderAt(bytes.NewReader([]byte("foobar")), int64(len("foobar")))
	assert.NoError(t, err)
	assert.Len(t, scanResults.MatchingRules(), 1)
}

func TestRulesScanReaderAt(t *testing.T) {
	r, err := Compile(`rule t { strings: $foo = "foo" condition: $foo }`)
	assert.NoError(t, err)
	defer r.Destroy()

	results, err := r.ScanReaderAt(bytes.NewReader([]byte("foo")), int64(len("foo")))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)
}

func TestScanReaderAtRejectsNegativeSize(t *testing.T) {
	r, err := Compile(`rule t { condition: true }`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	results, err := s.ScanReaderAt(bytes.NewReader(nil), -1)
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestScanReaderGlobals(t *testing.T) {
	r, err := Compile(
		`rule t { condition: var_bool }`,
		Globals(map[string]any{"var_bool": false}),
	)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	assert.NoError(t, s.SetGlobal("var_bool", true))

	results, err := s.ScanReader(bytes.NewBufferString("ignored"))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)
}

func TestScanReaderGlobalsAllSupportedTypes(t *testing.T) {
	r, err := Compile(
		`rule t_string { condition: var_string == "foo" }
		 rule t_float { condition: var_float == 1.5 }
		 rule t_map { condition: var_map.answer == 42 }
		 rule t_array { condition: var_array[0] == "x" }`,
		Globals(map[string]any{
			"var_string": "",
			"var_float":  0.0,
			"var_map":    map[string]any{"answer": 0},
			"var_array":  []any{"y"},
		}),
	)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	assert.NoError(t, s.SetGlobal("var_string", "foo"))
	assert.NoError(t, s.SetGlobal("var_float", float32(1.5)))
	assert.NoError(t, s.SetGlobal("var_map", map[string]any{"answer": 42}))
	assert.NoError(t, s.SetGlobal("var_array", []any{"x"}))

	results, err := s.ScanReader(bytes.NewBuffer(nil))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 4)
}

func TestTimeoutToGuestNanosPreservesSubSecondDurations(t *testing.T) {
	assert.EqualValues(t, (250 * time.Millisecond).Nanoseconds(), timeoutToGuestNanos(250*time.Millisecond))
	assert.EqualValues(t, (time.Second + 250*time.Millisecond).Nanoseconds(), timeoutToGuestNanos(time.Second+250*time.Millisecond))
	assert.Equal(t, uint64(0), timeoutToGuestNanos(0))
}

func TestScannerTimeout(t *testing.T) {
	r, _ := Compile("rule t { strings: $a = /a(.*)*a/ condition: $a }")
	s := NewScanner(r)
	s.SetTimeout(time.Nanosecond)
	_, err := s.Scan(bytes.Repeat([]byte("a"), 10000))
	assert.ErrorIs(t, err, ErrTimeout)
}

func TestScannerTimeoutDoesNotShortCircuitFastScans(t *testing.T) {
	r, _ := Compile(`rule t { condition: true }`)
	s := NewScanner(r)
	s.SetTimeout(time.Second)

	results, err := s.Scan([]byte{})
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)
}

func TestScanReaderTimeout(t *testing.T) {
	r, _ := Compile("rule t { strings: $a = /a(.*)*a/ condition: $a }")
	s := NewScanner(r)
	s.SetTimeout(time.Nanosecond)
	_, err := s.ScanReader(bytes.NewReader(bytes.Repeat([]byte("a"), 10000)))
	assert.ErrorIs(t, err, ErrTimeout)
}

func TestScanFileTimeoutDoesNotMaskErrors(t *testing.T) {
	r, _ := Compile(`rule t { condition: true }`)
	s := NewScanner(r)
	s.SetTimeout(time.Second)

	results, err := s.ScanFile("/definitely/missing/file")
	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrTimeout)
	assert.Empty(t, results.MatchingRules())
}

func TestScanReaderRejectsImportedModules(t *testing.T) {
	r, err := Compile(`
		import "pe"
		rule t { condition: true }
	`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	results, err := s.ScanReader(bytes.NewBuffer(nil))
	assert.ErrorIs(t, err, errScanReaderModulesUnsupported)
	assert.Empty(t, results.MatchingRules())
}

func TestScannerSetModuleOutputUnknownModule(t *testing.T) {
	r, err := Compile(`rule t { condition: true }`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	err = s.SetModuleOutput(&emptypb.Empty{})
	assert.Error(t, err)
	assert.ErrorContains(t, err, "unknown module")
}

func TestScannerProfilingAPIs(t *testing.T) {
	r, err := Compile(`rule t { strings: $a = "foo" condition: $a }`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	results, err := s.Scan([]byte("foo"))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)

	var slowest []ProfilingInfo
	slowestPanic := captureScannerPanic(func() {
		slowest = s.SlowestRules(1)
	})
	if os.Getenv("YARAX_REQUIRE_PROFILING") != "" {
		assert.Nil(t, slowestPanic)
	}
	if slowestPanic != nil {
		assert.Contains(t, fmt.Sprint(slowestPanic), "requires that the YARA-X guest is built with rules profiling support")
	} else {
		assert.LessOrEqual(t, len(slowest), 1)
	}

	clearPanic := captureScannerPanic(func() {
		s.ClearProfilingData()
	})
	if os.Getenv("YARAX_REQUIRE_PROFILING") != "" {
		assert.Nil(t, clearPanic)
	}
	if clearPanic != nil {
		assert.Contains(t, fmt.Sprint(clearPanic), "requires that the YARA-X guest is built with rules profiling support")
	}
}

func TestScannerProfilingEnabledWithOverride(t *testing.T) {
	if os.Getenv("YARAX_REQUIRE_PROFILING") == "" {
		t.Skip("set YARAX_REQUIRE_PROFILING=1 with YARAX_GUEST_WASM pointing to a profiling guest")
	}

	r, err := Compile(`
		rule slow {
			condition:
				for any i in (0..1000000) : (
					uint8(i) == 0xCC
				)
		}
	`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	for range 8 {
		results, err := s.Scan([]byte("foobar"))
		assert.NoError(t, err)
		assert.Empty(t, results.MatchingRules())
	}

	slowest := s.SlowestRules(10)
	if len(slowest) > 0 {
		assert.Equal(t, "default", slowest[0].Namespace)
		assert.Equal(t, "slow", slowest[0].Rule)
		assert.GreaterOrEqual(t, slowest[0].ConditionExecTime, time.Duration(0))
		assert.GreaterOrEqual(t, slowest[0].PatternMatchingTime, time.Duration(0))
	}

	s.ClearProfilingData()
	assert.NotPanics(t, func() { _ = s.SlowestRules(10) })
}

func TestScannerProfilingHelpersWithFakeGuest(t *testing.T) {
	t.Run("decodes profiling json and frees the buffer", func(t *testing.T) {
		s, guest := newTestProfilingScanner(t)
		payload, err := json.Marshal(profilingInfoJSONList{{
			Namespace:           "default",
			Rule:                "slow",
			PatternMatchingTime: 0.25,
			ConditionExecTime:   0.5,
		}})
		require.NoError(t, err)
		handle := guest.addBuffer(t, payload)

		guest.slowest = func(scannerHandle, count uint64) uint64 {
			assert.Equal(t, uint64(s.handle), scannerHandle)
			assert.Equal(t, uint64(1), count)
			return packTestCallResult(yrxSuccess, handle)
		}

		slowest := s.SlowestRules(1)
		require.Len(t, slowest, 1)
		assert.Equal(t, "default", slowest[0].Namespace)
		assert.Equal(t, "slow", slowest[0].Rule)
		assert.Equal(t, 250*time.Millisecond, slowest[0].PatternMatchingTime)
		assert.Equal(t, 500*time.Millisecond, slowest[0].ConditionExecTime)
		_, ok := guest.buffers[handle]
		assert.False(t, ok)
	})

	t.Run("clear profiling data succeeds", func(t *testing.T) {
		s, guest := newTestProfilingScanner(t)
		guest.clear = func(scannerHandle uint64) uint64 {
			assert.Equal(t, uint64(s.handle), scannerHandle)
			return packTestCallResult(yrxSuccess, 0)
		}

		assert.NotPanics(t, func() { s.ClearProfilingData() })
	})
}

func TestScannerProfilingHelpersErrorPaths(t *testing.T) {
	t.Run("rejects counts larger than uint32", func(t *testing.T) {
		s := &Scanner{}
		message := captureScannerPanic(func() {
			s.SlowestRules(int(uint64(math.MaxUint32) + 1))
		})
		require.NotNil(t, message)
		assert.Contains(t, fmt.Sprint(message), "slowest-rules count")
	})

	t.Run("slowest rules reports unsupported profiling guest", func(t *testing.T) {
		s, guest := newTestProfilingScanner(t)
		guest.slowest = func(_, _ uint64) uint64 {
			return packTestCallResult(yrxNotSupported, 0)
		}

		message := captureScannerPanic(func() {
			_ = s.SlowestRules(1)
		})
		require.NotNil(t, message)
		assert.Contains(t, fmt.Sprint(message), "requires that the YARA-X guest is built with rules profiling support")
	})

	t.Run("slowest rules surfaces guest errors", func(t *testing.T) {
		s, guest := newTestProfilingScanner(t)
		guest.slowest = func(_, _ uint64) uint64 {
			return packTestCallResult(yrxInvalidState, guest.addBuffer(t, []byte("profiling boom")))
		}

		message := captureScannerPanic(func() {
			_ = s.SlowestRules(1)
		})
		require.NotNil(t, message)
		assert.Contains(t, fmt.Sprint(message), "profiling boom")
	})

	t.Run("clear profiling data reports unsupported guest", func(t *testing.T) {
		s, guest := newTestProfilingScanner(t)
		guest.clear = func(uint64) uint64 {
			return packTestCallResult(yrxNotSupported, 0)
		}

		message := captureScannerPanic(func() {
			s.ClearProfilingData()
		})
		require.NotNil(t, message)
		assert.Contains(t, fmt.Sprint(message), "requires that the YARA-X guest is built with rules profiling support")
	})

	t.Run("clear profiling data surfaces guest errors", func(t *testing.T) {
		s, guest := newTestProfilingScanner(t)
		guest.clear = func(uint64) uint64 {
			return packTestCallResult(yrxInvalidState, guest.addBuffer(t, []byte("clear boom")))
		}

		message := captureScannerPanic(func() {
			s.ClearProfilingData()
		})
		require.NotNil(t, message)
		assert.Contains(t, fmt.Sprint(message), "clear boom")
	})
}

func captureScannerPanic(fn func()) (message any) {
	defer func() {
		if r := recover(); r != nil {
			message = r
		}
	}()
	fn()
	return
}

func TestRulesAndResultZeroValueAPIs(t *testing.T) {
	var rules *Rules
	assert.Equal(t, 0, rules.Count())
	assert.Empty(t, rules.Imports())
	assert.Empty(t, rules.Slice())

	_, err := rules.WriteTo(bytes.NewBuffer(nil))
	assert.EqualError(t, err, "rules object is destroyed")

	var rule *Rule
	assert.Empty(t, rule.Tags())
	assert.Empty(t, rule.Metadata())
	assert.Empty(t, rule.Patterns())

	var pattern *Pattern
	assert.Empty(t, pattern.Matches())
}

func TestCallbackArgsDoNotLeakGuestMemory(t *testing.T) {
	r, err := Compile(`rule t { strings: $a = "foo" condition: $a }`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	for range 128 {
		results, err := s.Scan([]byte("foo"))
		assert.NoError(t, err)
		assert.Len(t, results.MatchingRules(), 1)
	}

	sizeAfterWarmup := s.client.guest.Memory().Size()

	for range 2048 {
		results, err := s.Scan([]byte("foo"))
		assert.NoError(t, err)
		assert.Len(t, results.MatchingRules(), 1)
	}

	sizeAfterPhaseOne := s.client.guest.Memory().Size()

	for range 2048 {
		results, err := s.Scan([]byte("foo"))
		assert.NoError(t, err)
		assert.Len(t, results.MatchingRules(), 1)
	}

	sizeAfterPhaseTwo := s.client.guest.Memory().Size()

	assert.GreaterOrEqual(t, sizeAfterPhaseOne, sizeAfterWarmup)
	assert.Equal(t, sizeAfterPhaseOne, sizeAfterPhaseTwo)
}

func TestScannerScanReusesGuestBuffer(t *testing.T) {
	r, err := Compile(`rule t { condition: true }`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	results, err := s.Scan(bytes.Repeat([]byte("a"), 16))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)

	firstPtr := s.scanBufPtr
	firstCap := s.scanBufCap
	assert.NotZero(t, firstPtr)
	assert.GreaterOrEqual(t, firstCap, uint32(16))

	results, err = s.Scan(bytes.Repeat([]byte("b"), 8))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)
	assert.Equal(t, firstPtr, s.scanBufPtr)
	assert.Equal(t, firstCap, s.scanBufCap)

	growLen := int(firstCap) + 1
	results, err = s.Scan(bytes.Repeat([]byte("c"), growLen))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)
	assert.GreaterOrEqual(t, int64(s.scanBufCap), int64(growLen))

	sizeAfterGrow := s.client.guest.Memory().Size()
	for range 128 {
		results, err = s.Scan(bytes.Repeat([]byte("d"), growLen-1))
		assert.NoError(t, err)
		assert.Len(t, results.MatchingRules(), 1)
	}
	assert.Equal(t, sizeAfterGrow, s.client.guest.Memory().Size())
}

func TestScannerWriteReusableGuestStringReusesBuffer(t *testing.T) {
	r, err := Compile(`rule t { condition: true }`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	ptr, length, err := s.writeReusableGuestString(&s.pathBufPtr, &s.pathBufCap, "alpha")
	assert.NoError(t, err)
	assert.Equal(t, uint32(5), length)

	firstCap := s.pathBufCap

	ptr2, length2, err := s.writeReusableGuestString(&s.pathBufPtr, &s.pathBufCap, "beta")
	assert.NoError(t, err)
	assert.Equal(t, ptr, ptr2)
	assert.Equal(t, firstCap, s.pathBufCap)
	assert.Equal(t, uint32(4), length2)

	s.client.mu.Lock()
	view, ok := s.client.memory().Read(ptr2, length2)
	got := append([]byte(nil), view...)
	s.client.mu.Unlock()
	assert.True(t, ok)
	assert.Equal(t, "beta", string(got))
}

func TestScannerScanFileReusesHostBuffer(t *testing.T) {
	r, err := Compile(`rule t { condition: true }`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	writeTempFile := func(content []byte) string {
		path := t.TempDir() + "/scan.bin"
		assert.NoError(t, os.WriteFile(path, content, 0o600))
		return path
	}

	results, err := s.ScanFile(writeTempFile(bytes.Repeat([]byte("a"), 32)))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)

	firstCap := cap(s.fileBuf)
	assert.GreaterOrEqual(t, firstCap, 32)

	results, err = s.ScanFile(writeTempFile(bytes.Repeat([]byte("b"), 8)))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)
	assert.Equal(t, firstCap, cap(s.fileBuf))

	results, err = s.ScanFile(writeTempFile(bytes.Repeat([]byte("c"), firstCap+1)))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)
	assert.GreaterOrEqual(t, cap(s.fileBuf), firstCap+1)

	capAfterGrow := cap(s.fileBuf)
	results, err = s.ScanFile(writeTempFile(bytes.Repeat([]byte("d"), 4)))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)
	assert.Equal(t, capAfterGrow, cap(s.fileBuf))
}

func TestScannerMetadata(t *testing.T) {
	r, _ := Compile(`rule t {
				meta:
					some_int = 1
				some_float = 2.3034
				some_bool = true
				some_string = "hello"
				some_bytes = "\x00\x01\x02"
			condition:
				true
	}`)
	s := NewScanner(r)
	scanResults, _ := s.Scan([]byte{})
	matchingRules := scanResults.MatchingRules()

	assert.Len(t, matchingRules, 1)
	assert.Equal(t, "some_int", matchingRules[0].Metadata()[0].Identifier())
	assert.Equal(t, int64(1), matchingRules[0].Metadata()[0].Value())
	assert.Equal(t, "some_float", matchingRules[0].Metadata()[1].Identifier())
	assert.Equal(t, float64(2.3034), matchingRules[0].Metadata()[1].Value())
	assert.Equal(t, "some_bool", matchingRules[0].Metadata()[2].Identifier())
	assert.Equal(t, true, matchingRules[0].Metadata()[2].Value())
	assert.Equal(t, "some_string", matchingRules[0].Metadata()[3].Identifier())
	assert.Equal(t, "hello", matchingRules[0].Metadata()[3].Value())
	assert.Equal(t, "some_bytes", matchingRules[0].Metadata()[4].Identifier())
	assert.Equal(t, []byte{0, 1, 2}, matchingRules[0].Metadata()[4].Value())
}

func BenchmarkScan(b *testing.B) {
	rules, _ := Compile(`rule t {
		strings:
			$foo = "foo"
			$bar = "bar"
			$baz = "baz"
			$a = "a"
			$b = "b"
			$c = "c"
            $d = "d"
		condition: any of them
	}`)
	scanner := NewScanner(rules)
	for range b.N {
		results, _ := scanner.Scan([]byte("foo"))
		for _, rule := range results.MatchingRules() {
			_ = rule.Identifier()
		}
	}
}

func BenchmarkNewScanner(b *testing.B) {
	rules, _ := Compile(`rule t { strings: $foo = "foo" condition: $foo }`)
	b.ResetTimer()

	for range b.N {
		scanner := NewScanner(rules)
		scanner.Destroy()
	}
}

func BenchmarkRulesScan(b *testing.B) {
	rules, _ := Compile(`rule t { strings: $foo = "foo" condition: $foo }`)
	data := []byte("foo")
	b.ResetTimer()

	for range b.N {
		results, _ := rules.Scan(data)
		for _, rule := range results.MatchingRules() {
			_ = rule.Identifier()
		}
	}
}

func BenchmarkReadFrom(b *testing.B) {
	rules, _ := Compile(`rule t { condition: true }`)

	var buf bytes.Buffer
	_, _ = rules.WriteTo(&buf)
	serialized := buf.Bytes()

	b.ResetTimer()

	for range b.N {
		loaded, _ := ReadFrom(bytes.NewReader(serialized))
		loaded.Destroy()
	}
}
