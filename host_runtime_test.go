package yaraxwasm

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental/wazerotest"
)

func writeGuestTestBytes(t *testing.T, client *guestClient, data []byte) (uint32, uint32) {
	t.Helper()

	ptr, length, err := client.allocAndWrite(data)
	require.NoError(t, err)
	t.Cleanup(func() {
		client.free(ptr, length, 1)
	})
	return ptr, length
}

func mustTestU32FromLen(t *testing.T, length int, name string) uint32 {
	t.Helper()

	value, err := u32FromLen(length, name)
	require.NoError(t, err)
	return value
}

func mustTestU32FromUint64(t *testing.T, value uint64, name string) uint32 {
	t.Helper()

	narrowed, err := u32FromUint64(value, name)
	require.NoError(t, err)
	return narrowed
}

const testStackI32UpperBits = uint64(0xA5A5A5A5) << 32

func stackI32Arg(value uint32) uint64 {
	return testStackI32UpperBits | uint64(value)
}

func writeGuestTestString(t *testing.T, client *guestClient, value string) (uint32, uint32) {
	t.Helper()
	return writeGuestTestBytes(t, client, []byte(value))
}

func allocGuestResultArea(t *testing.T, client *guestClient, size uint32) uint32 {
	t.Helper()

	ptr, err := client.alloc(size, 8)
	require.NoError(t, err)
	t.Cleanup(func() {
		client.free(ptr, size, 8)
	})
	return ptr
}

func buildTestImportedFunctionModule(
	t *testing.T,
	moduleName string,
	importName string,
	params []api.ValueType,
	results []api.ValueType,
) []byte {
	t.Helper()

	wasm := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}

	typePayload := appendU32(nil, 1)
	typePayload = append(typePayload, 0x60)
	typePayload = appendU32(typePayload, mustTestU32FromLen(t, len(params), "test params length"))
	for _, param := range params {
		typePayload = append(typePayload, byte(param))
	}
	typePayload = appendU32(typePayload, mustTestU32FromLen(t, len(results), "test results length"))
	for _, result := range results {
		typePayload = append(typePayload, byte(result))
	}

	var err error
	wasm, err = appendSection(wasm, 1, typePayload)
	require.NoError(t, err)

	importPayload := appendU32(nil, 1)
	importPayload, err = appendName(importPayload, moduleName)
	require.NoError(t, err)
	importPayload, err = appendName(importPayload, importName)
	require.NoError(t, err)
	importPayload = append(importPayload, 0x00)
	importPayload = appendU32(importPayload, 0)

	wasm, err = appendSection(wasm, 2, importPayload)
	require.NoError(t, err)

	return wasm
}

func buildTestConstI64Module(t *testing.T, exportName string, value int64) []byte {
	t.Helper()

	wasm := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}

	typePayload := appendU32(nil, 1)
	typePayload = append(typePayload, 0x60)
	typePayload = appendU32(typePayload, 0)
	typePayload = appendU32(typePayload, 1)
	typePayload = append(typePayload, byte(api.ValueTypeI64))

	var err error
	wasm, err = appendSection(wasm, 1, typePayload)
	require.NoError(t, err)

	functionPayload := appendU32(nil, 1)
	functionPayload = appendU32(functionPayload, 0)
	wasm, err = appendSection(wasm, 3, functionPayload)
	require.NoError(t, err)

	exportPayload := appendU32(nil, 1)
	exportPayload, err = appendName(exportPayload, exportName)
	require.NoError(t, err)
	exportPayload = append(exportPayload, 0x00)
	exportPayload = appendU32(exportPayload, 0)
	wasm, err = appendSection(wasm, 7, exportPayload)
	require.NoError(t, err)

	body := []byte{0x00, 0x42}
	body = appendI64(body, value)
	body = append(body, 0x0b)

	codePayload := appendU32(nil, 1)
	codePayload = appendU32(codePayload, mustTestU32FromLen(t, len(body), "test wasm body length"))
	codePayload = append(codePayload, body...)
	wasm, err = appendSection(wasm, 10, codePayload)
	require.NoError(t, err)

	return wasm
}

func buildTestImportedMemoryModule(t *testing.T, moduleName string, importName string, minPages uint32) []byte {
	t.Helper()

	wasm := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}

	importPayload := appendU32(nil, 1)
	var err error
	importPayload, err = appendName(importPayload, moduleName)
	require.NoError(t, err)
	importPayload, err = appendName(importPayload, importName)
	require.NoError(t, err)
	importPayload = append(importPayload, 0x02)
	importPayload = append(importPayload, 0x00)
	importPayload = appendU32(importPayload, minPages)

	wasm, err = appendSection(wasm, 2, importPayload)
	require.NoError(t, err)
	return wasm
}

func writeExternImportsForTest(t *testing.T, client *guestClient, imports []externImport) (uint32, uint32) {
	t.Helper()

	if len(imports) == 0 {
		return 0, 0
	}

	record := make([]byte, 32*len(imports))
	for i, imp := range imports {
		offset := i * 32
		modulePtr, moduleLen := writeGuestTestString(t, client, imp.module)
		namePtr, nameLen := writeGuestTestString(t, client, imp.name)
		binary.LittleEndian.PutUint32(record[offset+0:offset+4], modulePtr)
		binary.LittleEndian.PutUint32(record[offset+4:offset+8], moduleLen)
		binary.LittleEndian.PutUint32(record[offset+8:offset+12], namePtr)
		binary.LittleEndian.PutUint32(record[offset+12:offset+16], nameLen)
		switch imp.kind {
		case externKindGlobal:
			record[offset+16] = 0
		case externKindMemory:
			record[offset+16] = 1
		default:
			t.Fatalf("unexpected extern kind %v", imp.kind)
		}
		binary.LittleEndian.PutUint64(record[offset+24:offset+32], imp.handle)
	}

	ptr, _ := writeGuestTestBytes(t, client, record)
	return ptr, mustTestU32FromLen(t, len(imports), "extern import count")
}

func newTestHostRuntime(t *testing.T) (*hostRuntime, context.Context, wazero.Runtime) {
	t.Helper()

	ctx := t.Context()
	rt := wazero.NewRuntimeWithConfig(ctx, runtimeConfig())
	t.Cleanup(func() {
		require.NoError(t, rt.Close(context.WithoutCancel(ctx)))
	})

	return newHostRuntime(rt), ctx, rt
}

func registerTestSession(t *testing.T, h *hostRuntime, sessionID uint64, session *hostSessionState) {
	t.Helper()

	h.sessionsMu.Lock()
	h.sessions[sessionID] = session
	h.sessionsMu.Unlock()

	t.Cleanup(func() {
		require.NoError(t, h.destroySession(context.WithoutCancel(t.Context()), sessionID))
	})
}

func readUnitResultMessageForTest(t *testing.T, mem api.Memory, retPtr uint32) (bool, string) {
	t.Helper()

	tag, ok := mem.ReadUint32Le(retPtr)
	require.True(t, ok)
	if tag == 0 {
		return true, ""
	}
	ptr, ok := mem.ReadUint32Le(retPtr + 4)
	require.True(t, ok)
	length, ok := mem.ReadUint32Le(retPtr + 8)
	require.True(t, ok)
	msg, err := readString(mem, ptr, length)
	require.NoError(t, err)
	return false, msg
}

func readU64ResultMessageForTest(t *testing.T, mem api.Memory, retPtr uint32) (uint64, string, bool) {
	t.Helper()

	tag, ok := mem.ReadUint32Le(retPtr)
	require.True(t, ok)
	if tag == 0 {
		value, ok := mem.ReadUint64Le(retPtr + 8)
		require.True(t, ok)
		return value, "", true
	}
	ptr, ok := mem.ReadUint32Le(retPtr + 8)
	require.True(t, ok)
	length, ok := mem.ReadUint32Le(retPtr + 12)
	require.True(t, ok)
	msg, err := readString(mem, ptr, length)
	require.NoError(t, err)
	return 0, msg, false
}

func readListResultForTest(t *testing.T, mem api.Memory, retPtr uint32) ([]byte, bool, string) {
	t.Helper()

	tag, ok := mem.ReadUint32Le(retPtr)
	require.True(t, ok)
	ptr, ok := mem.ReadUint32Le(retPtr + 4)
	require.True(t, ok)
	length, ok := mem.ReadUint32Le(retPtr + 8)
	require.True(t, ok)
	if tag != 0 {
		msg, err := readString(mem, ptr, length)
		require.NoError(t, err)
		return nil, false, msg
	}
	data, err := readBytes(mem, ptr, length)
	require.NoError(t, err)
	return data, true, ""
}

func newTestReallocModule(
	exportName string,
	memory *wazerotest.Memory,
	impl func(stack []uint64),
) (*wazerotest.Module, api.Function) {
	realloc := &wazerotest.Function{
		ParamTypes:  []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
		ResultTypes: []api.ValueType{api.ValueTypeI32},
		ExportNames: []string{exportName},
		GoModuleFunction: api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			impl(stack)
		}),
	}
	module := wazerotest.NewModule(memory, realloc)
	return module, module.ExportedFunction(exportName)
}

func readU64ListResultForTest(t *testing.T, mem api.Memory, retPtr uint32) ([]uint64, bool, string) {
	t.Helper()

	tag, ok := mem.ReadUint32Le(retPtr)
	require.True(t, ok)
	ptr, ok := mem.ReadUint32Le(retPtr + 4)
	require.True(t, ok)
	length, ok := mem.ReadUint32Le(retPtr + 8)
	require.True(t, ok)
	if tag != 0 {
		msg, err := readString(mem, ptr, length)
		require.NoError(t, err)
		return nil, false, msg
	}
	rawLen, err := checkedMul8(length)
	require.NoError(t, err)
	data, err := readBytes(mem, ptr, rawLen)
	require.NoError(t, err)
	return decodeU64ListForTest(t, data), true, ""
}

func encodeU64ListForTest(values ...uint64) []byte {
	buf := make([]byte, len(values)*8)
	for i, value := range values {
		binary.LittleEndian.PutUint64(buf[i*8:], value)
	}
	return buf
}

func decodeU64ListForTest(t *testing.T, data []byte) []uint64 {
	t.Helper()

	require.Zero(t, len(data)%8)
	out := make([]uint64, len(data)/8)
	for i := range out {
		out[i] = binary.LittleEndian.Uint64(data[i*8:])
	}
	return out
}

type fakeCallbackGuest struct {
	module       *wazerotest.Module
	memory       *wazerotest.Memory
	nextPtr      uint32
	postCalls    int
	reallocCalls int
	freeCalls    int
}

type errorFunction struct {
	*wazerotest.Function
	err error
}

func newErrorFunction(name string, err error) *errorFunction {
	return &errorFunction{
		Function: &wazerotest.Function{
			ParamTypes:       []api.ValueType{},
			ResultTypes:      []api.ValueType{},
			ExportNames:      []string{name},
			GoModuleFunction: api.GoModuleFunc(func(context.Context, api.Module, []uint64) {}),
		},
		err: err,
	}
}

func (f *errorFunction) Call(context.Context, ...uint64) ([]uint64, error) {
	return nil, f.err
}

func (f *errorFunction) CallWithStack(context.Context, []uint64) error {
	return f.err
}

func newFakeCallbackGuest(
	callback func(sessionID, callbackID uint64, args []uint64) ([]uint64, error),
) *fakeCallbackGuest {
	guest := &fakeCallbackGuest{
		memory:  wazerotest.NewFixedMemory(64 * 1024),
		nextPtr: 1024,
	}

	alloc := func(size, align uint32) uint32 {
		if align == 0 {
			align = 1
		}
		if size == 0 {
			size = 1
		}
		mask := align - 1
		ptr := (guest.nextPtr + mask) &^ mask
		guest.nextPtr = ptr + size
		return ptr
	}

	realloc := &wazerotest.Function{
		ParamTypes:  []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
		ResultTypes: []api.ValueType{api.ValueTypeI32},
		ExportNames: []string{"cabi_realloc"},
		GoModuleFunction: api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			ptr, _ := u32FromUint64(stack[0], "fake guest realloc ptr")
			size, _ := u32FromUint64(stack[3], "fake guest realloc size")
			align, _ := u32FromUint64(stack[2], "fake guest realloc align")
			if size == 0 {
				if ptr != 0 {
					guest.freeCalls++
				}
				stack[0] = 0
				return
			}
			guest.reallocCalls++
			stack[0] = uint64(alloc(size, align))
		}),
	}

	invoke := &wazerotest.Function{
		ParamTypes:  []api.ValueType{api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI64},
		ResultTypes: []api.ValueType{api.ValueTypeI32},
		ExportNames: []string{"yara:runtime/callbacks#invoke-callback"},
		GoModuleFunction: api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			sessionID := stack[0]
			callbackID := stack[1]
			argsPtr, _ := u32FromUint64(stack[2], "fake callback args ptr")
			argsLen, _ := u32FromUint64(stack[3], "fake callback args len")

			args := make([]uint64, argsLen)
			for i := range args {
				index, _ := u32FromLen(i, "fake callback arg index")
				value, ok := guest.memory.ReadUint64Le(argsPtr + index*8)
				if !ok {
					panic("failed to read fake callback arg")
				}
				args[i] = value
			}

			values, err := callback(sessionID, callbackID, args)
			retArea := alloc(12, 4)
			if err != nil {
				msg := []byte(err.Error())
				msgLen, convErr := u32FromLen(len(msg), "fake callback error length")
				if convErr != nil {
					panic(convErr)
				}
				msgPtr := alloc(msgLen, 1)
				_ = guest.memory.Write(msgPtr, msg)
				_ = guest.memory.WriteByte(retArea, 1)
				_ = guest.memory.WriteUint32Le(retArea+4, msgPtr)
				_ = guest.memory.WriteUint32Le(retArea+8, msgLen)
				stack[0] = uint64(retArea)
				return
			}

			valueCount, convErr := u32FromLen(len(values), "fake callback result count")
			if convErr != nil {
				panic(convErr)
			}
			valuesByteLen, convErr := checkedMul8(valueCount)
			if convErr != nil {
				panic(convErr)
			}
			valuesPtr := alloc(valuesByteLen, 8)
			for i, value := range values {
				index, _ := u32FromLen(i, "fake callback result index")
				_ = guest.memory.WriteUint64Le(valuesPtr+index*8, value)
			}
			_ = guest.memory.WriteByte(retArea, 0)
			_ = guest.memory.WriteUint32Le(retArea+4, valuesPtr)
			_ = guest.memory.WriteUint32Le(retArea+8, valueCount)
			stack[0] = uint64(retArea)
		}),
	}

	post := &wazerotest.Function{
		ParamTypes:  []api.ValueType{api.ValueTypeI32},
		ResultTypes: []api.ValueType{},
		ExportNames: []string{"cabi_post_yara:runtime/callbacks#invoke-callback"},
		GoModuleFunction: api.GoModuleFunc(func(_ context.Context, _ api.Module, _ []uint64) {
			guest.postCalls++
		}),
	}

	guest.module = wazerotest.NewModule(guest.memory, realloc, invoke, post)
	guest.module.ModuleName = "fake-guest"
	return guest
}

func registerTestGuest(t *testing.T, h *hostRuntime, guestID uint64, guest *fakeCallbackGuest) {
	t.Helper()

	realloc := guest.module.ExportedFunction("cabi_realloc")
	require.NotNil(t, realloc)
	h.registerGuest(guestID, guest.module, realloc)
	t.Cleanup(func() {
		h.unregisterGuest(guestID)
	})
}

func mustLookupScanDataIntegerImportForTest(t *testing.T, importName string) *scanDataIntegerImport {
	t.Helper()

	spec := lookupScanDataIntegerImport(
		"yara_x::wasm",
		importName,
		0,
		[]api.ValueType{api.ValueTypeI64},
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI32},
	)
	require.NotNil(t, spec)
	return spec
}

type flushRecorder struct {
	bytes.Buffer
	flushes  int
	flushErr error
}

func (w *flushRecorder) Flush() error {
	w.flushes++
	return w.flushErr
}

type errorWriter struct {
	calls int
	err   error
}

func (w *errorWriter) Write(_ []byte) (int, error) {
	w.calls++
	return 0, w.err
}

type flushOnlyRecorder struct {
	bytes.Buffer
	flushes int
}

func (w *flushOnlyRecorder) Flush() {
	w.flushes++
}

type failAfterWriter struct {
	bytes.Buffer
	calls  int
	failOn int
	err    error
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == w.failOn {
		return 0, w.err
	}
	return w.Buffer.Write(p)
}

type mutableTestGlobal struct {
	*wazerotest.Global
	setCalls int
}

func (g *mutableTestGlobal) Set(value uint64) {
	g.Value = value
	g.setCalls++
}

func captureHostRuntimePanic(fn func()) (message any) {
	defer func() {
		if r := recover(); r != nil {
			message = r
		}
	}()
	fn()
	return
}

type errorReallocFunction struct {
	*wazerotest.Function
	err error
}

func newErrorReallocFunction(err error) *errorReallocFunction {
	return &errorReallocFunction{
		Function: &wazerotest.Function{
			ParamTypes:       []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
			ResultTypes:      []api.ValueType{api.ValueTypeI32},
			ExportNames:      []string{"cabi_realloc"},
			GoModuleFunction: api.GoModuleFunc(func(context.Context, api.Module, []uint64) {}),
		},
		err: err,
	}
}

func (f *errorReallocFunction) Call(context.Context, ...uint64) ([]uint64, error) {
	return nil, f.err
}

func (f *errorReallocFunction) CallWithStack(context.Context, []uint64) error {
	return f.err
}

func TestParseFunctionImportsIncludesSyncFlags(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	modulePtr, moduleLen := writeGuestTestString(t, client, "env")
	namePtr, nameLen := writeGuestTestString(t, client, "lookup")
	modulePtr2, moduleLen2 := writeGuestTestString(t, client, "math")
	namePtr2, nameLen2 := writeGuestTestString(t, client, "abs")

	record := make([]byte, 48*2)
	binary.LittleEndian.PutUint32(record[0:4], modulePtr)
	binary.LittleEndian.PutUint32(record[4:8], moduleLen)
	binary.LittleEndian.PutUint32(record[8:12], namePtr)
	binary.LittleEndian.PutUint32(record[12:16], nameLen)
	binary.LittleEndian.PutUint64(record[32:40], 17)
	binary.LittleEndian.PutUint32(record[40:44], callbackSyncBefore)

	offset := 48
	binary.LittleEndian.PutUint32(record[offset+0:offset+4], modulePtr2)
	binary.LittleEndian.PutUint32(record[offset+4:offset+8], moduleLen2)
	binary.LittleEndian.PutUint32(record[offset+8:offset+12], namePtr2)
	binary.LittleEndian.PutUint32(record[offset+12:offset+16], nameLen2)
	binary.LittleEndian.PutUint64(record[offset+32:offset+40], 29)
	binary.LittleEndian.PutUint32(record[offset+40:offset+44], callbackSyncBefore|callbackSyncAfter)

	recordPtr, _ := writeGuestTestBytes(t, client, record)

	imports, err := parseFunctionImports(client.memory(), recordPtr, 2)
	require.NoError(t, err)
	assert.Equal(t, []functionImport{
		{module: "env", name: "lookup", callbackID: 17, syncFlags: callbackSyncBefore},
		{module: "math", name: "abs", callbackID: 29, syncFlags: callbackSyncBefore | callbackSyncAfter},
	}, imports)
}

func TestHostRuntimeHelperEncodersAndInitExprs(t *testing.T) {
	assert.Equal(t, int64(0x7fff), signExtendUint16(0x7fff))
	assert.Equal(t, int64(-1), signExtendUint16(0xffff))
	assert.Equal(t, int64(0x7fffffff), signExtendUint32(0x7fffffff))
	assert.Equal(t, int64(-1), signExtendUint32(0xffffffff))

	assert.Equal(t, byte(0x7e), valTypeToWasmByte(valTypeI64))
	assert.Equal(t, byte(0x7f), valTypeToWasmByte(valTypeI32))
	assert.Equal(t, byte(0x7c), valTypeToWasmByte(valTypeF64Bits))
	assert.Equal(t, byte(0x7d), valTypeToWasmByte(valTypeF32Bits))
	assert.Equal(t, byte(0x7f), valTypeToWasmByte(valType(99)))

	i32Expr, err := buildInitExpr(valTypeI32, 5)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x41, 0x05, 0x0b}, i32Expr)

	i64Expr, err := buildInitExpr(valTypeI64, 7)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x42, 0x07, 0x0b}, i64Expr)

	f32Expr, err := buildInitExpr(valTypeF32Bits, 0x3f800000)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x43, 0x00, 0x00, 0x80, 0x3f, 0x0b}, f32Expr)

	f64Expr, err := buildInitExpr(valTypeF64Bits, 0x3ff0000000000000)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f, 0x0b}, f64Expr)

	_, err = buildInitExpr(valTypeI32, 1<<32)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "i32 init expression")

	_, err = buildInitExpr(valType(99), 0)
	require.EqualError(t, err, "unsupported val-type 99")
}

func TestBuildExternModuleRejectsInvalidSpecs(t *testing.T) {
	_, err := buildExternModule(&externModuleSpec{name: "env"})
	require.EqualError(t, err, `extern module "env" has no exports`)

	_, err = buildExternModule(&externModuleSpec{
		name: "env",
		global: []externGlobalSpec{{
			name:  "bad",
			state: &globalState{typ: valType(99)},
		}},
	})
	require.EqualError(t, err, "unsupported val-type 99")
}

func TestParseFunctionImportsRejectsOutOfBoundsRecord(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	memSize := client.memory().Size()
	require.Greater(t, memSize, uint32(24))

	_, err = parseFunctionImports(client.memory(), memSize-24, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out-of-bounds function import record 0")
}

func TestParseExternImportsParsesKindsAndRejectsUnknownTag(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	modulePtr, moduleLen := writeGuestTestString(t, client, "env")
	namePtr, nameLen := writeGuestTestString(t, client, "counter")
	modulePtr2, moduleLen2 := writeGuestTestString(t, client, "env")
	namePtr2, nameLen2 := writeGuestTestString(t, client, "memory")

	record := make([]byte, 32*2)
	binary.LittleEndian.PutUint32(record[0:4], modulePtr)
	binary.LittleEndian.PutUint32(record[4:8], moduleLen)
	binary.LittleEndian.PutUint32(record[8:12], namePtr)
	binary.LittleEndian.PutUint32(record[12:16], nameLen)
	record[16] = 0
	binary.LittleEndian.PutUint64(record[24:32], 41)

	offset := 32
	binary.LittleEndian.PutUint32(record[offset+0:offset+4], modulePtr2)
	binary.LittleEndian.PutUint32(record[offset+4:offset+8], moduleLen2)
	binary.LittleEndian.PutUint32(record[offset+8:offset+12], namePtr2)
	binary.LittleEndian.PutUint32(record[offset+12:offset+16], nameLen2)
	record[offset+16] = 1
	binary.LittleEndian.PutUint64(record[offset+24:offset+32], 42)

	recordPtr, _ := writeGuestTestBytes(t, client, record)

	imports, err := parseExternImports(client.memory(), recordPtr, 2)
	require.NoError(t, err)
	assert.Equal(t, []externImport{
		{module: "env", name: "counter", kind: externKindGlobal, handle: 41},
		{module: "env", name: "memory", kind: externKindMemory, handle: 42},
	}, imports)

	record[offset+16] = 9
	invalidPtr, _ := writeGuestTestBytes(t, client, record)

	_, err = parseExternImports(client.memory(), invalidPtr, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "extern import 1 has unknown kind tag 9")
}

func TestReadBytesReturnsDetachedCopy(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	ptr, length := writeGuestTestBytes(t, client, []byte("abc"))

	data, err := readBytes(client.memory(), ptr, length)
	require.NoError(t, err)

	require.True(t, client.memory().Write(ptr, []byte("xyz")))
	assert.Equal(t, []byte("abc"), data)
}

func TestReadStringZeroLengthAndOutOfBounds(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	ptr, length := writeGuestTestBytes(t, client, []byte("abc"))

	value, err := readString(client.memory(), ptr, length)
	require.NoError(t, err)
	assert.Equal(t, "abc", value)

	value, err = readString(client.memory(), 0, 0)
	require.NoError(t, err)
	assert.Equal(t, "", value)

	_, err = readString(client.memory(), client.memory().Size()-1, 4)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out-of-bounds read")
}

func TestGuestClientCloseUnregistersGuest(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)

	guestID := client.guestID
	_, err = client.program.host.guest(guestID)
	require.NoError(t, err)

	client.close()
	client.close()

	_, err = client.program.host.guest(guestID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown guest instance")
	assert.Zero(t, client.guestID)
	assert.Nil(t, client.guest)
	assert.Nil(t, client.realloc)
	assert.Nil(t, client.exports)
}

func TestConsoleWriteMessageWritesFlushesAndCapturesErrors(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	guestID := client.guestID

	t.Run("writes newline and flushes", func(t *testing.T) {
		writer := &flushRecorder{}
		h.setGuestConsoleOutput(guestID, writer)

		ptr, length := writeGuestTestBytes(t, client, []byte("hello"))
		h.consoleWriteMessage(client.ctx, client.guest, []uint64{guestID, uint64(ptr), uint64(length)})

		assert.Equal(t, "hello\n", writer.String())
		assert.Equal(t, 1, writer.flushes)
		assert.NoError(t, h.takeGuestConsoleError(guestID))
	})

	t.Run("out of bounds read is recorded", func(t *testing.T) {
		writer := &flushRecorder{}
		h.setGuestConsoleOutput(guestID, writer)

		memSize := client.memory().Size()
		h.consoleWriteMessage(client.ctx, client.guest, []uint64{guestID, uint64(memSize - 1), 8})

		err := h.takeGuestConsoleError(guestID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "out-of-bounds read")
		assert.Empty(t, writer.String())
	})

	t.Run("writer error blocks later writes until reset", func(t *testing.T) {
		writer := &errorWriter{err: errors.New("console boom")}
		h.setGuestConsoleOutput(guestID, writer)

		ptr, length := writeGuestTestBytes(t, client, []byte("hello"))
		h.consoleWriteMessage(client.ctx, client.guest, []uint64{guestID, uint64(ptr), uint64(length)})
		h.consoleWriteMessage(client.ctx, client.guest, []uint64{guestID, uint64(ptr), uint64(length)})

		assert.Equal(t, 1, writer.calls)
		err := h.takeGuestConsoleError(guestID)
		require.EqualError(t, err, "console boom")

		h.resetGuestConsoleError(guestID)
		h.setGuestConsoleOutput(guestID, nil)
		assert.NoError(t, h.takeGuestConsoleError(guestID))
	})

	t.Run("nil console ignores messages", func(t *testing.T) {
		h.setGuestConsoleOutput(guestID, nil)
		ptr, length := writeGuestTestBytes(t, client, []byte("hello"))
		h.consoleWriteMessage(client.ctx, client.guest, []uint64{guestID, uint64(ptr), uint64(length)})
		assert.NoError(t, h.takeGuestConsoleError(guestID))
	})

	t.Run("newline write error is recorded", func(t *testing.T) {
		writer := &failAfterWriter{failOn: 2, err: errors.New("newline boom")}
		h.setGuestConsoleOutput(guestID, writer)

		ptr, length := writeGuestTestBytes(t, client, []byte("hello"))
		h.consoleWriteMessage(client.ctx, client.guest, []uint64{guestID, uint64(ptr), uint64(length)})

		err := h.takeGuestConsoleError(guestID)
		require.EqualError(t, err, "newline boom")
		assert.Equal(t, "hello", writer.String())
	})

	t.Run("flush without error return is supported", func(t *testing.T) {
		writer := &flushOnlyRecorder{}
		h.setGuestConsoleOutput(guestID, writer)

		ptr, length := writeGuestTestBytes(t, client, []byte("hello"))
		h.consoleWriteMessage(client.ctx, client.guest, []uint64{guestID, uint64(ptr), uint64(length)})

		assert.Equal(t, "hello\n", writer.String())
		assert.Equal(t, 1, writer.flushes)
		assert.NoError(t, h.takeGuestConsoleError(guestID))
	})
}

func TestScanBytesLifecycle(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	guest, err := h.guest(client.guestID)
	require.NoError(t, err)

	ptr, length := writeGuestTestBytes(t, client, []byte("scan-bytes"))
	h.beginScanBytes(client.ctx, client.guest, []uint64{client.guestID, stackI32Arg(ptr), stackI32Arg(length)})

	activePtr, activeLen, ok := guest.activeScanData()
	require.True(t, ok)
	assert.Equal(t, ptr, activePtr)
	assert.Equal(t, length, activeLen)

	h.endScanBytes(client.ctx, client.guest, []uint64{client.guestID})
	_, _, ok = guest.activeScanData()
	assert.False(t, ok)
}

func TestScanBytesPanicPaths(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host

	message := captureHostRuntimePanic(func() {
		h.beginScanBytes(client.ctx, client.guest, []uint64{client.guestID + 999, 1, 1})
	})
	require.NotNil(t, message)
	assert.Contains(t, message.(error).Error(), "unknown guest instance")

	message = captureHostRuntimePanic(func() {
		h.endScanBytes(client.ctx, client.guest, []uint64{client.guestID + 999})
	})
	require.NotNil(t, message)
	assert.Contains(t, message.(error).Error(), "unknown guest instance")
}

func TestHostRuntimeGlobalLifecycle(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(7001)
	registerTestSession(t, h, sessionID, newHostSessionState())

	retPtr := allocGuestResultArea(t, client, 16)

	h.globalNew(client.ctx, client.guest, []uint64{sessionID, uint64(valTypeI64), 1, 7, uint64(retPtr)})
	globalID, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)

	h.globalGet(client.ctx, client.guest, []uint64{sessionID, globalID, 0, uint64(retPtr)})
	value, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	assert.Equal(t, uint64(7), value)

	h.globalSet(client.ctx, client.guest, []uint64{sessionID, globalID, 0, 11, uint64(retPtr)})
	okResult, msg := readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, okResult, msg)

	h.globalGet(client.ctx, client.guest, []uint64{sessionID, globalID, 0, uint64(retPtr)})
	value, msg, ok = readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	assert.Equal(t, uint64(11), value)

	h.globalNew(client.ctx, client.guest, []uint64{sessionID, uint64(valTypeI64), 0, 5, uint64(retPtr)})
	immutableID, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)

	h.globalSet(client.ctx, client.guest, []uint64{sessionID, immutableID, 0, 9, uint64(retPtr)})
	okResult, msg = readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.False(t, okResult)
	assert.Contains(t, msg, "immutable")
}

func TestHostRuntimeGlobalGetSetErrorCasesAndNoRevisionChange(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(7005)
	session := newHostSessionState()
	registerTestSession(t, h, sessionID, session)

	retPtr := allocGuestResultArea(t, client, 16)

	h.globalGet(client.ctx, client.guest, []uint64{sessionID, 999, 0, uint64(retPtr)})
	_, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.False(t, ok)
	assert.Contains(t, msg, "unknown global handle 999")

	h.globalSet(client.ctx, client.guest, []uint64{sessionID, 999, 0, 1, uint64(retPtr)})
	ok, msg = readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.False(t, ok)
	assert.Contains(t, msg, "unknown global handle 999")

	h.globalNew(client.ctx, client.guest, []uint64{sessionID, uint64(valTypeI64), 1, 5, uint64(retPtr)})
	globalID, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	require.Equal(t, uint64(0), session.globals[globalID].revision)

	h.globalSet(client.ctx, client.guest, []uint64{sessionID, globalID, 0, 5, uint64(retPtr)})
	ok, msg = readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	assert.Equal(t, uint64(0), session.globals[globalID].revision)
}

func TestHostRuntimeGlobalAndMemoryCreationEdgeCases(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(7004)
	session := newHostSessionState()
	registerTestSession(t, h, sessionID, session)

	retPtr := allocGuestResultArea(t, client, 16)

	h.globalNew(client.ctx, client.guest, []uint64{sessionID, 99, 1, 7, uint64(retPtr)})
	_, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.False(t, ok)
	assert.Contains(t, msg, "unsupported val-type 99")

	h.memoryNew(client.ctx, client.guest, []uint64{sessionID, stackI32Arg(2), stackI32Arg(0), stackI32Arg(99), stackI32Arg(retPtr)})
	memoryID, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	require.NotNil(t, session.memories[memoryID])
	assert.Nil(t, session.memories[memoryID].maximum)
	assert.Len(t, session.memories[memoryID].data, 2*pageSize)

	h.memoryNew(client.ctx, client.guest, []uint64{sessionID, stackI32Arg(1), stackI32Arg(1), stackI32Arg(3), stackI32Arg(retPtr)})
	boundedID, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	require.NotNil(t, session.memories[boundedID].maximum)
	assert.Equal(t, uint32(3), *session.memories[boundedID].maximum)
}

func TestHostRuntimeMemoryNewValidationErrors(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	retPtr := allocGuestResultArea(t, client, 16)

	tests := []struct {
		name  string
		stack []uint64
		want  string
	}{
		{
			name:  "zero session",
			stack: []uint64{0, 1, 0, 0, uint64(retPtr)},
			want:  "invalid zero session id",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h.memoryNew(client.ctx, client.guest, tc.stack)
			_, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
			require.False(t, ok)
			assert.Contains(t, msg, tc.want)
		})
	}
}

func TestHostRuntimeMemoryWriteAndReadDetachFromCallerMemory(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(7002)
	session := newHostSessionState()
	registerTestSession(t, h, sessionID, session)

	retPtr := allocGuestResultArea(t, client, 16)

	h.memoryNew(client.ctx, client.guest, []uint64{sessionID, 1, 1, 1, uint64(retPtr)})
	memoryID, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)

	dataPtr, dataLen := writeGuestTestBytes(t, client, []byte("abc"))
	h.memoryWrite(client.ctx, client.guest, []uint64{sessionID, memoryID, stackI32Arg(dataPtr), stackI32Arg(dataLen), stackI32Arg(retPtr)})
	okResult, msg := readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, okResult, msg)

	require.True(t, client.memory().Write(dataPtr, []byte("xyz")))
	assert.Equal(t, []byte("abc"), session.memories[memoryID].data)

	h.memoryRead(client.ctx, client.guest, []uint64{sessionID, memoryID, uint64(retPtr)})
	data, ok, msg := readListResultForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	assert.Equal(t, []byte("abc"), data)

	session.memories[memoryID].data[0] = 'q'
	assert.Equal(t, []byte("abc"), data)
}

func TestHostRuntimeMemoryReadWriteErrorCasesAndRevisions(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(7003)
	session := newHostSessionState()
	registerTestSession(t, h, sessionID, session)

	retPtr := allocGuestResultArea(t, client, 16)

	h.memoryRead(client.ctx, client.guest, []uint64{0, 1, uint64(retPtr)})
	_, ok, msg := readListResultForTest(t, client.memory(), retPtr)
	require.False(t, ok)
	assert.Contains(t, msg, "invalid zero session id")

	h.memoryRead(client.ctx, client.guest, []uint64{sessionID, 123, uint64(retPtr)})
	_, ok, msg = readListResultForTest(t, client.memory(), retPtr)
	require.False(t, ok)
	assert.Contains(t, msg, "unknown memory handle 123")

	h.memoryNew(client.ctx, client.guest, []uint64{sessionID, 1, 0, 0, uint64(retPtr)})
	memoryID, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)

	memSize := client.memory().Size()
	h.memoryWrite(client.ctx, client.guest, []uint64{sessionID, memoryID, uint64(memSize - 1), 8, uint64(retPtr)})
	ok, msg = readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.False(t, ok)
	assert.Contains(t, msg, "out-of-bounds read")

	dataPtr, dataLen := writeGuestTestBytes(t, client, []byte("same"))
	h.memoryWrite(client.ctx, client.guest, []uint64{sessionID, memoryID, uint64(dataPtr), uint64(dataLen), uint64(retPtr)})
	ok, msg = readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	require.Equal(t, uint64(1), session.memories[memoryID].revision)

	h.memoryWrite(client.ctx, client.guest, []uint64{sessionID, memoryID, uint64(dataPtr), uint64(dataLen), uint64(retPtr)})
	ok, msg = readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	assert.Equal(t, uint64(1), session.memories[memoryID].revision)
}

func TestHostRuntimeMemoryWriteValidationAndZeroLengthClear(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(7007)
	session := newHostSessionState()
	registerTestSession(t, h, sessionID, session)

	retPtr := allocGuestResultArea(t, client, 16)
	h.memoryNew(client.ctx, client.guest, []uint64{sessionID, 1, 0, 0, uint64(retPtr)})
	memoryID, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)

	dataPtr, dataLen := writeGuestTestBytes(t, client, []byte("abc"))
	h.memoryWrite(client.ctx, client.guest, []uint64{sessionID, memoryID, uint64(dataPtr), uint64(dataLen), uint64(retPtr)})
	ok, msg = readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	require.Equal(t, uint64(1), session.memories[memoryID].revision)

	h.memoryWrite(client.ctx, client.guest, []uint64{sessionID, memoryID, 0, 0, uint64(retPtr)})
	ok, msg = readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	assert.Empty(t, session.memories[memoryID].data)
	assert.Equal(t, uint64(2), session.memories[memoryID].revision)

	tests := []struct {
		name  string
		stack []uint64
		want  string
	}{
		{
			name:  "zero session",
			stack: []uint64{0, memoryID, 0, 0, uint64(retPtr)},
			want:  "invalid zero session id",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h.memoryWrite(client.ctx, client.guest, tc.stack)
			ok, msg := readUnitResultMessageForTest(t, client.memory(), retPtr)
			require.False(t, ok)
			assert.Contains(t, msg, tc.want)
		})
	}
}

func TestInstantiateCreatesRunnableInstance(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(9201)
	session := newHostSessionState()
	registerTestSession(t, h, sessionID, session)

	wasm := buildTestConstI64Module(t, "forty_two", 42)
	modulePtr, moduleLen := writeGuestTestBytes(t, client, wasm)
	retPtr := allocGuestResultArea(t, client, 16)

	h.instantiate(client.ctx, client.guest, []uint64{
		sessionID,
		stackI32Arg(modulePtr),
		stackI32Arg(moduleLen),
		0,
		0,
		0,
		0,
		stackI32Arg(retPtr),
	})

	instanceID, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	require.NotNil(t, session.instances[instanceID])

	namePtr, nameLen := writeGuestTestString(t, client, "forty_two")
	resultsPtr, _ := writeGuestTestBytes(t, client, make([]byte, 4))
	h.callExport(client.ctx, client.guest, []uint64{
		sessionID,
		instanceID,
		stackI32Arg(namePtr),
		stackI32Arg(nameLen),
		0,
		0,
		stackI32Arg(resultsPtr),
		stackI32Arg(1),
		noTimeoutNanos,
		stackI32Arg(retPtr),
	})

	values, ok, msg := readU64ListResultForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	assert.Equal(t, []uint64{42}, values)
}

func TestInstantiateReportsSetupErrors(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(9202)
	registerTestSession(t, h, sessionID, newHostSessionState())
	retPtr := allocGuestResultArea(t, client, 16)

	t.Run("unknown session", func(t *testing.T) {
		wasm := buildTestConstI64Module(t, "x", 1)
		modulePtr, moduleLen := writeGuestTestBytes(t, client, wasm)

		h.instantiate(client.ctx, client.guest, []uint64{
			0,
			uint64(modulePtr),
			uint64(moduleLen),
			0,
			0,
			0,
			0,
			uint64(retPtr),
		})

		_, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
		require.False(t, ok)
		assert.Contains(t, msg, "invalid zero session id")
	})

	t.Run("compile error", func(t *testing.T) {
		modulePtr, moduleLen := writeGuestTestBytes(t, client, []byte{0x00, 0x61, 0x73})

		h.instantiate(client.ctx, client.guest, []uint64{
			sessionID,
			uint64(modulePtr),
			uint64(moduleLen),
			0,
			0,
			0,
			0,
			uint64(retPtr),
		})

		_, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
		require.False(t, ok)
		assert.NotEmpty(t, msg)
	})

	t.Run("invalid function import record", func(t *testing.T) {
		wasm := buildTestConstI64Module(t, "x", 1)
		modulePtr, moduleLen := writeGuestTestBytes(t, client, wasm)
		memSize := client.memory().Size()

		h.instantiate(client.ctx, client.guest, []uint64{
			sessionID,
			uint64(modulePtr),
			uint64(moduleLen),
			uint64(memSize - 24),
			1,
			0,
			0,
			uint64(retPtr),
		})

		_, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
		require.False(t, ok)
		assert.Contains(t, msg, "out-of-bounds function import record 0")
	})

	t.Run("missing callback mapping for imported function", func(t *testing.T) {
		wasm := buildTestImportedFunctionModule(t, "env", "lookup", nil, []api.ValueType{api.ValueTypeI64})
		modulePtr, moduleLen := writeGuestTestBytes(t, client, wasm)

		h.instantiate(client.ctx, client.guest, []uint64{
			sessionID,
			uint64(modulePtr),
			uint64(moduleLen),
			0,
			0,
			0,
			0,
			uint64(retPtr),
		})

		_, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
		require.False(t, ok)
		assert.Contains(t, msg, "missing callback mapping for import env.lookup")
	})

	t.Run("unknown extern handle", func(t *testing.T) {
		wasm := buildTestConstI64Module(t, "x", 1)
		modulePtr, moduleLen := writeGuestTestBytes(t, client, wasm)
		externsPtr, externsLen := writeExternImportsForTest(t, client, []externImport{{
			module: "env",
			name:   "counter",
			kind:   externKindGlobal,
			handle: 999,
		}})

		h.instantiate(client.ctx, client.guest, []uint64{
			sessionID,
			uint64(modulePtr),
			uint64(moduleLen),
			0,
			0,
			uint64(externsPtr),
			uint64(externsLen),
			uint64(retPtr),
		})

		_, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
		require.False(t, ok)
		assert.Contains(t, msg, "unknown global handle 999")
	})

	t.Run("final instantiation fails on unresolved memory import", func(t *testing.T) {
		wasm := buildTestImportedMemoryModule(t, "env", "memory", 1)
		modulePtr, moduleLen := writeGuestTestBytes(t, client, wasm)

		h.instantiate(client.ctx, client.guest, []uint64{
			sessionID,
			uint64(modulePtr),
			uint64(moduleLen),
			0,
			0,
			0,
			0,
			uint64(retPtr),
		})

		_, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
		require.False(t, ok)
		assert.NotEmpty(t, msg)
		assert.Contains(t, msg, "env")
	})
}

func TestInstantiateExternModulesAndSyncRoundTrip(t *testing.T) {
	h, ctx, rt := newTestHostRuntime(t)

	maxPages := uint32(1)
	session := newHostSessionState()
	session.globals[1] = &globalState{
		typ:     valTypeI64,
		mutable: true,
		value:   7,
	}
	session.memories[2] = &memoryState{
		initial: 1,
		maximum: &maxPages,
		data:    []byte("abc"),
	}

	instance := &instanceState{
		session:       session,
		externs:       []externImport{{module: "env", name: "counter", kind: externKindGlobal, handle: 1}, {module: "env", name: "memory", kind: externKindMemory, handle: 2}},
		externModules: map[string]api.Module{},
	}

	require.NoError(t, h.instantiateExternModules(ctx, rt, instance.externs, instance))

	mod := instance.externModules["env"]
	require.NotNil(t, mod)
	require.NoError(t, h.syncExternsToModules(instance))

	global := mod.ExportedGlobal("counter")
	require.NotNil(t, global)
	assert.Equal(t, uint64(7), global.Get())

	memory := mod.Memory()
	require.NotNil(t, memory)
	got, ok := memory.Read(0, 3)
	require.True(t, ok)
	assert.Equal(t, []byte("abc"), got)

	mutableGlobal, ok := global.(api.MutableGlobal)
	require.True(t, ok)
	mutableGlobal.Set(11)
	require.True(t, memory.Write(0, []byte("xyz")))

	require.NoError(t, h.syncExternsFromModules(instance))

	assert.Equal(t, uint64(11), session.globals[1].value)
	require.Len(t, session.memories[2].data, int(memory.Size()))
	assert.Equal(t, []byte("xyz"), session.memories[2].data[:3])

	require.True(t, memory.Write(0, []byte("qqq")))
	assert.Equal(t, []byte("xyz"), session.memories[2].data[:3])
}

func TestDestroySessionClosesInstancesAndIsIdempotent(t *testing.T) {
	h, ctx, _ := newTestHostRuntime(t)

	sessionID := uint64(9001)
	session := newHostSessionState()
	instanceRT := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig())
	instance := &instanceState{rt: instanceRT}
	session.instances[5] = instance

	h.sessionsMu.Lock()
	h.sessions[sessionID] = session
	h.sessionsMu.Unlock()

	require.NoError(t, h.destroySession(ctx, sessionID))
	require.NoError(t, h.destroySession(ctx, sessionID))

	h.sessionsMu.RLock()
	_, ok := h.sessions[sessionID]
	h.sessionsMu.RUnlock()
	assert.False(t, ok)
	assert.Nil(t, instance.rt)
	assert.Empty(t, session.instances)
}

func TestInstanceDestroyRemovesInstanceAndReportsUnknownHandle(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(9002)
	session := newHostSessionState()
	registerTestSession(t, h, sessionID, session)

	instanceID := uint64(7)
	instance := &instanceState{
		sessionID:     sessionID,
		session:       session,
		module:        wazerotest.NewModule(nil),
		externModules: map[string]api.Module{},
		exports:       map[string]api.Function{},
	}
	session.instances[instanceID] = instance

	retPtr := allocGuestResultArea(t, client, 12)
	h.instanceDestroy(client.ctx, client.guest, []uint64{sessionID, instanceID, uint64(retPtr)})
	ok, msg := readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	assert.Nil(t, instance.module)
	_, exists := session.instances[instanceID]
	assert.False(t, exists)

	h.instanceDestroy(client.ctx, client.guest, []uint64{sessionID, instanceID, uint64(retPtr)})
	ok, msg = readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.False(t, ok)
	assert.Contains(t, msg, "unknown instance handle")
}

func TestValidateModuleAcceptsValidWASMAndRejectsInvalidBytes(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	retPtr := allocGuestResultArea(t, client, 12)

	wasm, err := buildExternModule(&externModuleSpec{
		name: "env",
		global: []externGlobalSpec{{
			name:  "counter",
			state: &globalState{typ: valTypeI64, mutable: true, value: 1},
		}},
	})
	require.NoError(t, err)

	modulePtr, moduleLen := writeGuestTestBytes(t, client, wasm)
	h.validateModule(client.ctx, client.guest, []uint64{stackI32Arg(modulePtr), stackI32Arg(moduleLen), stackI32Arg(retPtr)})
	ok, msg := readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)

	invalidPtr, invalidLen := writeGuestTestBytes(t, client, []byte{0x00, 0x61, 0x73})
	h.validateModule(client.ctx, client.guest, []uint64{stackI32Arg(invalidPtr), stackI32Arg(invalidLen), stackI32Arg(retPtr)})
	ok, msg = readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.False(t, ok)
	assert.NotEmpty(t, msg)
}

func TestValidateModuleReportsOutOfBoundsRead(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	retPtr := allocGuestResultArea(t, client, 12)
	memSize := client.memory().Size()

	h.validateModule(client.ctx, client.guest, []uint64{uint64(memSize - 1), 8, uint64(retPtr)})
	ok, msg := readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.False(t, ok)
	assert.Contains(t, msg, "out-of-bounds read")
}

func TestValidateModuleUsesLow32BitsFromStack(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	retPtr := allocGuestResultArea(t, client, 12)
	module := buildTestConstI64Module(t, "x", 1)
	modulePtr, moduleLen := writeGuestTestBytes(t, client, module)

	h.validateModule(client.ctx, client.guest, []uint64{stackI32Arg(modulePtr), stackI32Arg(moduleLen), stackI32Arg(retPtr)})
	ok, msg := readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
}

func TestWriteU64ResultErrEncodesMessage(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	retPtr := allocGuestResultArea(t, client, 16)
	h.writeU64ResultErr(client.ctx, client.guest, retPtr, "boom")

	_, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.False(t, ok)
	assert.Equal(t, "boom", msg)
}

func TestCallExportReturnsResultsAndCachesExport(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(9101)
	instanceID := uint64(3)
	session := newHostSessionState()
	registerTestSession(t, h, sessionID, session)

	sum := wazerotest.NewFunction(func(_ context.Context, _ api.Module, left, right uint64) uint64 {
		return left + right
	})
	sum.ExportNames = []string{"sum"}

	instance := &instanceState{
		sessionID:     sessionID,
		session:       session,
		module:        wazerotest.NewModule(nil, sum),
		externModules: map[string]api.Module{},
		exports:       map[string]api.Function{},
	}
	session.instances[instanceID] = instance

	namePtr, nameLen := writeGuestTestString(t, client, "sum")
	paramsPtr, _ := writeGuestTestBytes(t, client, encodeU64ListForTest(20, 22))
	resultsPtr, _ := writeGuestTestBytes(t, client, make([]byte, 4))
	retPtr := allocGuestResultArea(t, client, 12)

	h.callExport(client.ctx, client.guest, []uint64{
		sessionID,
		instanceID,
		stackI32Arg(namePtr),
		stackI32Arg(nameLen),
		stackI32Arg(paramsPtr),
		stackI32Arg(2),
		stackI32Arg(resultsPtr),
		stackI32Arg(1),
		noTimeoutNanos,
		stackI32Arg(retPtr),
	})

	values, ok, msg := readU64ListResultForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	assert.Equal(t, []uint64{42}, values)
	assert.NotNil(t, instance.exports["sum"])
}

func TestCallExportReportsMissingExport(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(9102)
	instanceID := uint64(4)
	session := newHostSessionState()
	registerTestSession(t, h, sessionID, session)

	instance := &instanceState{
		sessionID:     sessionID,
		session:       session,
		module:        wazerotest.NewModule(nil),
		externModules: map[string]api.Module{},
		exports:       map[string]api.Function{},
	}
	session.instances[instanceID] = instance

	namePtr, nameLen := writeGuestTestString(t, client, "missing")
	resultsPtr, _ := writeGuestTestBytes(t, client, make([]byte, 0))
	retPtr := allocGuestResultArea(t, client, 12)

	h.callExport(client.ctx, client.guest, []uint64{
		sessionID,
		instanceID,
		uint64(namePtr),
		uint64(nameLen),
		0,
		0,
		uint64(resultsPtr),
		0,
		noTimeoutNanos,
		uint64(retPtr),
	})

	_, ok, msg := readListResultForTest(t, client.memory(), retPtr)
	require.False(t, ok)
	assert.Contains(t, msg, `missing export "missing"`)
}

func TestCallExportRejectsUnexpectedResultLength(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(9103)
	instanceID := uint64(5)
	session := newHostSessionState()
	registerTestSession(t, h, sessionID, session)

	pair := wazerotest.NewFunction(func(_ context.Context, _ api.Module, value uint64) (uint64, uint64) {
		return value, value + 1
	})
	pair.ExportNames = []string{"pair"}

	instance := &instanceState{
		sessionID:     sessionID,
		session:       session,
		module:        wazerotest.NewModule(nil, pair),
		externModules: map[string]api.Module{},
		exports:       map[string]api.Function{},
	}
	session.instances[instanceID] = instance

	namePtr, nameLen := writeGuestTestString(t, client, "pair")
	paramsPtr, _ := writeGuestTestBytes(t, client, encodeU64ListForTest(7))
	resultsPtr, _ := writeGuestTestBytes(t, client, make([]byte, 4))
	retPtr := allocGuestResultArea(t, client, 12)

	h.callExport(client.ctx, client.guest, []uint64{
		sessionID,
		instanceID,
		uint64(namePtr),
		uint64(nameLen),
		uint64(paramsPtr),
		1,
		uint64(resultsPtr),
		1,
		noTimeoutNanos,
		uint64(retPtr),
	})

	_, ok, msg := readListResultForTest(t, client.memory(), retPtr)
	require.False(t, ok)
	assert.Contains(t, msg, "unexpected result length: got 2 want 1")
}

func TestCallExportPropagatesTimeoutAndOtherErrors(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(9104)
	instanceID := uint64(6)
	session := newHostSessionState()
	registerTestSession(t, h, sessionID, session)

	instance := &instanceState{
		sessionID:     sessionID,
		session:       session,
		module:        wazerotest.NewModule(nil),
		externModules: map[string]api.Module{},
		exports: map[string]api.Function{
			"timeout": newErrorFunction("timeout", errors.New("wrapped "+hostCallTimeoutError+" value")),
			"boom":    newErrorFunction("boom", errors.New("boom")),
		},
	}
	session.instances[instanceID] = instance

	retPtr := allocGuestResultArea(t, client, 12)
	resultsPtr, _ := writeGuestTestBytes(t, client, make([]byte, 0))

	for _, tc := range []struct {
		name    string
		wantMsg string
	}{
		{name: "timeout", wantMsg: hostCallTimeoutError},
		{name: "boom", wantMsg: "boom"},
	} {
		namePtr, nameLen := writeGuestTestString(t, client, tc.name)
		h.callExport(client.ctx, client.guest, []uint64{
			sessionID,
			instanceID,
			uint64(namePtr),
			uint64(nameLen),
			0,
			0,
			uint64(resultsPtr),
			0,
			noTimeoutNanos,
			uint64(retPtr),
		})

		_, ok, msg := readListResultForTest(t, client.memory(), retPtr)
		require.False(t, ok)
		assert.Equal(t, tc.wantMsg, msg)
	}
}

func TestCallExportValidationErrors(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	retPtr := allocGuestResultArea(t, client, 12)

	t.Run("rejects zero session id", func(t *testing.T) {
		h.callExport(client.ctx, client.guest, []uint64{
			0,
			1,
			0,
			0,
			0,
			0,
			0,
			0,
			noTimeoutNanos,
			uint64(retPtr),
		})

		_, ok, msg := readListResultForTest(t, client.memory(), retPtr)
		require.False(t, ok)
		assert.Contains(t, msg, "invalid zero session id")
	})

	t.Run("reports unknown instance handle", func(t *testing.T) {
		sessionID := uint64(9106)
		registerTestSession(t, h, sessionID, newHostSessionState())

		h.callExport(client.ctx, client.guest, []uint64{
			sessionID,
			999,
			0,
			0,
			0,
			0,
			0,
			0,
			noTimeoutNanos,
			uint64(retPtr),
		})

		_, ok, msg := readListResultForTest(t, client.memory(), retPtr)
		require.False(t, ok)
		assert.Contains(t, msg, "unknown instance handle 999")
	})

	t.Run("reports out of bounds results buffer", func(t *testing.T) {
		sessionID := uint64(9107)
		instanceID := uint64(8)
		session := newHostSessionState()
		registerTestSession(t, h, sessionID, session)

		sum := wazerotest.NewFunction(func(_ context.Context, _ api.Module, left, right uint64) uint64 {
			return left + right
		})
		sum.ExportNames = []string{"sum"}

		instance := &instanceState{
			sessionID:     sessionID,
			session:       session,
			module:        wazerotest.NewModule(nil, sum),
			externModules: map[string]api.Module{},
			exports:       map[string]api.Function{},
		}
		session.instances[instanceID] = instance

		namePtr, nameLen := writeGuestTestString(t, client, "sum")
		paramsPtr, _ := writeGuestTestBytes(t, client, encodeU64ListForTest(1, 2))
		memSize := client.memory().Size()

		h.callExport(client.ctx, client.guest, []uint64{
			sessionID,
			instanceID,
			uint64(namePtr),
			uint64(nameLen),
			uint64(paramsPtr),
			2,
			uint64(memSize - 1),
			4,
			noTimeoutNanos,
			uint64(retPtr),
		})

		_, ok, msg := readListResultForTest(t, client.memory(), retPtr)
		require.False(t, ok)
		assert.Contains(t, msg, "out-of-bounds read")
	})

	t.Run("rejects parameter count overflow in byte calculation", func(t *testing.T) {
		sessionID := uint64(9109)
		instanceID := uint64(9)
		session := newHostSessionState()
		registerTestSession(t, h, sessionID, session)

		instance := &instanceState{
			sessionID:     sessionID,
			session:       session,
			module:        wazerotest.NewModule(nil),
			externModules: map[string]api.Module{},
			exports:       map[string]api.Function{},
		}
		session.instances[instanceID] = instance

		namePtr, nameLen := writeGuestTestString(t, client, "missing")

		h.callExport(client.ctx, client.guest, []uint64{
			sessionID,
			instanceID,
			uint64(namePtr),
			uint64(nameLen),
			0,
			uint64(math.MaxUint32/8) + 1,
			0,
			0,
			noTimeoutNanos,
			uint64(retPtr),
		})

		_, ok, msg := readListResultForTest(t, client.memory(), retPtr)
		require.False(t, ok)
		assert.Contains(t, msg, "overflow while computing")
	})

	t.Run("surfaces sync-to-modules failure before export lookup", func(t *testing.T) {
		sessionID := uint64(9110)
		instanceID := uint64(10)
		session := newHostSessionState()
		registerTestSession(t, h, sessionID, session)

		instance := &instanceState{
			sessionID: sessionID,
			session:   session,
			module:    wazerotest.NewModule(nil),
			externBindings: []instanceExternBinding{{
				module: "env",
				name:   "counter",
				kind:   externKindGlobal,
			}},
			externModules: map[string]api.Module{},
			exports:       map[string]api.Function{},
		}
		session.instances[instanceID] = instance

		namePtr, nameLen := writeGuestTestString(t, client, "missing")
		h.callExport(client.ctx, client.guest, []uint64{
			sessionID,
			instanceID,
			uint64(namePtr),
			uint64(nameLen),
			0,
			0,
			0,
			0,
			noTimeoutNanos,
			uint64(retPtr),
		})

		_, ok, msg := readListResultForTest(t, client.memory(), retPtr)
		require.False(t, ok)
		assert.Contains(t, msg, `missing global state for "env"."counter"`)
	})

	t.Run("surfaces sync-from-modules failure after call", func(t *testing.T) {
		sessionID := uint64(9111)
		instanceID := uint64(11)
		session := newHostSessionState()
		registerTestSession(t, h, sessionID, session)

		sum := wazerotest.NewFunction(func(_ context.Context, _ api.Module, left, right uint64) uint64 {
			return left + right
		})
		sum.ExportNames = []string{"sum"}

		instance := &instanceState{
			sessionID: sessionID,
			session:   session,
			module:    wazerotest.NewModule(nil, sum),
			externBindings: []instanceExternBinding{{
				module:             "env",
				name:               "counter",
				kind:               externKindGlobal,
				globalState:        &globalState{revision: 1, value: 7},
				lastSyncedRevision: unsetExternRevision,
			}},
			externModules: map[string]api.Module{},
			exports:       map[string]api.Function{},
		}
		session.instances[instanceID] = instance

		namePtr, nameLen := writeGuestTestString(t, client, "sum")
		paramsPtr, _ := writeGuestTestBytes(t, client, encodeU64ListForTest(2, 3))
		resultsPtr, _ := writeGuestTestBytes(t, client, make([]byte, 4))

		h.callExport(client.ctx, client.guest, []uint64{
			sessionID,
			instanceID,
			uint64(namePtr),
			uint64(nameLen),
			uint64(paramsPtr),
			2,
			uint64(resultsPtr),
			1,
			noTimeoutNanos,
			uint64(retPtr),
		})

		_, ok, msg := readListResultForTest(t, client.memory(), retPtr)
		require.False(t, ok)
		assert.Contains(t, msg, `missing global binding for "env"."counter"`)
	})
}

func TestCallExportRejectsInvalidTimeoutValue(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(9105)
	instanceID := uint64(7)
	session := newHostSessionState()
	registerTestSession(t, h, sessionID, session)

	sum := wazerotest.NewFunction(func(_ context.Context, _ api.Module, left, right uint64) uint64 {
		return left + right
	})
	sum.ExportNames = []string{"sum"}

	instance := &instanceState{
		sessionID:     sessionID,
		session:       session,
		module:        wazerotest.NewModule(nil, sum),
		externModules: map[string]api.Module{},
		exports:       map[string]api.Function{},
	}
	session.instances[instanceID] = instance

	namePtr, nameLen := writeGuestTestString(t, client, "sum")
	paramsPtr, _ := writeGuestTestBytes(t, client, encodeU64ListForTest(20, 22))
	resultsPtr, _ := writeGuestTestBytes(t, client, make([]byte, 4))
	retPtr := allocGuestResultArea(t, client, 12)

	h.callExport(client.ctx, client.guest, []uint64{
		sessionID,
		instanceID,
		uint64(namePtr),
		uint64(nameLen),
		uint64(paramsPtr),
		2,
		uint64(resultsPtr),
		1,
		uint64(math.MaxInt64) + 1,
		uint64(retPtr),
	})

	_, ok, msg := readListResultForTest(t, client.memory(), retPtr)
	require.False(t, ok)
	assert.Contains(t, msg, "call-export timeout")
}

func TestCallGuestCallbackSuccessAndError(t *testing.T) {
	h, ctx, _ := newTestHostRuntime(t)

	var seenSessionID uint64
	var seenCallbackID uint64
	var seenArgs []uint64

	guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
		seenSessionID = sessionID
		seenCallbackID = callbackID
		seenArgs = append([]uint64(nil), args...)
		if callbackID == 9 {
			return nil, errors.New("boom")
		}
		return []uint64{11, 22}, nil
	})
	registerTestGuest(t, h, 41, guest)

	values := make([]uint64, 2)
	err := h.callGuestCallback(ctx, 41, 7, []uint64{3, 5}, values)
	require.NoError(t, err)
	assert.Equal(t, []uint64{11, 22}, values)
	assert.Equal(t, uint64(41), seenSessionID)
	assert.Equal(t, uint64(7), seenCallbackID)
	assert.Equal(t, []uint64{3, 5}, seenArgs)
	assert.Equal(t, 1, guest.postCalls)

	err = h.callGuestCallback(ctx, 41, 9, []uint64{1}, nil)
	require.Error(t, err)
	assert.EqualError(t, err, "boom")
	assert.Equal(t, 2, guest.postCalls)
}

func TestCallGuestCallbackEdgeCases(t *testing.T) {
	t.Run("missing callback export", func(t *testing.T) {
		h := newHostRuntime(nil)
		module, realloc := newTestReallocModule("cabi_realloc", wazerotest.NewFixedMemory(64*1024), func(stack []uint64) {
			stack[0] = 1024
		})
		h.registerGuest(51, module, realloc)
		t.Cleanup(func() { h.unregisterGuest(51) })

		err := h.callGuestCallback(t.Context(), 51, 1, nil, nil)
		require.EqualError(t, err, "guest callback export is missing")
	})

	t.Run("empty callback error gets default message", func(t *testing.T) {
		h, ctx, _ := newTestHostRuntime(t)
		guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
			return nil, errors.New("")
		})
		registerTestGuest(t, h, 52, guest)

		err := h.callGuestCallback(ctx, 52, 1, nil, nil)
		require.EqualError(t, err, "callback returned an empty error")
	})

	t.Run("post cleanup failure is returned", func(t *testing.T) {
		h, ctx, _ := newTestHostRuntime(t)
		guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
			return nil, nil
		})
		registerTestGuest(t, h, 53, guest)

		state, err := h.guest(53)
		require.NoError(t, err)
		state.callbackPost = newErrorFunction("cabi_post_yara:runtime/callbacks#invoke-callback", errors.New("post boom"))

		err = h.callGuestCallback(ctx, 53, 1, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "post-return callback cleanup failed: post boom")
	})
}

func TestCallGuestCallbackDecodingFailures(t *testing.T) {
	t.Run("unexpected callback return arity", func(t *testing.T) {
		h, ctx, _ := newTestHostRuntime(t)
		guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
			return nil, nil
		})
		registerTestGuest(t, h, 54, guest)

		state, err := h.guest(54)
		require.NoError(t, err)
		invoke := &wazerotest.Function{
			ParamTypes:  []api.ValueType{api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI64},
			ResultTypes: []api.ValueType{},
			ExportNames: []string{"yara:runtime/callbacks#invoke-callback"},
		}
		state.callbackInvoke = wazerotest.NewModule(guest.memory, invoke).ExportedFunction("yara:runtime/callbacks#invoke-callback")

		err = h.callGuestCallback(ctx, 54, 1, nil, nil)
		require.EqualError(t, err, "unexpected callback return arity 0")
	})

	t.Run("result pointers use the low 32 bits", func(t *testing.T) {
		h, ctx, _ := newTestHostRuntime(t)
		guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
			return nil, nil
		})
		registerTestGuest(t, h, 56, guest)

		state, err := h.guest(56)
		require.NoError(t, err)

		retArea := uint32(64)
		valuesPtr := uint32(128)
		invoke := wazerotest.NewFunction(func(_ context.Context, _ api.Module, _, _, _, _ uint64) uint64 {
			require.True(t, guest.memory.WriteByte(retArea, 0))
			require.True(t, guest.memory.WriteUint32Le(retArea+4, valuesPtr))
			require.True(t, guest.memory.WriteUint32Le(retArea+8, 1))
			require.True(t, guest.memory.WriteUint64Le(valuesPtr, 99))
			return stackI32Arg(retArea)
		})
		invoke.ExportNames = []string{"yara:runtime/callbacks#invoke-callback"}
		state.callbackInvoke = wazerotest.NewModule(guest.memory, invoke).ExportedFunction("yara:runtime/callbacks#invoke-callback")
		values := make([]uint64, 1)
		err = h.callGuestCallback(ctx, 56, 1, nil, values)
		require.NoError(t, err)
		assert.Equal(t, []uint64{99}, values)

		retArea = guest.memory.Size() - 1
		invoke = wazerotest.NewFunction(func(_ context.Context, _ api.Module, _, _, _, _ uint64) uint64 {
			require.True(t, guest.memory.WriteByte(retArea, 0))
			return uint64(retArea)
		})
		invoke.ExportNames = []string{"yara:runtime/callbacks#invoke-callback"}
		state.callbackInvoke = wazerotest.NewModule(guest.memory, invoke).ExportedFunction("yara:runtime/callbacks#invoke-callback")
		err = h.callGuestCallback(ctx, 56, 1, nil, nil)
		require.EqualError(t, err, "failed to read callback result pointer")
	})

	t.Run("out of bounds result data is returned", func(t *testing.T) {
		h, ctx, _ := newTestHostRuntime(t)
		guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
			return nil, nil
		})
		registerTestGuest(t, h, 57, guest)

		state, err := h.guest(57)
		require.NoError(t, err)
		retArea := uint32(2048)
		invoke := wazerotest.NewFunction(func(_ context.Context, _ api.Module, _, _, _, _ uint64) uint64 {
			require.True(t, guest.memory.WriteByte(retArea, 0))
			require.True(t, guest.memory.WriteUint32Le(retArea+4, guest.memory.Size()-4))
			require.True(t, guest.memory.WriteUint32Le(retArea+8, 1))
			return uint64(retArea)
		})
		invoke.ExportNames = []string{"yara:runtime/callbacks#invoke-callback"}
		state.callbackInvoke = wazerotest.NewModule(guest.memory, invoke).ExportedFunction("yara:runtime/callbacks#invoke-callback")

		err = h.callGuestCallback(ctx, 57, 1, nil, make([]uint64, 1))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "out-of-bounds read")
	})
}

func TestLookupModuleReallocSupportsFallbackExport(t *testing.T) {
	module, fallback := newTestReallocModule("cabi_realloc_wit_bindgen_0_46_0", nil, func(stack []uint64) {
		stack[0] = 64
	})

	realloc, err := lookupModuleRealloc(module)
	require.NoError(t, err)
	assert.Same(t, fallback, realloc)

	_, err = lookupModuleRealloc(wazerotest.NewModule(nil))
	require.EqualError(t, err, "guest allocator export not found")
}

func TestNormalizeImportBaseNameVariants(t *testing.T) {
	tests := []struct {
		moduleName string
		importName string
		want       string
		ok         bool
	}{
		{moduleName: "env", importName: "", want: "", ok: false},
		{moduleName: "env", importName: "lookup", want: "lookup", ok: true},
		{moduleName: "env", importName: "env.lookup@1.0", want: "lookup", ok: true},
		{moduleName: "env", importName: "pkg.lookup", want: "lookup", ok: true},
		{moduleName: "env", importName: "env.", want: "", ok: false},
	}

	for _, tc := range tests {
		got, ok := normalizeImportBaseName(tc.moduleName, tc.importName)
		assert.Equal(t, tc.ok, ok)
		assert.Equal(t, tc.want, got)
	}
}

func TestAllocWithReallocNormalizesZeroSizeAndAlignment(t *testing.T) {
	var got []uint64
	_, realloc := newTestReallocModule("cabi_realloc", nil, func(stack []uint64) {
		got = append([]uint64(nil), stack[:4]...)
		stack[0] = 96
	})

	ptr, err := allocWithRealloc(t.Context(), realloc, 0, 0)
	require.NoError(t, err)
	assert.Equal(t, uint32(96), ptr)
	assert.Equal(t, []uint64{0, 0, 1, 1}, got)
}

func TestAllocWithReallocRejectsUnexpectedResults(t *testing.T) {
	noResult := &wazerotest.Function{
		ParamTypes:  []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
		ResultTypes: []api.ValueType{},
	}

	_, err := allocWithRealloc(t.Context(), noResult, 8, 4)
	require.EqualError(t, err, "unexpected realloc result arity 0")

	_, realloc := newTestReallocModule("cabi_realloc", nil, func(stack []uint64) {
		stack[0] = 0
	})
	_, err = allocWithRealloc(t.Context(), realloc, 8, 4)
	require.EqualError(t, err, "guest allocator returned null pointer")
}

func TestGuestModuleAllocationHelpersRejectInvalidPointersAndWrites(t *testing.T) {
	t.Run("alloc rejects pointers outside uint32", func(t *testing.T) {
		_, realloc := newTestReallocModule("cabi_realloc", nil, func(stack []uint64) {
			stack[0] = uint64(math.MaxUint32) + 1
		})

		guest := &guestModuleState{realloc: realloc}
		_, err := guest.alloc(t.Context(), 8, 4)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "realloc pointer result")
	})

	t.Run("realloc buffer rejects null pointers", func(t *testing.T) {
		_, realloc := newTestReallocModule("cabi_realloc", nil, func(stack []uint64) {
			stack[0] = 0
		})

		guest := &guestModuleState{realloc: realloc}
		_, err := guest.reallocBuffer(t.Context(), 32, 16, 8, 64)
		require.EqualError(t, err, "guest allocator returned null pointer")
	})

	t.Run("module alloc and write reports out of bounds writes", func(t *testing.T) {
		memory := wazerotest.NewFixedMemory(64 * 1024)
		module, _ := newTestReallocModule("cabi_realloc", memory, func(stack []uint64) {
			stack[0] = uint64(memory.Size() - 2)
		})
		h := newHostRuntime(nil)

		_, _, err := h.moduleAllocAndWrite(t.Context(), module, []byte("boom"))
		require.EqualError(t, err, "failed to write 4 bytes to guest memory at 65534")
	})
}

func TestHostRuntimeAllocWithModuleReallocUsesRegisteredGuest(t *testing.T) {
	h := newHostRuntime(nil)
	targetModule := wazerotest.NewModule(wazerotest.NewFixedMemory(64 * 1024))
	guestModule, guestRealloc := newTestReallocModule("cabi_realloc", nil, func(stack []uint64) {
		assert.Equal(t, []uint64{0, 0, 1, 1}, append([]uint64(nil), stack[:4]...))
		stack[0] = 4096
	})
	_ = guestModule

	h.registerGuest(7, targetModule, guestRealloc)
	t.Cleanup(func() { h.unregisterGuest(7) })

	ptr, err := h.allocWithModuleRealloc(t.Context(), targetModule, 0, 0)
	require.NoError(t, err)
	assert.Equal(t, uint32(4096), ptr)
}

func TestHostRuntimeModuleAllocAndWriteUsesModuleRealloc(t *testing.T) {
	memory := wazerotest.NewFixedMemory(64 * 1024)
	module, _ := newTestReallocModule("cabi_realloc", memory, func(stack []uint64) {
		stack[0] = 32
	})
	h := newHostRuntime(nil)

	ptr, length, err := h.moduleAllocAndWrite(t.Context(), module, []byte("yarax"))
	require.NoError(t, err)
	assert.Equal(t, uint32(32), ptr)
	assert.Equal(t, uint32(5), length)

	written, ok := memory.Read(ptr, length)
	require.True(t, ok)
	assert.Equal(t, []byte("yarax"), written)
}

func TestWriteU64ListResultOKEdgeCases(t *testing.T) {
	h := newHostRuntime(nil)
	ctx := t.Context()

	t.Run("writes empty list successfully", func(t *testing.T) {
		memory := wazerotest.NewFixedMemory(64 * 1024)
		module, _ := newTestReallocModule("cabi_realloc", memory, func(stack []uint64) {
			stack[0] = 32
		})

		require.NoError(t, h.writeU64ListResultOK(ctx, module, 8, nil))
		values, ok, msg := readU64ListResultForTest(t, memory, 8)
		require.True(t, ok, msg)
		assert.Empty(t, values)
	})

	t.Run("missing allocator export is returned", func(t *testing.T) {
		module := wazerotest.NewModule(wazerotest.NewFixedMemory(64 * 1024))
		err := h.writeU64ListResultOK(ctx, module, 8, []uint64{1})
		require.EqualError(t, err, "guest allocator export not found")
	})
}

func TestGuestAllocationHelpersPropagateErrors(t *testing.T) {
	guest := &guestModuleState{realloc: newErrorReallocFunction(errors.New("realloc boom"))}

	_, err := guest.alloc(t.Context(), 8, 4)
	require.EqualError(t, err, "realloc boom")

	_, err = guest.reallocBuffer(t.Context(), 32, 16, 8, 64)
	require.EqualError(t, err, "realloc boom")
}

func TestCallGuestCallbackReusesArgsBuffer(t *testing.T) {
	h, ctx, _ := newTestHostRuntime(t)

	guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
		return nil, nil
	})
	registerTestGuest(t, h, 41, guest)

	require.NoError(t, h.callGuestCallback(ctx, 41, 1, []uint64{1, 2}, nil))
	require.NoError(t, h.callGuestCallback(ctx, 41, 2, []uint64{3, 4}, nil))
	assert.Equal(t, 1, guest.reallocCalls)
	assert.Zero(t, guest.freeCalls)

	require.NoError(t, h.callGuestCallback(ctx, 41, 3, []uint64{5, 6, 7}, nil))
	assert.Equal(t, 2, guest.reallocCalls)
	assert.Zero(t, guest.freeCalls)
}

func TestInvokeImportCallbackWritesResultsIntoStack(t *testing.T) {
	h, ctx, _ := newTestHostRuntime(t)

	guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
		return []uint64{args[0] + 10, args[1] + 20}, nil
	})
	registerTestGuest(t, h, 88, guest)

	instance := &instanceState{
		sessionID: 88,
		session:   newHostSessionState(),
	}

	stack := []uint64{3, 5}
	err := h.invokeImportCallback(
		ctx,
		instance,
		2,
		0,
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI64},
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI64},
		stack,
	)
	require.NoError(t, err)
	assert.Equal(t, []uint64{13, 25}, stack[:2])
}

func TestSyncExternsToModulesModeErrorCases(t *testing.T) {
	h := newHostRuntime(nil)

	t.Run("missing global state", func(t *testing.T) {
		instance := &instanceState{
			session: newHostSessionState(),
			externBindings: []instanceExternBinding{{
				module: "env",
				name:   "counter",
				kind:   externKindGlobal,
			}},
		}

		err := h.syncExternsToModulesMode(instance, true)
		require.EqualError(t, err, `missing global state for "env"."counter"`)
	})

	t.Run("skips unchanged globals when not forced", func(t *testing.T) {
		state := &globalState{revision: 5, value: 7}
		global := &mutableTestGlobal{Global: wazerotest.GlobalI64(0)}
		instance := &instanceState{
			session: newHostSessionState(),
			externBindings: []instanceExternBinding{{
				module:             "env",
				name:               "counter",
				kind:               externKindGlobal,
				globalState:        state,
				mutableGlobal:      global,
				lastSyncedRevision: 5,
			}},
		}

		require.NoError(t, h.syncExternsToModulesMode(instance, false))
		assert.Zero(t, global.setCalls)
		assert.Equal(t, uint64(0), global.Get())
	})

	t.Run("missing memory state", func(t *testing.T) {
		instance := &instanceState{
			session: newHostSessionState(),
			externBindings: []instanceExternBinding{{
				module: "env",
				name:   "memory",
				kind:   externKindMemory,
			}},
		}

		err := h.syncExternsToModulesMode(instance, true)
		require.EqualError(t, err, `missing memory state for "env"."memory"`)
	})

	t.Run("missing memory export", func(t *testing.T) {
		instance := &instanceState{
			session: newHostSessionState(),
			externBindings: []instanceExternBinding{{
				module:      "env",
				name:        "memory",
				kind:        externKindMemory,
				memoryState: &memoryState{revision: 1, data: []byte("abc")},
			}},
		}

		err := h.syncExternsToModulesMode(instance, true)
		require.EqualError(t, err, `missing memory export "memory" in module "env"`)
	})

	t.Run("rejects state larger than module memory", func(t *testing.T) {
		instance := &instanceState{
			session: newHostSessionState(),
			externBindings: []instanceExternBinding{{
				module: "env",
				name:   "memory",
				kind:   externKindMemory,
				memoryState: &memoryState{
					revision: 1,
					data:     make([]byte, 65537),
				},
				memory: wazerotest.NewFixedMemory(64 * 1024),
			}},
		}

		err := h.syncExternsToModulesMode(instance, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `memory "env"."memory" is larger than module memory`)
	})
}

func TestServeScanDataIntegerImportValidReads(t *testing.T) {
	h, ctx, _ := newTestHostRuntime(t)

	guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
		return nil, nil
	})
	registerTestGuest(t, h, 91, guest)

	dataPtr := uint32(2048)
	data := []byte{0x01, 0x02, 0x03, 0x04, 0xff, 0xff, 0xff, 0xff}
	require.True(t, guest.memory.Write(dataPtr, data))
	h.beginScanBytes(ctx, guest.module, []uint64{91, uint64(dataPtr), uint64(len(data))})
	t.Cleanup(func() {
		h.endScanBytes(ctx, guest.module, []uint64{91})
	})

	instance := &instanceState{
		sessionID: 91,
		session:   newHostSessionState(),
	}

	for _, tc := range []struct {
		name       string
		importName string
		offset     int64
		want       int64
	}{
		{name: "uint8", importName: "yara_x::wasm.uint8@i@i:R0:255u", offset: 0, want: 1},
		{name: "uint16", importName: "yara_x::wasm.uint16@i@i:R0:65535u", offset: 0, want: 0x0201},
		{name: "uint32", importName: "yara_x::wasm.uint32@i@i:R0:4294967295u", offset: 0, want: 0x04030201},
		{name: "uint16be", importName: "yara_x::wasm.uint16be@i@i:R0:65535u", offset: 0, want: 0x0102},
		{name: "uint32be", importName: "yara_x::wasm.uint32be@i@i:R0:4294967295u", offset: 0, want: 0x01020304},
		{name: "int8", importName: "yara_x::wasm.int8@i@i:R-128:127u", offset: 4, want: -1},
		{name: "int16", importName: "yara_x::wasm.int16@i@i:R-32768:32767u", offset: 4, want: -1},
		{name: "int32", importName: "yara_x::wasm.int32@i@i:R-2147483648:2147483647u", offset: 4, want: -1},
		{name: "int16be", importName: "yara_x::wasm.int16be@i@i:R-32768:32767u", offset: 4, want: -1},
		{name: "int32be", importName: "yara_x::wasm.int32be@i@i:R-2147483648:2147483647u", offset: 4, want: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := mustLookupScanDataIntegerImportForTest(t, tc.importName)
			stack := []uint64{u64FromI64Bits(tc.offset), 0}

			handled, err := h.serveScanDataIntegerImport(instance, *spec, stack)
			require.NoError(t, err)
			require.True(t, handled)
			assert.Equal(t, uint64(0), stack[1])
			assert.Equal(t, tc.want, i64FromBits(stack[0]))
		})
	}
}

func TestServeScanDataIntegerImportUndefinedCases(t *testing.T) {
	h, ctx, _ := newTestHostRuntime(t)

	guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
		return nil, nil
	})
	registerTestGuest(t, h, 92, guest)

	dataPtr := uint32(3072)
	data := []byte{0x01, 0x02, 0x03}
	require.True(t, guest.memory.Write(dataPtr, data))
	h.beginScanBytes(ctx, guest.module, []uint64{92, uint64(dataPtr), uint64(len(data))})
	t.Cleanup(func() {
		h.endScanBytes(ctx, guest.module, []uint64{92})
	})

	instance := &instanceState{
		sessionID: 92,
		session:   newHostSessionState(),
	}

	for _, tc := range []struct {
		name       string
		importName string
		offset     int64
	}{
		{name: "negative offset", importName: "yara_x::wasm.uint16@i@i:R0:65535u", offset: -1},
		{name: "short tail uint16", importName: "yara_x::wasm.uint16@i@i:R0:65535u", offset: 2},
		{name: "short tail uint32", importName: "yara_x::wasm.uint32@i@i:R0:4294967295u", offset: 0},
		{name: "short tail int16be", importName: "yara_x::wasm.int16be@i@i:R-32768:32767u", offset: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := mustLookupScanDataIntegerImportForTest(t, tc.importName)
			stack := []uint64{u64FromI64Bits(tc.offset), 77}

			handled, err := h.serveScanDataIntegerImport(instance, *spec, stack)
			require.NoError(t, err)
			require.True(t, handled)
			assert.Equal(t, uint64(0), stack[0])
			assert.Equal(t, uint64(1), stack[1])
		})
	}
}

func TestInvokeImportUsesScanDataIntegerFastPathAndFallback(t *testing.T) {
	h, ctx, _ := newTestHostRuntime(t)

	callbacks := 0
	guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
		callbacks++
		assert.Equal(t, uint64(93), sessionID)
		assert.Equal(t, uint64(17), callbackID)
		assert.Equal(t, []uint64{u64FromI64Bits(1)}, args)
		return []uint64{u64FromI64Bits(99), 0}, nil
	})
	registerTestGuest(t, h, 93, guest)

	dataPtr := uint32(4096)
	require.True(t, guest.memory.Write(dataPtr, []byte{0xaa, 0xbb, 0xcc, 0xdd}))

	instance := &instanceState{
		sessionID: 93,
		session:   newHostSessionState(),
	}
	spec := mustLookupScanDataIntegerImportForTest(t, "yara_x::wasm.uint16@i@i:R0:65535u")
	paramTypes := []api.ValueType{api.ValueTypeI64}
	resultTypes := []api.ValueType{api.ValueTypeI64, api.ValueTypeI32}

	stack := []uint64{u64FromI64Bits(1), 0}
	err := h.invokeImport(ctx, instance, 17, 0, spec, paramTypes, resultTypes, stack)
	require.NoError(t, err)
	assert.Equal(t, 1, callbacks)
	assert.Equal(t, int64(99), i64FromBits(stack[0]))
	assert.Equal(t, uint64(0), stack[1])

	h.beginScanBytes(ctx, guest.module, []uint64{93, uint64(dataPtr), 4})
	t.Cleanup(func() {
		h.endScanBytes(ctx, guest.module, []uint64{93})
	})

	stack = []uint64{u64FromI64Bits(0), 0}
	err = h.invokeImport(ctx, instance, 17, 0, spec, paramTypes, resultTypes, stack)
	require.NoError(t, err)
	assert.Equal(t, 1, callbacks)
	assert.Equal(t, int64(0xbbaa), i64FromBits(stack[0]))
	assert.Equal(t, uint64(0), stack[1])
}

func TestInvokeImportCallbackSelectiveSync(t *testing.T) {
	t.Run("sync before refreshes session state from extern modules", func(t *testing.T) {
		h, ctx, rt := newTestHostRuntime(t)
		guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
			return nil, nil
		})
		registerTestGuest(t, h, 77, guest)

		maxPages := uint32(1)
		session := newHostSessionState()
		session.globals[1] = &globalState{typ: valTypeI64, mutable: true, value: 3}
		session.memories[2] = &memoryState{initial: 1, maximum: &maxPages, data: []byte("old")}

		instance := &instanceState{
			sessionID:     77,
			session:       session,
			externs:       []externImport{{module: "env", name: "counter", kind: externKindGlobal, handle: 1}, {module: "env", name: "memory", kind: externKindMemory, handle: 2}},
			externModules: map[string]api.Module{},
		}

		require.NoError(t, h.instantiateExternModules(ctx, rt, instance.externs, instance))
		mod := instance.externModules["env"]
		require.NotNil(t, mod)

		global := mod.ExportedGlobal("counter")
		mutableGlobal, ok := global.(api.MutableGlobal)
		require.True(t, ok)
		mutableGlobal.Set(33)
		require.True(t, mod.Memory().Write(0, []byte("new")))

		stack := []uint64{}
		require.NoError(t, h.invokeImportCallback(ctx, instance, 1, callbackSyncBefore, nil, nil, stack))
		assert.Equal(t, uint64(33), session.globals[1].value)
		assert.Equal(t, []byte("new"), session.memories[2].data[:3])
	})

	t.Run("sync after pushes session state into extern modules", func(t *testing.T) {
		h, ctx, rt := newTestHostRuntime(t)
		guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
			return nil, nil
		})
		registerTestGuest(t, h, 77, guest)

		maxPages := uint32(1)
		session := newHostSessionState()
		session.globals[1] = &globalState{typ: valTypeI64, mutable: true, value: 44}
		session.memories[2] = &memoryState{initial: 1, maximum: &maxPages, data: []byte("abc")}

		instance := &instanceState{
			sessionID:     77,
			session:       session,
			externs:       []externImport{{module: "env", name: "counter", kind: externKindGlobal, handle: 1}, {module: "env", name: "memory", kind: externKindMemory, handle: 2}},
			externModules: map[string]api.Module{},
		}

		require.NoError(t, h.instantiateExternModules(ctx, rt, instance.externs, instance))
		mod := instance.externModules["env"]
		require.NotNil(t, mod)

		stack := []uint64{}
		require.NoError(t, h.invokeImportCallback(ctx, instance, 2, callbackSyncAfter, nil, nil, stack))
		assert.Equal(t, uint64(44), mod.ExportedGlobal("counter").Get())
		data, ok := mod.Memory().Read(0, 3)
		require.True(t, ok)
		assert.Equal(t, []byte("abc"), data)
	})
}

func TestInvokeImportCallbackTimeoutAndResultValidation(t *testing.T) {
	h, ctx, _ := newTestHostRuntime(t)

	callCount := 0
	guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
		callCount++
		return []uint64{99}, nil
	})
	registerTestGuest(t, h, 88, guest)

	instance := &instanceState{
		sessionID: 88,
		session:   newHostSessionState(),
	}

	clearDeadline := instance.beginCallDeadline(0)
	err := h.invokeImportCallback(ctx, instance, 1, 0, nil, nil, nil)
	clearDeadline()
	require.Error(t, err)
	assert.EqualError(t, err, hostCallTimeoutError)
	assert.Zero(t, callCount)

	stack := []uint64{0}
	err = h.invokeImportCallback(ctx, instance, 2, 0, nil, []api.ValueType{}, stack)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "returned 1 values, expected 0")
	assert.Equal(t, 1, callCount)
}

func TestInvokeImportCallbackAdditionalErrorPaths(t *testing.T) {
	t.Run("sync before failure is returned before callback", func(t *testing.T) {
		h, ctx, _ := newTestHostRuntime(t)
		callCount := 0
		guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
			callCount++
			return nil, nil
		})
		registerTestGuest(t, h, 94, guest)

		instance := &instanceState{
			sessionID: 94,
			session:   newHostSessionState(),
			externBindings: []instanceExternBinding{{
				module: "env",
				name:   "counter",
				kind:   externKindGlobal,
			}},
		}

		err := h.invokeImportCallback(ctx, instance, 1, callbackSyncBefore, nil, nil, nil)
		require.EqualError(t, err, `missing global binding for "env"."counter"`)
		assert.Zero(t, callCount)
	})

	t.Run("callback error is returned", func(t *testing.T) {
		h, ctx, _ := newTestHostRuntime(t)
		guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
			return nil, errors.New("callback boom")
		})
		registerTestGuest(t, h, 95, guest)

		instance := &instanceState{
			sessionID: 95,
			session:   newHostSessionState(),
		}

		err := h.invokeImportCallback(ctx, instance, 1, 0, nil, nil, nil)
		require.EqualError(t, err, "callback boom")
	})

	t.Run("timeout after callback is returned", func(t *testing.T) {
		h, ctx, _ := newTestHostRuntime(t)
		instance := &instanceState{
			sessionID: 96,
			session:   newHostSessionState(),
		}
		guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
			instance.beginCallDeadline(0)
			return nil, nil
		})
		registerTestGuest(t, h, 96, guest)

		err := h.invokeImportCallback(ctx, instance, 1, 0, nil, nil, nil)
		require.EqualError(t, err, hostCallTimeoutError)
	})

	t.Run("sync after failure is returned", func(t *testing.T) {
		h, ctx, _ := newTestHostRuntime(t)
		guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
			return nil, nil
		})
		registerTestGuest(t, h, 97, guest)

		instance := &instanceState{
			sessionID: 97,
			session:   newHostSessionState(),
			externBindings: []instanceExternBinding{{
				module: "env",
				name:   "memory",
				kind:   externKindMemory,
			}},
		}

		err := h.invokeImportCallback(ctx, instance, 1, callbackSyncAfter, nil, nil, nil)
		require.EqualError(t, err, `missing memory state for "env"."memory"`)
	})
}
