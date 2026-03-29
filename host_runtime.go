package yaraxwasm

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const (
	yaraRuntimeHostModule = "yara:runtime/host"
	goConsoleHostModule   = "go:console/host"
	goScanDataHostModule  = "go:scan-data/host"
	pageSize              = 65536
	hostCallTimeoutError  = "__yarax_timeout__"
	noTimeoutNanos        = ^uint64(0)
	unsetExternRevision   = ^uint64(0)
)

type valType uint32

const (
	valTypeI64 valType = iota
	valTypeI32
	valTypeF64Bits
	valTypeF32Bits
)

type globalState struct {
	typ      valType
	mutable  bool
	value    uint64
	revision uint64
}

type memoryState struct {
	initial  uint32
	maximum  *uint32
	data     []byte
	revision uint64
}

type externKind uint32

const (
	externKindGlobal externKind = iota
	externKindMemory
)

const (
	callbackSyncBefore uint32 = 1 << 0
	callbackSyncAfter  uint32 = 1 << 1
)

type functionImport struct {
	module     string
	name       string
	callbackID uint64
	syncFlags  uint32
}

type externImport struct {
	module string
	name   string
	kind   externKind
	handle uint64
}

type instanceState struct {
	sessionID      uint64
	session        *hostSessionState
	rt             wazero.Runtime
	module         api.Module
	helperModules  []api.Module
	externModules  map[string]api.Module
	externs        []externImport
	externBindings []instanceExternBinding
	exportMu       sync.Mutex
	exports        map[string]api.Function
	deadlineMu     sync.RWMutex
	deadline       time.Time
	hasDeadline    bool
}

type instanceExternBinding struct {
	module             string
	name               string
	kind               externKind
	globalState        *globalState
	memoryState        *memoryState
	global             api.Global
	mutableGlobal      api.MutableGlobal
	memory             api.Memory
	lastSyncedRevision uint64
}

func (i *instanceState) close(ctx context.Context) {
	if i.rt != nil {
		_ = i.rt.Close(ctx)
		i.rt = nil
		return
	}
	if i.module != nil {
		_ = i.module.Close(ctx)
		i.module = nil
	}
}

func (i *instanceState) beginCallDeadline(timeout time.Duration) func() {
	if timeout <= 0 {
		i.deadlineMu.Lock()
		i.deadline = time.Now()
		i.hasDeadline = true
		i.deadlineMu.Unlock()
		return func() {
			i.deadlineMu.Lock()
			i.hasDeadline = false
			i.deadline = time.Time{}
			i.deadlineMu.Unlock()
		}
	}

	i.deadlineMu.Lock()
	i.deadline = time.Now().Add(timeout)
	i.hasDeadline = true
	i.deadlineMu.Unlock()

	return func() {
		i.deadlineMu.Lock()
		i.hasDeadline = false
		i.deadline = time.Time{}
		i.deadlineMu.Unlock()
	}
}

func (i *instanceState) timedOut() bool {
	i.deadlineMu.RLock()
	defer i.deadlineMu.RUnlock()
	return i.hasDeadline && !time.Now().Before(i.deadline)
}

type hostSessionState struct {
	mu         sync.RWMutex
	nextHandle uint64
	globals    map[uint64]*globalState
	memories   map[uint64]*memoryState
	instances  map[uint64]*instanceState
}

type guestModuleState struct {
	module          api.Module
	realloc         api.Function
	callbackInvoke  api.Function
	callbackPost    api.Function
	callbackArgsPtr uint32
	callbackArgsCap uint32
	callStack       []uint64
	reallocMu       sync.Mutex
	reallocStack    []uint64
	mu              sync.Mutex
	scanDataMu      sync.RWMutex
	scanDataPtr     uint32
	scanDataLen     uint32
	hasScanData     bool
	consoleMu       sync.Mutex
	console         io.Writer
	consoleErr      error
}

type scanDataIntegerImport struct {
	name      string
	byteLen   uint32
	signed    bool
	bigEndian bool
}

func signExtendUint16(v uint16) int64 {
	if v&0x8000 != 0 {
		return int64(v) - (1 << 16)
	}
	return int64(v)
}

func signExtendUint32(v uint32) int64 {
	if v&0x80000000 != 0 {
		return int64(v) - (1 << 32)
	}
	return int64(v)
}

func newHostSessionState() *hostSessionState {
	return &hostSessionState{
		globals:   map[uint64]*globalState{},
		memories:  map[uint64]*memoryState{},
		instances: map[uint64]*instanceState{},
	}
}

func (s *hostSessionState) nextID() uint64 {
	s.nextHandle++
	return s.nextHandle
}

type hostRuntime struct {
	rt wazero.Runtime

	guestsMu     sync.RWMutex
	guests       map[uint64]*guestModuleState
	guestModules map[api.Module]*guestModuleState
	sessionsMu   sync.RWMutex
	sessions     map[uint64]*hostSessionState
}

func newHostRuntime(rt wazero.Runtime) *hostRuntime {
	return &hostRuntime{
		rt:           rt,
		guests:       map[uint64]*guestModuleState{},
		guestModules: map[api.Module]*guestModuleState{},
		sessions:     map[uint64]*hostSessionState{},
	}
}

func (h *hostRuntime) registerGuest(
	guestID uint64,
	module api.Module,
	realloc api.Function,
) {
	guest := &guestModuleState{
		module:         module,
		realloc:        realloc,
		callbackInvoke: module.ExportedFunction("yara:runtime/callbacks#invoke-callback"),
		callbackPost:   module.ExportedFunction("cabi_post_yara:runtime/callbacks#invoke-callback"),
	}
	h.guestsMu.Lock()
	h.guests[guestID] = guest
	h.guestModules[module] = guest
	h.guestsMu.Unlock()
}

func (h *hostRuntime) unregisterGuest(guestID uint64) {
	h.guestsMu.Lock()
	guest := h.guests[guestID]
	delete(h.guests, guestID)
	if guest != nil {
		delete(h.guestModules, guest.module)
	}
	h.guestsMu.Unlock()
}

func (h *hostRuntime) guest(guestID uint64) (*guestModuleState, error) {
	h.guestsMu.RLock()
	guest := h.guests[guestID]
	h.guestsMu.RUnlock()
	if guest == nil {
		return nil, fmt.Errorf("unknown guest instance %d", guestID)
	}
	return guest, nil
}

func (h *hostRuntime) moduleGuest(module api.Module) *guestModuleState {
	h.guestsMu.RLock()
	guest := h.guestModules[module]
	h.guestsMu.RUnlock()
	return guest
}

func (g *guestModuleState) setActiveScanData(ptr, length uint32) {
	g.scanDataMu.Lock()
	g.scanDataPtr = ptr
	g.scanDataLen = length
	g.hasScanData = true
	g.scanDataMu.Unlock()
}

func (g *guestModuleState) clearActiveScanData() {
	g.scanDataMu.Lock()
	g.scanDataPtr = 0
	g.scanDataLen = 0
	g.hasScanData = false
	g.scanDataMu.Unlock()
}

func (g *guestModuleState) activeScanData() (uint32, uint32, bool) {
	g.scanDataMu.RLock()
	defer g.scanDataMu.RUnlock()
	return g.scanDataPtr, g.scanDataLen, g.hasScanData
}

func (h *hostRuntime) setGuestConsoleOutput(guestID uint64, w io.Writer) {
	guest, err := h.guest(guestID)
	if err != nil {
		return
	}
	guest.consoleMu.Lock()
	guest.console = w
	guest.consoleErr = nil
	guest.consoleMu.Unlock()
}

func (h *hostRuntime) resetGuestConsoleError(guestID uint64) {
	guest, err := h.guest(guestID)
	if err != nil {
		return
	}
	guest.consoleMu.Lock()
	guest.consoleErr = nil
	guest.consoleMu.Unlock()
}

func (h *hostRuntime) takeGuestConsoleError(guestID uint64) error {
	guest, err := h.guest(guestID)
	if err != nil {
		return nil
	}
	guest.consoleMu.Lock()
	defer guest.consoleMu.Unlock()
	err = guest.consoleErr
	guest.consoleErr = nil
	return err
}

func (h *hostRuntime) instantiateHostBridge(ctx context.Context) error {
	builder := h.rt.NewHostModuleBuilder(yaraRuntimeHostModule)

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.validateModule),
		[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("validate-module")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.globalNew),
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI64, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("global-new")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.globalGet),
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("global-get")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.globalSet),
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI64, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("global-set")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.memoryNew),
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("memory-new")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.memoryRead),
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("memory-read")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.memoryWrite),
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("memory-write")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.instantiate),
		[]api.ValueType{
			api.ValueTypeI64,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI32,
		},
		[]api.ValueType{},
	).Export("instantiate")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.instanceDestroy),
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("instance-destroy")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.callExport),
		[]api.ValueType{
			api.ValueTypeI64,
			api.ValueTypeI64,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI64,
			api.ValueTypeI32,
		},
		[]api.ValueType{},
	).Export("call-export")

	if _, err := builder.Instantiate(ctx); err != nil {
		return err
	}

	consoleBuilder := h.rt.NewHostModuleBuilder(goConsoleHostModule)
	consoleBuilder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.consoleWriteMessage),
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("write-message")

	if _, err := consoleBuilder.Instantiate(ctx); err != nil {
		return err
	}

	scanDataBuilder := h.rt.NewHostModuleBuilder(goScanDataHostModule)
	scanDataBuilder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.beginScanBytes),
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("begin-scan-bytes")
	scanDataBuilder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.endScanBytes),
		[]api.ValueType{api.ValueTypeI64},
		[]api.ValueType{},
	).Export("end-scan-bytes")

	_, err := scanDataBuilder.Instantiate(ctx)
	return err
}

func (h *hostRuntime) session(sessionID uint64) (*hostSessionState, error) {
	if sessionID == 0 {
		return nil, errors.New("invalid zero session id")
	}

	h.sessionsMu.RLock()
	state := h.sessions[sessionID]
	h.sessionsMu.RUnlock()
	if state != nil {
		return state, nil
	}

	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()

	if state = h.sessions[sessionID]; state != nil {
		return state, nil
	}

	state = newHostSessionState()
	h.sessions[sessionID] = state
	return state, nil
}

func (h *hostRuntime) destroySession(ctx context.Context, sessionID uint64) error {
	h.sessionsMu.Lock()
	state := h.sessions[sessionID]
	if state != nil {
		delete(h.sessions, sessionID)
	}
	h.sessionsMu.Unlock()
	if state == nil {
		return nil
	}
	return state.closeAllInstances(ctx)
}

// Wazero passes all params in uint64 stack slots; i32 values must be decoded
// from the low 32 bits instead of validating the entire slot width.
func decodeStackU32(v uint64) uint32 {
	return api.DecodeU32(v)
}

func (h *hostRuntime) consoleWriteMessage(ctx context.Context, caller api.Module, stack []uint64) {
	guestID := stack[0]
	ptr := decodeStackU32(stack[1])
	length := decodeStackU32(stack[2])

	guest, err := h.guest(guestID)
	if err != nil {
		return
	}

	message, err := readBytes(caller.Memory(), ptr, length)
	if err != nil {
		guest.consoleMu.Lock()
		if guest.consoleErr == nil {
			guest.consoleErr = err
		}
		guest.consoleMu.Unlock()
		return
	}

	guest.consoleMu.Lock()
	defer guest.consoleMu.Unlock()

	if guest.console == nil || guest.consoleErr != nil {
		return
	}

	if _, err := guest.console.Write(message); err != nil {
		guest.consoleErr = err
		return
	}
	if _, err := guest.console.Write([]byte{'\n'}); err != nil {
		guest.consoleErr = err
		return
	}
	switch flusher := guest.console.(type) {
	case interface{ Flush() error }:
		if err := flusher.Flush(); err != nil {
			guest.consoleErr = err
		}
	case interface{ Flush() }:
		flusher.Flush()
	}
}

func (h *hostRuntime) beginScanBytes(_ context.Context, _ api.Module, stack []uint64) {
	guestID := stack[0]
	ptr := decodeStackU32(stack[1])
	length := decodeStackU32(stack[2])

	guest, err := h.guest(guestID)
	if err != nil {
		panic(err)
	}
	guest.setActiveScanData(ptr, length)
}

func (h *hostRuntime) endScanBytes(_ context.Context, _ api.Module, stack []uint64) {
	guestID := stack[0]
	guest, err := h.guest(guestID)
	if err != nil {
		panic(err)
	}
	guest.clearActiveScanData()
}

func (s *hostSessionState) closeAllInstances(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, inst := range s.instances {
		inst.close(ctx)
		delete(s.instances, id)
	}
	return nil
}

func (h *hostRuntime) validateModule(ctx context.Context, caller api.Module, stack []uint64) {
	mem := caller.Memory()
	retPtr := decodeStackU32(stack[2])
	modulePtr := decodeStackU32(stack[0])
	moduleLen := decodeStackU32(stack[1])

	moduleBytes, err := readBytes(mem, modulePtr, moduleLen)
	if err != nil {
		h.writeUnitResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	compiled, err := h.rt.CompileModule(ctx, moduleBytes)
	if err != nil {
		h.writeUnitResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	_ = compiled.Close(ctx)
	h.writeUnitResultOK(mem, retPtr)
}

func (h *hostRuntime) globalNew(ctx context.Context, caller api.Module, stack []uint64) {
	mem := caller.Memory()
	sessionID := stack[0]
	retPtr := decodeStackU32(stack[4])
	rawType := decodeStackU32(stack[1])
	typ := valType(rawType)
	mutable := decodeStackU32(stack[2]) != 0
	value := stack[3]

	session, err := h.session(sessionID)
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	if typ > valTypeF32Bits {
		h.writeU64ResultErr(ctx, caller, retPtr, fmt.Sprintf("unsupported val-type %d", typ))
		return
	}

	session.mu.Lock()
	id := session.nextID()
	session.globals[id] = &globalState{
		typ:     typ,
		mutable: mutable,
		value:   value,
	}
	session.mu.Unlock()

	h.writeU64ResultOK(mem, retPtr, id)
}

func (h *hostRuntime) globalGet(ctx context.Context, caller api.Module, stack []uint64) {
	mem := caller.Memory()
	sessionID := stack[0]
	retPtr := decodeStackU32(stack[3])
	id := stack[1]

	session, err := h.session(sessionID)
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	session.mu.RLock()
	global, ok := session.globals[id]
	var value uint64
	if ok {
		value = global.value
	}
	session.mu.RUnlock()
	if !ok {
		h.writeU64ResultErr(ctx, caller, retPtr, fmt.Sprintf("unknown global handle %d", id))
		return
	}

	h.writeU64ResultOK(mem, retPtr, value)
}

func (h *hostRuntime) globalSet(ctx context.Context, caller api.Module, stack []uint64) {
	mem := caller.Memory()
	sessionID := stack[0]
	retPtr := decodeStackU32(stack[4])
	id := stack[1]
	value := stack[3]

	session, err := h.session(sessionID)
	if err != nil {
		h.writeUnitResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	session.mu.Lock()
	global, ok := session.globals[id]
	if !ok {
		session.mu.Unlock()
		h.writeUnitResultErr(ctx, caller, retPtr, fmt.Sprintf("unknown global handle %d", id))
		return
	}

	if !global.mutable {
		session.mu.Unlock()
		h.writeUnitResultErr(ctx, caller, retPtr, fmt.Sprintf("global %d is immutable", id))
		return
	}

	if global.value != value {
		global.value = value
		global.revision++
	}
	session.mu.Unlock()
	h.writeUnitResultOK(mem, retPtr)
}

func (h *hostRuntime) memoryNew(ctx context.Context, caller api.Module, stack []uint64) {
	mem := caller.Memory()
	sessionID := stack[0]
	retPtr := decodeStackU32(stack[4])
	initialPages := decodeStackU32(stack[1])
	maxTag := decodeStackU32(stack[2])
	maxRaw := decodeStackU32(stack[3])

	session, err := h.session(sessionID)
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	var maximum *uint32
	if maxTag != 0 {
		maxPages := maxRaw
		maximum = &maxPages
	}

	dataSize := int(initialPages) * pageSize
	session.mu.Lock()
	id := session.nextID()
	session.memories[id] = &memoryState{
		initial: initialPages,
		maximum: maximum,
		data:    make([]byte, dataSize),
	}
	session.mu.Unlock()

	h.writeU64ResultOK(mem, retPtr, id)
}

func (h *hostRuntime) memoryRead(ctx context.Context, caller api.Module, stack []uint64) {
	sessionID := stack[0]
	retPtr := decodeStackU32(stack[2])
	id := stack[1]

	session, err := h.session(sessionID)
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	session.mu.RLock()
	memory, ok := session.memories[id]
	if !ok {
		session.mu.RUnlock()
		h.writeListResultErr(ctx, caller, retPtr, fmt.Sprintf("unknown memory handle %d", id))
		return
	}
	if err := h.writeBytesResultOK(ctx, caller, retPtr, memory.data); err != nil {
		session.mu.RUnlock()
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	session.mu.RUnlock()
}

func (h *hostRuntime) memoryWrite(ctx context.Context, caller api.Module, stack []uint64) {
	mem := caller.Memory()
	sessionID := stack[0]
	retPtr := decodeStackU32(stack[4])
	id := stack[1]
	dataPtr := decodeStackU32(stack[2])
	dataLen := decodeStackU32(stack[3])

	session, err := h.session(sessionID)
	if err != nil {
		h.writeUnitResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	session.mu.RLock()
	_, ok := session.memories[id]
	session.mu.RUnlock()
	if !ok {
		h.writeUnitResultErr(ctx, caller, retPtr, fmt.Sprintf("unknown memory handle %d", id))
		return
	}

	var data []byte
	if dataLen > 0 {
		var readOK bool
		data, readOK = mem.Read(dataPtr, dataLen)
		if !readOK {
			h.writeUnitResultErr(ctx, caller, retPtr, fmt.Sprintf("out-of-bounds read at %d with length %d", dataPtr, dataLen))
			return
		}
	}

	session.mu.Lock()
	memory, ok := session.memories[id]
	if !ok {
		session.mu.Unlock()
		h.writeUnitResultErr(ctx, caller, retPtr, fmt.Sprintf("unknown memory handle %d", id))
		return
	}
	changed := len(memory.data) != len(data) || !bytes.Equal(memory.data, data)
	if cap(memory.data) < len(data) {
		memory.data = make([]byte, len(data))
	} else {
		memory.data = memory.data[:len(data)]
	}
	if len(data) > 0 {
		copy(memory.data, data)
	}
	if changed {
		memory.revision++
	}
	session.mu.Unlock()

	h.writeUnitResultOK(mem, retPtr)
}

func (h *hostRuntime) instantiate(ctx context.Context, caller api.Module, stack []uint64) {
	sessionID := stack[0]
	mem := caller.Memory()
	retPtr := decodeStackU32(stack[7])

	modulePtr := decodeStackU32(stack[1])
	moduleLen := decodeStackU32(stack[2])
	functionsPtr := decodeStackU32(stack[3])
	functionsLen := decodeStackU32(stack[4])
	externsPtr := decodeStackU32(stack[5])
	externsLen := decodeStackU32(stack[6])

	session, err := h.session(sessionID)
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	moduleBytes, err := readBytes(mem, modulePtr, moduleLen)
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	functionImports, err := parseFunctionImports(mem, functionsPtr, functionsLen)
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	externImports, err := parseExternImports(mem, externsPtr, externsLen)
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	instanceRT := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig())
	compiled, err := instanceRT.CompileModule(ctx, moduleBytes)
	if err != nil {
		_ = instanceRT.Close(ctx)
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	instance := &instanceState{
		sessionID:     sessionID,
		session:       session,
		rt:            instanceRT,
		helperModules: make([]api.Module, 0),
		externModules: make(map[string]api.Module),
		externs:       externImports,
		exports:       make(map[string]api.Function),
	}

	if err := h.instantiateFunctionModules(ctx, instanceRT, compiled, functionImports, instance); err != nil {
		_ = compiled.Close(ctx)
		instance.close(ctx)
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	if err := h.instantiateExternModules(ctx, instanceRT, externImports, instance); err != nil {
		_ = compiled.Close(ctx)
		instance.close(ctx)
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	if err := h.syncExternsToModules(instance); err != nil {
		_ = compiled.Close(ctx)
		instance.close(ctx)
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	session.mu.Lock()
	moduleName := fmt.Sprintf("yrx-rule-%d-%d", sessionID, session.nextID())
	session.mu.Unlock()
	module, err := instanceRT.InstantiateModule(
		ctx,
		compiled,
		wazero.NewModuleConfig().WithName(moduleName),
	)
	_ = compiled.Close(ctx)
	if err != nil {
		instance.close(ctx)
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	instance.module = module
	session.mu.Lock()
	id := session.nextID()
	session.instances[id] = instance
	session.mu.Unlock()

	h.writeU64ResultOK(mem, retPtr, id)
}

func (h *hostRuntime) instanceDestroy(ctx context.Context, caller api.Module, stack []uint64) {
	mem := caller.Memory()
	sessionID := stack[0]
	instanceID := stack[1]
	retPtr := decodeStackU32(stack[2])

	session, err := h.session(sessionID)
	if err != nil {
		h.writeUnitResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	session.mu.Lock()
	instance, ok := session.instances[instanceID]
	if !ok {
		session.mu.Unlock()
		h.writeUnitResultErr(ctx, caller, retPtr, fmt.Sprintf("unknown instance handle %d", instanceID))
		return
	}

	instance.close(ctx)
	delete(session.instances, instanceID)
	session.mu.Unlock()
	h.writeUnitResultOK(mem, retPtr)
}

func (h *hostRuntime) callExport(ctx context.Context, caller api.Module, stack []uint64) {
	sessionID := stack[0]
	mem := caller.Memory()
	retPtr := decodeStackU32(stack[9])

	instanceID := stack[1]
	namePtr := decodeStackU32(stack[2])
	nameLen := decodeStackU32(stack[3])
	paramsPtr := decodeStackU32(stack[4])
	paramsLen := decodeStackU32(stack[5])
	resultsPtr := decodeStackU32(stack[6])
	resultsLen := decodeStackU32(stack[7])
	timeoutNanos := stack[8]

	session, err := h.session(sessionID)
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	session.mu.RLock()
	instance, ok := session.instances[instanceID]
	session.mu.RUnlock()
	if !ok {
		h.writeListResultErr(ctx, caller, retPtr, fmt.Sprintf("unknown instance handle %d", instanceID))
		return
	}

	exportName, err := readString(mem, namePtr, nameLen)
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	paramsByteLen, err := checkedMul8(paramsLen)
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	paramBytes, err := readBytes(mem, paramsPtr, paramsByteLen)
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	_, err = readBytes(mem, resultsPtr, resultsLen*4)
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	if err := h.syncExternsToModulesIfChanged(instance); err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	instance.exportMu.Lock()
	fn := instance.exports[exportName]
	if fn == nil {
		fn = instance.module.ExportedFunction(exportName)
		if fn != nil {
			instance.exports[exportName] = fn
		}
	}
	instance.exportMu.Unlock()
	if fn == nil {
		h.writeListResultErr(ctx, caller, retPtr, fmt.Sprintf("missing export %q", exportName))
		return
	}

	clearDeadline := func() {}
	if timeoutNanos != noTimeoutNanos {
		timeout, convErr := durationFromNanos(timeoutNanos, "call-export timeout")
		if convErr != nil {
			h.writeListResultErr(ctx, caller, retPtr, convErr.Error())
			return
		}
		clearDeadline = instance.beginCallDeadline(timeout)
	}
	defer clearDeadline()

	resultCount := len(fn.Definition().ResultTypes())
	callStackLen := max(resultCount, int(paramsLen))
	callStack := make([]uint64, callStackLen)
	for i := range int(paramsLen) {
		offset := i * 8
		callStack[i] = binary.LittleEndian.Uint64(paramBytes[offset : offset+8])
	}

	outLen, err := u32FromLen(resultCount, "call-export result count")
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	if err := fn.CallWithStack(ctx, callStack); err != nil {
		if strings.Contains(err.Error(), hostCallTimeoutError) {
			h.writeListResultErr(ctx, caller, retPtr, hostCallTimeoutError)
			return
		}
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	if err := h.syncExternsFromModules(instance); err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	if outLen != resultsLen {
		h.writeListResultErr(
			ctx,
			caller,
			retPtr,
			fmt.Sprintf("unexpected result length: got %d want %d", resultCount, resultsLen),
		)
		return
	}

	if err := h.writeU64ListResultOK(ctx, caller, retPtr, callStack[:resultCount]); err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
	}
}

func (h *hostRuntime) instantiateFunctionModules(
	ctx context.Context,
	rt wazero.Runtime,
	compiled wazero.CompiledModule,
	callbacks []functionImport,
	instance *instanceState,
) error {
	callbackIDByName := make(map[string]uint64, len(callbacks))
	callbackSyncFlagsByName := make(map[string]uint32, len(callbacks))
	for _, c := range callbacks {
		callbackIDByName[importKey(c.module, c.name)] = c.callbackID
		callbackSyncFlagsByName[importKey(c.module, c.name)] = c.syncFlags
	}

	type exportDef struct {
		module     string
		name       string
		callbackID uint64
		syncFlags  uint32
		params     []api.ValueType
		results    []api.ValueType
		fastPath   *scanDataIntegerImport
	}

	moduleExports := map[string][]exportDef{}
	seen := map[string]struct{}{}

	for _, def := range compiled.ImportedFunctions() {
		moduleName, importName, isImport := def.Import()
		if !isImport {
			continue
		}

		key := importKey(moduleName, importName)
		if _, done := seen[key]; done {
			continue
		}
		seen[key] = struct{}{}

		callbackID, ok := callbackIDByName[key]
		if !ok {
			return fmt.Errorf("missing callback mapping for import %s.%s", moduleName, importName)
		}

		moduleExports[moduleName] = append(moduleExports[moduleName], exportDef{
			module:     moduleName,
			name:       importName,
			callbackID: callbackID,
			syncFlags:  callbackSyncFlagsByName[key],
			params:     def.ParamTypes(),
			results:    def.ResultTypes(),
			fastPath:   lookupScanDataIntegerImport(moduleName, importName, callbackSyncFlagsByName[key], def.ParamTypes(), def.ResultTypes()),
		})
	}

	moduleNames := make([]string, 0, len(moduleExports))
	for name := range moduleExports {
		moduleNames = append(moduleNames, name)
	}
	sort.Strings(moduleNames)

	for _, moduleName := range moduleNames {
		builder := rt.NewHostModuleBuilder(moduleName)
		exports := moduleExports[moduleName]
		sort.Slice(exports, func(i, j int) bool { return exports[i].name < exports[j].name })

		for _, export := range exports {
			callbackID := export.callbackID
			syncFlags := export.syncFlags
			paramTypes := export.params
			resultTypes := export.results
			fastPath := export.fastPath

			builder.NewFunctionBuilder().WithGoModuleFunction(
				api.GoModuleFunc(func(ctx context.Context, _ api.Module, stack []uint64) {
					if err := h.invokeImport(ctx, instance, callbackID, syncFlags, fastPath, paramTypes, resultTypes, stack); err != nil {
						panic(err)
					}
				}),
				paramTypes,
				resultTypes,
			).Export(export.name)
		}

		mod, err := builder.Instantiate(ctx)
		if err != nil {
			return fmt.Errorf("instantiate callback module %q: %w", moduleName, err)
		}
		instance.helperModules = append(instance.helperModules, mod)
	}

	return nil
}

func normalizeImportBaseName(moduleName, importName string) (string, bool) {
	if importName == "" {
		return "", false
	}

	base, _, _ := strings.Cut(importName, "@")
	if prefix := moduleName + "."; strings.HasPrefix(base, prefix) {
		base = strings.TrimPrefix(base, prefix)
	} else if idx := strings.LastIndexByte(base, '.'); idx >= 0 {
		base = base[idx+1:]
	}
	if base == "" {
		return "", false
	}
	return base, true
}

func lookupScanDataIntegerImport(
	moduleName string,
	importName string,
	syncFlags uint32,
	paramTypes []api.ValueType,
	resultTypes []api.ValueType,
) *scanDataIntegerImport {
	if moduleName != "yara_x::wasm" || syncFlags != 0 {
		return nil
	}
	if len(paramTypes) != 1 || paramTypes[0] != api.ValueTypeI64 {
		return nil
	}
	if len(resultTypes) != 2 || resultTypes[0] != api.ValueTypeI64 || resultTypes[1] != api.ValueTypeI32 {
		return nil
	}

	baseName, ok := normalizeImportBaseName(moduleName, importName)
	if !ok {
		return nil
	}

	var spec scanDataIntegerImport
	switch baseName {
	case "uint8":
		spec = scanDataIntegerImport{name: baseName, byteLen: 1}
	case "uint16":
		spec = scanDataIntegerImport{name: baseName, byteLen: 2}
	case "uint32":
		spec = scanDataIntegerImport{name: baseName, byteLen: 4}
	case "uint8be":
		spec = scanDataIntegerImport{name: baseName, byteLen: 1, bigEndian: true}
	case "uint16be":
		spec = scanDataIntegerImport{name: baseName, byteLen: 2, bigEndian: true}
	case "uint32be":
		spec = scanDataIntegerImport{name: baseName, byteLen: 4, bigEndian: true}
	case "int8":
		spec = scanDataIntegerImport{name: baseName, byteLen: 1, signed: true}
	case "int16":
		spec = scanDataIntegerImport{name: baseName, byteLen: 2, signed: true}
	case "int32":
		spec = scanDataIntegerImport{name: baseName, byteLen: 4, signed: true}
	case "int8be":
		spec = scanDataIntegerImport{name: baseName, byteLen: 1, signed: true, bigEndian: true}
	case "int16be":
		spec = scanDataIntegerImport{name: baseName, byteLen: 2, signed: true, bigEndian: true}
	case "int32be":
		spec = scanDataIntegerImport{name: baseName, byteLen: 4, signed: true, bigEndian: true}
	default:
		return nil
	}

	return &spec
}

func (h *hostRuntime) invokeImport(
	ctx context.Context,
	instance *instanceState,
	callbackID uint64,
	syncFlags uint32,
	fastPath *scanDataIntegerImport,
	paramTypes []api.ValueType,
	resultTypes []api.ValueType,
	stack []uint64,
) error {
	if fastPath != nil {
		handled, err := h.serveScanDataIntegerImport(instance, *fastPath, stack)
		if handled || err != nil {
			return err
		}
	}

	return h.invokeImportCallback(ctx, instance, callbackID, syncFlags, paramTypes, resultTypes, stack)
}

func (h *hostRuntime) serveScanDataIntegerImport(
	instance *instanceState,
	spec scanDataIntegerImport,
	stack []uint64,
) (bool, error) {
	guest, err := h.guest(instance.sessionID)
	if err != nil {
		return false, err
	}

	scanPtr, scanLen, active := guest.activeScanData()
	if !active {
		return false, nil
	}
	if len(stack) < 2 {
		return false, fmt.Errorf("scan-data import %s requires at least 2 stack slots, got %d", spec.name, len(stack))
	}

	offset := i64FromBits(stack[0])
	value, defined, err := readScanDataInteger(guest.module.Memory(), scanPtr, scanLen, offset, spec)
	if err != nil {
		return true, err
	}

	if !defined {
		stack[0] = 0
		stack[1] = 1
		return true, nil
	}

	stack[0] = u64FromI64Bits(value)
	stack[1] = 0
	return true, nil
}

func readScanDataInteger(
	mem api.Memory,
	scanPtr uint32,
	scanLen uint32,
	offset int64,
	spec scanDataIntegerImport,
) (int64, bool, error) {
	if mem == nil {
		return 0, false, errors.New("guest memory is missing")
	}
	if offset < 0 {
		return 0, false, nil
	}

	offsetU := uint64(offset)
	byteLen := uint64(spec.byteLen)
	if byteLen == 0 || byteLen > uint64(scanLen) {
		return 0, false, nil
	}
	if offsetU > uint64(scanLen)-byteLen {
		return 0, false, nil
	}
	absolute, err := u32FromUint64(uint64(scanPtr)+offsetU, "scan-data absolute offset")
	if err != nil {
		return 0, false, err
	}
	switch spec.byteLen {
	case 1:
		b, ok := mem.ReadByte(absolute)
		if !ok {
			return 0, false, fmt.Errorf("failed to read byte at guest offset %d", absolute)
		}
		if spec.signed {
			if b < 0x80 {
				return int64(b), true, nil
			}
			return int64(b) - 0x100, true, nil
		}
		return int64(b), true, nil
	case 2:
		if !spec.bigEndian {
			v, ok := mem.ReadUint16Le(absolute)
			if !ok {
				return 0, false, fmt.Errorf("failed to read uint16 at guest offset %d", absolute)
			}
			if spec.signed {
				return signExtendUint16(v), true, nil
			}
			return int64(v), true, nil
		}
		buf, ok := mem.Read(absolute, 2)
		if !ok {
			return 0, false, fmt.Errorf("failed to read 2 bytes at guest offset %d", absolute)
		}
		v := binary.BigEndian.Uint16(buf)
		if spec.signed {
			return signExtendUint16(v), true, nil
		}
		return int64(v), true, nil
	case 4:
		if !spec.bigEndian {
			v, ok := mem.ReadUint32Le(absolute)
			if !ok {
				return 0, false, fmt.Errorf("failed to read uint32 at guest offset %d", absolute)
			}
			if spec.signed {
				return signExtendUint32(v), true, nil
			}
			return int64(v), true, nil
		}
		buf, ok := mem.Read(absolute, 4)
		if !ok {
			return 0, false, fmt.Errorf("failed to read 4 bytes at guest offset %d", absolute)
		}
		v := binary.BigEndian.Uint32(buf)
		if spec.signed {
			return signExtendUint32(v), true, nil
		}
		return int64(v), true, nil
	default:
		return 0, false, fmt.Errorf("unsupported scan-data integer width %d", spec.byteLen)
	}
}

type externModuleSpec struct {
	name   string
	memory *externMemorySpec
	global []externGlobalSpec
}

type externMemorySpec struct {
	name  string
	state *memoryState
}

type externGlobalSpec struct {
	name  string
	state *globalState
}

func (h *hostRuntime) instantiateExternModules(
	ctx context.Context,
	rt wazero.Runtime,
	externs []externImport,
	instance *instanceState,
) error {
	specByModule := map[string]*externModuleSpec{}

	for _, ext := range externs {
		spec, ok := specByModule[ext.module]
		if !ok {
			spec = &externModuleSpec{name: ext.module}
			specByModule[ext.module] = spec
		}

		switch ext.kind {
		case externKindGlobal:
			instance.session.mu.RLock()
			state, ok := instance.session.globals[ext.handle]
			instance.session.mu.RUnlock()
			if !ok {
				return fmt.Errorf("unknown global handle %d", ext.handle)
			}
			spec.global = append(spec.global, externGlobalSpec{name: ext.name, state: state})
		case externKindMemory:
			instance.session.mu.RLock()
			state, ok := instance.session.memories[ext.handle]
			instance.session.mu.RUnlock()
			if !ok {
				return fmt.Errorf("unknown memory handle %d", ext.handle)
			}
			if spec.memory != nil {
				return fmt.Errorf("multiple memories for module %q", ext.module)
			}
			spec.memory = &externMemorySpec{name: ext.name, state: state}
		default:
			return fmt.Errorf("unsupported extern kind %d", ext.kind)
		}
	}

	moduleNames := make([]string, 0, len(specByModule))
	for name := range specByModule {
		moduleNames = append(moduleNames, name)
	}
	sort.Strings(moduleNames)

	for _, moduleName := range moduleNames {
		spec := specByModule[moduleName]
		wasm, err := buildExternModule(spec)
		if err != nil {
			return fmt.Errorf("build extern module %q: %w", moduleName, err)
		}

		compiled, err := rt.CompileModule(ctx, wasm)
		if err != nil {
			return fmt.Errorf("compile extern module %q: %w", moduleName, err)
		}

		mod, err := rt.InstantiateModule(
			ctx,
			compiled,
			wazero.NewModuleConfig().WithName(moduleName),
		)
		_ = compiled.Close(ctx)
		if err != nil {
			return fmt.Errorf("instantiate extern module %q: %w", moduleName, err)
		}

		instance.helperModules = append(instance.helperModules, mod)
		instance.externModules[moduleName] = mod
	}

	instance.externBindings = make([]instanceExternBinding, 0, len(externs))
	for _, ext := range externs {
		mod, ok := instance.externModules[ext.module]
		if !ok {
			return fmt.Errorf("extern module %q not found", ext.module)
		}

		binding := instanceExternBinding{
			module:             ext.module,
			name:               ext.name,
			kind:               ext.kind,
			lastSyncedRevision: unsetExternRevision,
		}

		switch ext.kind {
		case externKindGlobal:
			instance.session.mu.RLock()
			state, ok := instance.session.globals[ext.handle]
			instance.session.mu.RUnlock()
			if !ok {
				return fmt.Errorf("unknown global handle %d", ext.handle)
			}

			global := mod.ExportedGlobal(ext.name)
			if global == nil {
				return fmt.Errorf("missing global export %q in module %q", ext.name, ext.module)
			}

			binding.globalState = state
			binding.global = global
			if mutableGlobal, ok := global.(api.MutableGlobal); ok {
				binding.mutableGlobal = mutableGlobal
			}

		case externKindMemory:
			instance.session.mu.RLock()
			state, ok := instance.session.memories[ext.handle]
			instance.session.mu.RUnlock()
			if !ok {
				return fmt.Errorf("unknown memory handle %d", ext.handle)
			}

			memory := mod.Memory()
			if memory == nil {
				return fmt.Errorf("module %q has no memory export", ext.module)
			}

			binding.memoryState = state
			binding.memory = memory

		default:
			return fmt.Errorf("unsupported extern kind %d", ext.kind)
		}

		instance.externBindings = append(instance.externBindings, binding)
	}

	return nil
}

func (h *hostRuntime) invokeImportCallback(
	ctx context.Context,
	instance *instanceState,
	callbackID uint64,
	syncFlags uint32,
	paramTypes []api.ValueType,
	resultTypes []api.ValueType,
	stack []uint64,
) error {
	if instance.timedOut() {
		return errors.New(hostCallTimeoutError)
	}

	if syncFlags&callbackSyncBefore != 0 {
		if err := h.syncExternsFromModules(instance); err != nil {
			return err
		}
	}

	if instance.timedOut() {
		return errors.New(hostCallTimeoutError)
	}

	paramCount := len(paramTypes)
	resultCount := len(resultTypes)
	if err := h.callGuestCallback(ctx, instance.sessionID, callbackID, stack[:paramCount], stack[:resultCount]); err != nil {
		return err
	}

	if instance.timedOut() {
		return errors.New(hostCallTimeoutError)
	}

	if syncFlags&callbackSyncAfter != 0 {
		if err := h.syncExternsToModulesIfChanged(instance); err != nil {
			return err
		}
	}

	return nil
}

func (h *hostRuntime) callGuestCallback(
	ctx context.Context,
	sessionID uint64,
	callbackID uint64,
	args []uint64,
	out []uint64,
) (err error) {
	guest, err := h.guest(sessionID)
	if err != nil {
		return err
	}

	guest.mu.Lock()
	defer guest.mu.Unlock()

	if guest.callbackInvoke == nil {
		return errors.New("guest callback export is missing")
	}

	mem := guest.module.Memory()
	argCount, err := u32FromLen(len(args), "callback argument count")
	if err != nil {
		return err
	}
	argsLenBytes, err := checkedMul8(argCount)
	if err != nil {
		return err
	}
	argsPtr, err := guest.ensureCallbackArgsBuffer(ctx, argsLenBytes, 8)
	if err != nil {
		return err
	}

	for i, arg := range args {
		index, convErr := u32FromLen(i, "callback argument index")
		if convErr != nil {
			return convErr
		}
		offset := argsPtr + index*8
		if !mem.WriteUint64Le(offset, arg) {
			return fmt.Errorf("failed to write callback arg at %d", offset)
		}
	}

	resultCount := len(guest.callbackInvoke.Definition().ResultTypes())
	if resultCount != 1 {
		return fmt.Errorf("unexpected callback return arity %d", resultCount)
	}

	guest.callStack = ensureUint64Stack(guest.callStack, callStackLen(guest.callbackInvoke, 4))
	guest.callStack[0] = sessionID
	guest.callStack[1] = callbackID
	guest.callStack[2] = uint64(argsPtr)
	guest.callStack[3] = uint64(argCount)
	if err := guest.callbackInvoke.CallWithStack(ctx, guest.callStack); err != nil {
		return err
	}

	retArea := decodeStackU32(guest.callStack[0])
	if guest.callbackPost != nil {
		defer func() {
			postStack := guest.callStack[:1]
			postStack[0] = uint64(retArea)
			if postErr := guest.callbackPost.CallWithStack(ctx, postStack); postErr != nil && err == nil {
				err = fmt.Errorf("post-return callback cleanup failed: %w", postErr)
			}
		}()
	}

	tag, ok := mem.ReadByte(retArea)
	if !ok {
		return fmt.Errorf("failed to read callback tag at %d", retArea)
	}

	if tag == 0 {
		ptr, ok := mem.ReadUint32Le(retArea + 4)
		if !ok {
			return errors.New("failed to read callback result pointer")
		}
		length, ok := mem.ReadUint32Le(retArea + 8)
		if !ok {
			return errors.New("failed to read callback result length")
		}
		if int(length) != len(out) {
			return fmt.Errorf(
				"callback %d returned %d values, expected %d",
				callbackID,
				length,
				len(out),
			)
		}
		if length == 0 {
			return nil
		}

		rawLen, mulErr := checkedMul8(length)
		if mulErr != nil {
			return mulErr
		}

		buf, ok := mem.Read(ptr, rawLen)
		if !ok {
			return fmt.Errorf("out-of-bounds read at %d with length %d", ptr, rawLen)
		}

		for i := range out {
			base := i * 8
			out[i] = binary.LittleEndian.Uint64(buf[base : base+8])
		}
		return nil
	}

	errPtr, ok := mem.ReadUint32Le(retArea + 4)
	if !ok {
		return errors.New("failed to read callback error pointer")
	}
	errLen, ok := mem.ReadUint32Le(retArea + 8)
	if !ok {
		return errors.New("failed to read callback error length")
	}
	msg, readErr := readString(mem, errPtr, errLen)
	if readErr != nil {
		return readErr
	}
	if msg == "" {
		msg = "callback returned an empty error"
	}
	return errors.New(msg)
}

func (g *guestModuleState) ensureCallbackArgsBuffer(
	ctx context.Context,
	size uint32,
	align uint32,
) (uint32, error) {
	requiredSize := normalizeGuestAllocSize(size)
	if g.callbackArgsPtr != 0 && g.callbackArgsCap >= requiredSize {
		return g.callbackArgsPtr, nil
	}

	if g.callbackArgsPtr == 0 {
		ptr, err := g.alloc(ctx, requiredSize, align)
		if err != nil {
			return 0, err
		}
		g.callbackArgsPtr = ptr
		g.callbackArgsCap = requiredSize
		return ptr, nil
	}

	ptr, err := g.reallocBuffer(ctx, g.callbackArgsPtr, g.callbackArgsCap, align, requiredSize)
	if err != nil {
		return 0, err
	}
	g.callbackArgsPtr = ptr
	g.callbackArgsCap = requiredSize
	return ptr, nil
}

func (h *hostRuntime) syncExternsToModules(instance *instanceState) error {
	return h.syncExternsToModulesMode(instance, true)
}

func (h *hostRuntime) syncExternsToModulesIfChanged(instance *instanceState) error {
	return h.syncExternsToModulesMode(instance, false)
}

func (h *hostRuntime) syncExternsToModulesMode(instance *instanceState, force bool) error {
	for i := range instance.externBindings {
		binding := &instance.externBindings[i]

		switch binding.kind {
		case externKindGlobal:
			instance.session.mu.RLock()
			state := binding.globalState
			if state == nil {
				instance.session.mu.RUnlock()
				return fmt.Errorf("missing global state for %q.%q", binding.module, binding.name)
			}
			revision := state.revision
			value := state.value
			instance.session.mu.RUnlock()

			if !force && binding.lastSyncedRevision == revision {
				continue
			}
			if binding.mutableGlobal != nil {
				binding.mutableGlobal.Set(value)
			}
			binding.lastSyncedRevision = revision

		case externKindMemory:
			instance.session.mu.RLock()
			state := binding.memoryState
			if state == nil {
				instance.session.mu.RUnlock()
				return fmt.Errorf("missing memory state for %q.%q", binding.module, binding.name)
			}
			revision := state.revision
			if !force && binding.lastSyncedRevision == revision {
				instance.session.mu.RUnlock()
				continue
			}
			if binding.memory == nil {
				instance.session.mu.RUnlock()
				return fmt.Errorf("missing memory export %q in module %q", binding.name, binding.module)
			}
			if len(state.data) > int(binding.memory.Size()) {
				instance.session.mu.RUnlock()
				return fmt.Errorf(
					"memory %q.%q is larger than module memory (%d > %d)",
					binding.module,
					binding.name,
					len(state.data),
					binding.memory.Size(),
				)
			}
			if len(state.data) > 0 && !binding.memory.Write(0, state.data) {
				instance.session.mu.RUnlock()
				return fmt.Errorf("failed to write module memory for %q.%q", binding.module, binding.name)
			}
			binding.lastSyncedRevision = revision
			instance.session.mu.RUnlock()
		}
	}

	return nil
}

func (h *hostRuntime) syncExternsFromModules(instance *instanceState) error {
	for i := range instance.externBindings {
		binding := &instance.externBindings[i]

		switch binding.kind {
		case externKindGlobal:
			if binding.globalState == nil || binding.global == nil {
				return fmt.Errorf("missing global binding for %q.%q", binding.module, binding.name)
			}
			value := binding.global.Get()

			instance.session.mu.Lock()
			if binding.globalState.value != value {
				binding.globalState.value = value
				binding.globalState.revision++
			}
			binding.lastSyncedRevision = binding.globalState.revision
			instance.session.mu.Unlock()

		case externKindMemory:
			if binding.memoryState == nil || binding.memory == nil {
				return fmt.Errorf("missing memory binding for %q.%q", binding.module, binding.name)
			}

			size := binding.memory.Size()
			buf, ok := binding.memory.Read(0, size)
			if !ok {
				return fmt.Errorf("failed to read memory from module %q", binding.module)
			}

			instance.session.mu.Lock()
			state := binding.memoryState
			if len(state.data) != len(buf) || !bytes.Equal(state.data, buf) {
				if cap(state.data) < len(buf) {
					state.data = make([]byte, len(buf))
				} else {
					state.data = state.data[:len(buf)]
				}
				copy(state.data, buf)
				state.revision++
			}
			binding.lastSyncedRevision = state.revision
			instance.session.mu.Unlock()
		}
	}

	return nil
}

func parseFunctionImports(mem api.Memory, ptr, length uint32) ([]functionImport, error) {
	const recordSize = uint32(48)
	imports := make([]functionImport, 0, length)

	for i := range length {
		recordPtr := ptr + i*recordSize
		record, ok := mem.Read(recordPtr, recordSize)
		if !ok {
			return nil, fmt.Errorf("out-of-bounds function import record %d", i)
		}

		modulePtr := binary.LittleEndian.Uint32(record[0:4])
		moduleLen := binary.LittleEndian.Uint32(record[4:8])
		namePtr := binary.LittleEndian.Uint32(record[8:12])
		nameLen := binary.LittleEndian.Uint32(record[12:16])
		callbackID := binary.LittleEndian.Uint64(record[32:40])
		syncFlags := binary.LittleEndian.Uint32(record[40:44])

		module, err := readString(mem, modulePtr, moduleLen)
		if err != nil {
			return nil, fmt.Errorf("function import %d module: %w", i, err)
		}
		name, err := readString(mem, namePtr, nameLen)
		if err != nil {
			return nil, fmt.Errorf("function import %d name: %w", i, err)
		}

		imports = append(imports, functionImport{
			module:     module,
			name:       name,
			callbackID: callbackID,
			syncFlags:  syncFlags,
		})
	}

	return imports, nil
}

func parseExternImports(mem api.Memory, ptr, length uint32) ([]externImport, error) {
	const recordSize = uint32(32)
	imports := make([]externImport, 0, length)

	for i := range length {
		recordPtr := ptr + i*recordSize
		record, ok := mem.Read(recordPtr, recordSize)
		if !ok {
			return nil, fmt.Errorf("out-of-bounds extern import record %d", i)
		}

		modulePtr := binary.LittleEndian.Uint32(record[0:4])
		moduleLen := binary.LittleEndian.Uint32(record[4:8])
		namePtr := binary.LittleEndian.Uint32(record[8:12])
		nameLen := binary.LittleEndian.Uint32(record[12:16])
		tag := record[16]
		handle := binary.LittleEndian.Uint64(record[24:32])

		module, err := readString(mem, modulePtr, moduleLen)
		if err != nil {
			return nil, fmt.Errorf("extern import %d module: %w", i, err)
		}
		name, err := readString(mem, namePtr, nameLen)
		if err != nil {
			return nil, fmt.Errorf("extern import %d name: %w", i, err)
		}

		var kind externKind
		switch tag {
		case 0:
			kind = externKindGlobal
		case 1:
			kind = externKindMemory
		default:
			return nil, fmt.Errorf("extern import %d has unknown kind tag %d", i, uint32(tag))
		}

		imports = append(imports, externImport{
			module: module,
			name:   name,
			kind:   kind,
			handle: handle,
		})
	}

	return imports, nil
}

func buildExternModule(spec *externModuleSpec) ([]byte, error) {
	exports := 0
	if spec.memory != nil {
		exports++
	}
	exports += len(spec.global)
	if exports == 0 {
		return nil, fmt.Errorf("extern module %q has no exports", spec.name)
	}

	wasm := make([]byte, 0, 512)
	wasm = append(wasm, 0x00, 0x61, 0x73, 0x6d)
	wasm = append(wasm, 0x01, 0x00, 0x00, 0x00)

	if spec.memory != nil {
		payload := make([]byte, 0, 16)
		payload = appendU32(payload, 1)
		if spec.memory.state.maximum == nil {
			payload = append(payload, 0x00)
			payload = appendU32(payload, spec.memory.state.initial)
		} else {
			payload = append(payload, 0x01)
			payload = appendU32(payload, spec.memory.state.initial)
			payload = appendU32(payload, *spec.memory.state.maximum)
		}
		var err error
		wasm, err = appendSection(wasm, 5, payload)
		if err != nil {
			return nil, err
		}
	}

	if len(spec.global) > 0 {
		payload := make([]byte, 0, len(spec.global)*16)
		globalCount, err := u32FromLen(len(spec.global), "extern module global count")
		if err != nil {
			return nil, err
		}
		payload = appendU32(payload, globalCount)
		for _, g := range spec.global {
			payload = append(payload, valTypeToWasmByte(g.state.typ))
			if g.state.mutable {
				payload = append(payload, 0x01)
			} else {
				payload = append(payload, 0x00)
			}
			initExpr, err := buildInitExpr(g.state.typ, g.state.value)
			if err != nil {
				return nil, err
			}
			payload = append(payload, initExpr...)
		}
		wasm, err = appendSection(wasm, 6, payload)
		if err != nil {
			return nil, err
		}
	}

	exportPayload := make([]byte, 0, 256)
	exportCount, err := u32FromLen(exports, "extern module export count")
	if err != nil {
		return nil, err
	}
	exportPayload = appendU32(exportPayload, exportCount)

	if spec.memory != nil {
		exportPayload, err = appendName(exportPayload, spec.memory.name)
		if err != nil {
			return nil, err
		}
		exportPayload = append(exportPayload, 0x02)
		exportPayload = appendU32(exportPayload, 0)
	}

	for i, g := range spec.global {
		exportPayload, err = appendName(exportPayload, g.name)
		if err != nil {
			return nil, err
		}
		exportPayload = append(exportPayload, 0x03)
		index, convErr := u32FromLen(i, "extern module global index")
		if convErr != nil {
			return nil, convErr
		}
		exportPayload = appendU32(exportPayload, index)
	}

	wasm, err = appendSection(wasm, 7, exportPayload)
	if err != nil {
		return nil, err
	}
	return wasm, nil
}

func appendSection(dst []byte, id byte, payload []byte) ([]byte, error) {
	payloadLen, err := u32FromLen(len(payload), "WASM section payload length")
	if err != nil {
		return nil, err
	}
	dst = append(dst, id)
	dst = appendU32(dst, payloadLen)
	dst = append(dst, payload...)
	return dst, nil
}

func appendName(dst []byte, name string) ([]byte, error) {
	nameLen, err := u32FromLen(len(name), "WASM name length")
	if err != nil {
		return nil, err
	}
	dst = appendU32(dst, nameLen)
	dst = append(dst, []byte(name)...)
	return dst, nil
}

func appendU32(dst []byte, v uint32) []byte {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			dst = append(dst, b|0x80)
		} else {
			dst = append(dst, b)
			return dst
		}
	}
}

func appendI32(dst []byte, v int32) []byte {
	val := int64(v)
	for {
		b := byte(val & 0x7f)
		val >>= 7
		signBit := (b & 0x40) != 0
		done := (val == 0 && !signBit) || (val == -1 && signBit)
		if done {
			dst = append(dst, b)
			return dst
		}
		dst = append(dst, b|0x80)
	}
}

func appendI64(dst []byte, v int64) []byte {
	val := v
	for {
		b := byte(val & 0x7f)
		val >>= 7
		signBit := (b & 0x40) != 0
		done := (val == 0 && !signBit) || (val == -1 && signBit)
		if done {
			dst = append(dst, b)
			return dst
		}
		dst = append(dst, b|0x80)
	}
}

func valTypeToWasmByte(t valType) byte {
	switch t {
	case valTypeI64:
		return 0x7e
	case valTypeI32:
		return 0x7f
	case valTypeF64Bits:
		return 0x7c
	case valTypeF32Bits:
		return 0x7d
	default:
		return 0x7f
	}
}

func buildInitExpr(t valType, raw uint64) ([]byte, error) {
	expr := make([]byte, 0, 16)
	switch t {
	case valTypeI32:
		bits, err := u32FromUint64(raw, "i32 init expression")
		if err != nil {
			return nil, err
		}
		expr = append(expr, 0x41)
		expr = appendI32(expr, i32FromBits(bits))
	case valTypeI64:
		expr = append(expr, 0x42)
		expr = appendI64(expr, i64FromBits(raw))
	case valTypeF32Bits:
		bits, err := u32FromUint64(raw, "f32 init expression bits")
		if err != nil {
			return nil, err
		}
		expr = append(expr, 0x43)
		var data [4]byte
		binary.LittleEndian.PutUint32(data[:], bits)
		expr = append(expr, data[:]...)
	case valTypeF64Bits:
		expr = append(expr, 0x44)
		var data [8]byte
		binary.LittleEndian.PutUint64(data[:], raw)
		expr = append(expr, data[:]...)
	default:
		return nil, fmt.Errorf("unsupported val-type %d", t)
	}
	expr = append(expr, 0x0b)
	return expr, nil
}

func checkedMul8(a uint32) (uint32, error) {
	product := uint64(a) * 8
	if product > math.MaxUint32 {
		return 0, fmt.Errorf("overflow while computing %d * 8", a)
	}
	return uint32(product), nil
}

func importKey(module, name string) string {
	return module + "\x00" + name
}

func readBytes(mem api.Memory, ptr, length uint32) ([]byte, error) {
	if length == 0 {
		return []byte{}, nil
	}
	data, ok := mem.Read(ptr, length)
	if !ok {
		return nil, fmt.Errorf("out-of-bounds read at %d with length %d", ptr, length)
	}
	copied := make([]byte, len(data))
	copy(copied, data)
	return copied, nil
}

func readString(mem api.Memory, ptr, length uint32) (string, error) {
	data, err := readBytes(mem, ptr, length)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func normalizeGuestAlign(align uint32) uint32 {
	if align == 0 {
		return 1
	}
	return align
}

func normalizeGuestAllocSize(size uint32) uint32 {
	if size == 0 {
		return 1
	}
	return size
}

func lookupModuleRealloc(module api.Module) (api.Function, error) {
	realloc := module.ExportedFunction("cabi_realloc")
	if realloc == nil {
		realloc = module.ExportedFunction("cabi_realloc_wit_bindgen_0_46_0")
	}
	if realloc == nil {
		return nil, errors.New("guest allocator export not found")
	}

	return realloc, nil
}

func callReallocWithStack(
	ctx context.Context,
	realloc api.Function,
	scratch []uint64,
	ptr,
	oldSize,
	align,
	newSize uint32,
) (uint64, []uint64, error) {
	resultCount := len(realloc.Definition().ResultTypes())
	if resultCount != 1 {
		return 0, scratch, fmt.Errorf("unexpected realloc result arity %d", resultCount)
	}

	callStack := ensureUint64Stack(scratch, callStackLen(realloc, 4))
	callStack[0] = uint64(ptr)
	callStack[1] = uint64(oldSize)
	callStack[2] = uint64(align)
	callStack[3] = uint64(newSize)
	if err := realloc.CallWithStack(ctx, callStack); err != nil {
		return 0, callStack, err
	}
	return callStack[0], callStack, nil
}

func (g *guestModuleState) callRealloc(
	ctx context.Context,
	ptr,
	oldSize,
	align,
	newSize uint32,
) (uint64, error) {
	g.reallocMu.Lock()
	defer g.reallocMu.Unlock()

	result, scratch, err := callReallocWithStack(
		ctx,
		g.realloc,
		g.reallocStack,
		ptr,
		oldSize,
		align,
		newSize,
	)
	g.reallocStack = scratch
	return result, err
}

func (g *guestModuleState) alloc(ctx context.Context, size, align uint32) (uint32, error) {
	result, err := g.callRealloc(
		ctx,
		0,
		0,
		normalizeGuestAlign(align),
		normalizeGuestAllocSize(size),
	)
	if err != nil {
		return 0, err
	}
	ptr, err := u32FromUint64(result, "realloc pointer result")
	if err != nil {
		return 0, err
	}
	if ptr == 0 {
		return 0, errors.New("guest allocator returned null pointer")
	}
	return ptr, nil
}

func (g *guestModuleState) reallocBuffer(
	ctx context.Context,
	ptr,
	oldSize,
	align,
	newSize uint32,
) (uint32, error) {
	result, err := g.callRealloc(
		ctx,
		ptr,
		normalizeGuestAllocSize(oldSize),
		normalizeGuestAlign(align),
		normalizeGuestAllocSize(newSize),
	)
	if err != nil {
		return 0, err
	}
	newPtr, err := u32FromUint64(result, "realloc pointer result")
	if err != nil {
		return 0, err
	}
	if newPtr == 0 {
		return 0, errors.New("guest allocator returned null pointer")
	}
	return newPtr, nil
}

func allocWithRealloc(
	ctx context.Context,
	realloc api.Function,
	size,
	align uint32,
) (uint32, error) {
	result, _, err := callReallocWithStack(
		ctx,
		realloc,
		nil,
		0,
		0,
		normalizeGuestAlign(align),
		normalizeGuestAllocSize(size),
	)
	if err != nil {
		return 0, err
	}
	ptr, err := u32FromUint64(result, "realloc pointer result")
	if err != nil {
		return 0, err
	}
	if ptr == 0 {
		return 0, errors.New("guest allocator returned null pointer")
	}

	return ptr, nil
}

func (h *hostRuntime) allocWithModuleRealloc(
	ctx context.Context,
	module api.Module,
	size,
	align uint32,
) (uint32, error) {
	if guest := h.moduleGuest(module); guest != nil {
		return guest.alloc(ctx, size, align)
	}
	realloc, err := lookupModuleRealloc(module)
	if err != nil {
		return 0, err
	}
	return allocWithRealloc(ctx, realloc, size, align)
}

func (h *hostRuntime) moduleAllocAndWrite(
	ctx context.Context,
	module api.Module,
	data []byte,
) (uint32, uint32, error) {
	dataLen, err := u32FromLen(len(data), "module allocation length")
	if err != nil {
		return 0, 0, err
	}
	ptr, err := h.allocWithModuleRealloc(ctx, module, dataLen, 1)
	if err != nil {
		return 0, 0, err
	}

	if len(data) > 0 && !module.Memory().Write(ptr, data) {
		return 0, 0, fmt.Errorf("failed to write %d bytes to guest memory at %d", len(data), ptr)
	}

	return ptr, dataLen, nil
}

func (h *hostRuntime) writeUnitResultOK(mem api.Memory, retPtr uint32) {
	_ = mem.WriteUint32Le(retPtr, 0)
}

func (h *hostRuntime) writeUnitResultErr(ctx context.Context, caller api.Module, retPtr uint32, message string) {
	ptr, length, err := h.moduleAllocAndWrite(ctx, caller, []byte(message))
	if err != nil {
		ptr, length = 0, 0
	}
	mem := caller.Memory()
	_ = mem.WriteUint32Le(retPtr, 1)
	_ = mem.WriteUint32Le(retPtr+4, ptr)
	_ = mem.WriteUint32Le(retPtr+8, length)
}

func (h *hostRuntime) writeU64ResultOK(mem api.Memory, retPtr uint32, value uint64) {
	_ = mem.WriteUint32Le(retPtr, 0)
	_ = mem.WriteUint64Le(retPtr+8, value)
}

func (h *hostRuntime) writeU64ResultErr(ctx context.Context, caller api.Module, retPtr uint32, message string) {
	ptr, length, err := h.moduleAllocAndWrite(ctx, caller, []byte(message))
	if err != nil {
		ptr, length = 0, 0
	}
	mem := caller.Memory()
	_ = mem.WriteUint32Le(retPtr, 1)
	_ = mem.WriteUint32Le(retPtr+8, ptr)
	_ = mem.WriteUint32Le(retPtr+12, length)
}

func (h *hostRuntime) writeBytesResultOK(ctx context.Context, caller api.Module, retPtr uint32, data []byte) error {
	ptr, length, err := h.moduleAllocAndWrite(ctx, caller, data)
	if err != nil {
		return err
	}
	mem := caller.Memory()
	_ = mem.WriteUint32Le(retPtr, 0)
	_ = mem.WriteUint32Le(retPtr+4, ptr)
	_ = mem.WriteUint32Le(retPtr+8, length)
	return nil
}

func (h *hostRuntime) writeU64ListResultOK(ctx context.Context, caller api.Module, retPtr uint32, values []uint64) error {
	valueCount, err := u32FromLen(len(values), "uint64 result count")
	if err != nil {
		return err
	}
	rawLen, err := checkedMul8(valueCount)
	if err != nil {
		return err
	}
	ptr, err := h.allocWithModuleRealloc(ctx, caller, rawLen, 8)
	if err != nil {
		return err
	}
	mem := caller.Memory()
	for i, value := range values {
		index, convErr := u32FromLen(i, "uint64 result index")
		if convErr != nil {
			return convErr
		}
		offset := ptr + index*8
		if !mem.WriteUint64Le(offset, value) {
			return fmt.Errorf("failed to write %d uint64 values to guest memory at %d", len(values), ptr)
		}
	}
	_ = mem.WriteUint32Le(retPtr, 0)
	_ = mem.WriteUint32Le(retPtr+4, ptr)
	_ = mem.WriteUint32Le(retPtr+8, valueCount)
	return nil
}

func (h *hostRuntime) writeListResultErr(ctx context.Context, caller api.Module, retPtr uint32, message string) {
	ptr, length, err := h.moduleAllocAndWrite(ctx, caller, []byte(message))
	if err != nil {
		ptr, length = 0, 0
	}
	mem := caller.Memory()
	_ = mem.WriteUint32Le(retPtr, 1)
	_ = mem.WriteUint32Le(retPtr+4, ptr)
	_ = mem.WriteUint32Le(retPtr+8, length)
}
