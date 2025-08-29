package wasm

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const wasmFile = "target/wasm32-unknown-unknown/release/biscuit_wasm_go.wasm"

type WasmEnv struct {
	Ctx    context.Context
	Module api.Module
}

func (env WasmEnv) GetFunction(name string) (api.Function, error) {
	function := env.Module.ExportedFunction(name)
	if function == nil {
 	slog.Error("exported function not found", slog.String("name", name))
		return nil, fmt.Errorf("exported function '%s' not found", name)
	}
	return function, nil
}

func (env WasmEnv) GetMemory() (api.Memory, error) {
	memory := env.Module.Memory()
	if memory == nil {
		return nil, fmt.Errorf("exported memory '%s' not found", "default")
	}
	return memory, nil
}

func (env WasmEnv) Call(function api.Function, params ...uint64) ([]uint64, error) {
	return function.Call(env.Ctx, params...)
}

func CloseRuntime(runtime wazero.Runtime, ctx context.Context) {
	if runtime.Close(ctx) != nil {

		panic("failed to close runtime")
	}
}

func CloseWasmModule(module api.Module, goContext context.Context) {
	if module.Close(goContext) != nil {
		panic("failed to close module")
	}
}

func InitWasm() (WasmEnv, error) {
	ctx := context.Background()
	// Create a new runtime
	runtime := wazero.NewRuntime(ctx)

	sourceWasm, err := os.ReadFile(wasmFile)
	if err != nil {
 	slog.Error("Unable to read wasm file", slog.String("file", wasmFile), slog.Any("err", err))
		panic(nil)
	}

	// Compile module
	compiled, err := runtime.CompileModule(ctx, sourceWasm)
	if err != nil {
 	slog.Error("Unable to compile wasm file", slog.String("file", wasmFile), slog.Any("err", err))
		panic(nil)
	}

	// Auto-instantiate host stubs for any imported functions (e.g., from "__wbindgen_placeholder__").
	if err := InstantiateImportStubs(ctx, runtime, compiled); err != nil {
 	slog.Error("Unable to instantiate import stubs", slog.Any("err", err))
		panic(nil)
	}

	// Use default module config so the module's start function (if any) runs.
	wasmConfig := wazero.NewModuleConfig()

	module, err := runtime.InstantiateModule(ctx, compiled, wasmConfig)

	if err != nil {
 	slog.Error("Unable to instantiate module", slog.Any("err", err))
		panic(nil)
	}

	return WasmEnv{
		Ctx:    ctx,
		Module: module,
	}, nil
}

func (env WasmEnv) Free(ptr uint64, length uint64) error {
	free, err := env.GetFunction("__wbindgen_free")
	if err != nil {
 	slog.Error("exported function not found", slog.String("name", "__wbindgen_free"))
		return err
	}
	_, err = env.Call(free, ptr, length, 1)
	return err
}

func (env WasmEnv) Malloc(length uint64) (uint64, error) {
	malloc, err := env.GetFunction("__wbindgen_malloc")
	if err != nil {
 	slog.Error("exported function not found", slog.String("name", "__wbindgen_malloc"))
		return 0, err
	}
	results, err := env.Call(malloc, length, 1)
	if err != nil {
		slog.Error("malloc failed", slog.Any("err", err))
		return 0, err
	}

	if len(results) != 1 {
		slog.Error("malloc failed: unexpected return value")
		return 0, fmt.Errorf("malloc failed: unexpected return value")
	}

	return results[0], nil
}

func (env WasmEnv) GetStringValueFromPointer(ptr uint64) (string, error) {

	// étape 3 : lire ptr,len depuis mémoire wasm
	mem := env.Module.Memory()
	buf, ok := mem.Read(uint32(ptr), 8)
	if !ok {
		slog.Error("cannot read return area 2222")
		return "", fmt.Errorf("cannot read return area")
	}
	strPtr := binary.LittleEndian.Uint32(buf[0:4])
	strLen := binary.LittleEndian.Uint32(buf[4:8])

	fmt.Println("strPtr:", strPtr, "strLen:", strLen)

	// étape 4 : lire la vraie string UTF-8
	strBytes, ok := mem.Read(strPtr, strLen)
	if !ok {
		panic("cannot read string")
	}
	stringData := string(strBytes)

	err := env.Free(uint64(strPtr), uint64(strLen))
	if err != nil {
 	slog.Error("cannot free string", slog.Uint64("ptr", uint64(strPtr)), slog.Uint64("len", uint64(strLen)))
		return "", err
	}

	return stringData, nil
}
