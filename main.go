package main

import (
	"context"
	"fmt"
	"os"

	keypairModule "biscuit-wasm-go/crypto/keypair"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const wasmFile = "target/wasm32-unknown-unknown/release/biscuit_wasm_go.wasm"

const addFunction = "add"

func closeRuntime(runtime wazero.Runtime, ctx context.Context) {
	if runtime.Close(ctx) != nil {
		panic("failed to close runtime")
	}
}

func closeWasmModule(module api.Module, goContext context.Context) {
	if module.Close(goContext) != nil {
		panic("failed to close module")
	}
}

func createkeypair(module api.Module, goContext context.Context) {
	keypair := keypairModule.Invoke(module, goContext)

	if err := keypair.New(keypairModule.Ed25519); err != nil {
		println("keypair.New error:", err.Error())
	}

	privateKey, err := keypair.GetPrivateKey()
	if err != nil {
		println("keypair.GetPrivateKey error:", err.Error())
	}

	fmt.Printf("Privatekey %+v\n", privateKey)

	privateKeyString, err := privateKey.ToString()
	if err != nil {
		println("privateKey.ToString error:", err.Error())
	}
	fmt.Printf("PrivateKeyString %s\n", privateKeyString)
}

func main() {
	goContext := context.Background()

	// Create a new runtime
	runtime := wazero.NewRuntime(goContext)
	defer closeRuntime(runtime, goContext)

	sourceWasm, err := os.ReadFile(wasmFile)
	if err != nil {
		panic(err)
	}

	// Compile module
	compiled, err := runtime.CompileModule(goContext, sourceWasm)
	if err != nil {
		panic(err)
	}

	// Auto-instantiate host stubs for any imported functions (e.g., from "__wbindgen_placeholder__").
	if err := InstantiateImportStubs(goContext, runtime, compiled); err != nil {
		panic(err)
	}

	// Use default module config so the module's start function (if any) runs.
	wasmConfig := wazero.NewModuleConfig()

	module, err := runtime.InstantiateModule(goContext, compiled, wasmConfig)
	if err != nil {
		panic(err)
	}
	defer closeWasmModule(module, goContext)

	createkeypair(module, goContext)
	createkeypair(module, goContext)

	//add := module.ExportedFunction(addFunction)
	//if add == nil {
	//	panic("exported function 'add' not found")
	//}

	//// Prepare data in wasm memory and pass (ptr, len) as raw C ABI slice
	//mem := module.Memory()
	//if mem == nil {
	//	panic("module has no exported memory")
	//}
	//
	//data := []byte("toto")
	//// Naive placement: write at offset 0x100 (avoid potential null region)
	//const offset = uint32(0x100)
	//if ok := mem.Write(offset, data); !ok {
	//	panic("failed to write data into wasm memory")
	//}
	//
	//// Call add(a: i64, b: i64, data: &[u8]) -> i64
	//// wazero uses uint64 for all stack values; i64 is passed as uint64 bitwise
	//result, err := add.Call(goContext, uint64(1), uint64(2), uint64(offset), uint64(len(data)), 1)
	//if err != nil {
	//	panic(err)
	//}
	//
	//if len(result) == 0 {
	//	panic("no result returned from add")
	//}
	//// The function returns i64; wazero uses uint64 for stack values.
	//println(uint64(result[0]))

}
