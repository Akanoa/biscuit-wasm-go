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

}
