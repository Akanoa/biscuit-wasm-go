package main

import (
	keypairModule "biscuit-wasm-go/crypto/keypair"
	"biscuit-wasm-go/wasm"
	"context"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const WasmFile = "target/wasm32-unknown-unknown/release/biscuit_wasm_go.wasm"

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

func createkeypair(env wasm.WasmEnv, algorithm keypairModule.SignatureAlgorithm) *keypairModule.KeyPair {
	keypair := keypairModule.Invoke(env)

	if err := keypair.New(algorithm); err != nil {
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

	return keypair
}

func main() {
	env, err := wasm.InitWasm()
	if err != nil {
		panic(err)
	}

	//keypair1 := createkeypair(env, keypairModule.Ed25519)
	////createkeypair(module, ctx, keypairModule.Secp256r1)
	//
	//privateKey1, err := keypair1.GetPrivateKey()
	//if err != nil {
	//	println("keypair1.GetPrivateKey error:", err.Error())
	//	return
	//}
	//
	//privateKey1String, err := privateKey1.ToString()
	//if err != nil {
	//	println("privateKey1.ToString error:", err.Error())
	//}
	//fmt.Println("From Keypair", privateKey1String)

	//keypair2 := keypairModule.Invoke(module, ctx)
	//err = keypair2.FromPrivateKey(privateKey1)
	//if err != nil {
	//	println("keypair2.FromPrivateKey error:", err.Error())
	//	return
	//}
	//
	//privateKey2, err := keypair2.GetPrivateKey()
	//if err != nil {
	//	println("keypair2.GetPrivateKey error:", err.Error())
	//	return
	//}
	//
	//privateKey2String, err := privateKey2.ToString()
	//if err != nil {
	//	println("privateKey2.ToString error:", err.Error())
	//}
	//
	//fmt.Println("From Keypair", privateKey2String)

	privateKey3 := keypairModule.InvokePrivateKey(env)
	err = privateKey3.FromString("ed25519-private2/eacbce4ed1a4132e1c667ebe5f730f493197fd3def32027a87ea2233d5b55abf")
	if err != nil {
		println("privateKey3.FromString error:", err.Error())
	}

	privateKey3String, err := privateKey3.ToString()
	if err != nil {
		println("privateKey3.ToString error:", err.Error())
		return
	}
	fmt.Println("From PrivateKey", privateKey3String)

}
