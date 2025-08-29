package keypair

import (
	"biscuit-wasm-go/wasm"
)

type PublicKey struct {
	env wasm.WasmEnv
	ptr uint64
}

//func (self PublicKey) ToString() (string, error) {
//	if self.ptr == 0 {
//		return "", fmt.Errorf("public key not initialized")
//	}
//
//	function, err := self.env.GetFunction("public_key_toString")
//	if err != nil {
//		slog.Error("exported function 'public_key_toString' not found")
//		return "", err
//	}
//
//	return "", nil
//}
