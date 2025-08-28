package keypair

import (
	"context"
	"fmt"

	"github.com/tetratelabs/wazero/api"
)

type PublicKey struct {
	context context.Context
	module  api.Module
	ptr     uint64
}

func NonePublicKey(context context.Context, module api.Module) PublicKey {
	return PublicKey{context: context, module: module, ptr: 0}
}

func (self PublicKey) ToString() (string, error) {
	if self.ptr == 0 {
		return "", fmt.Errorf("public key not initialized")
	}

	function := self.module.ExportedFunction("public_key_toString")
	if function == nil {
		return "", fmt.Errorf("exported function 'public_key_toString' not found")
	}

	return "", nil
}
