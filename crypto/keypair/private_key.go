package keypair

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/tetratelabs/wazero/api"
)

type PrivateKey struct {
	context context.Context
	module  api.Module
	ptr     uint64
}

func NonePrivateKey(context context.Context, module api.Module) PrivateKey {
	return PrivateKey{context: context, module: module, ptr: 0}
}

func (self PrivateKey) ToString() (string, error) {
	if self.ptr == 0 {
		return "", fmt.Errorf("public key not initialized")
	}

	function := self.module.ExportedFunction("privatekey_toString")
	if function == nil {
		return "", fmt.Errorf("exported function 'privatekey_toString' not found")
	}

	malloc := self.module.ExportedFunction("__wbindgen_malloc")
	free := self.module.ExportedFunction("__wbindgen_free")

	results, err := malloc.Call(self.context, 8, 1)
	if err != nil {
		panic(err)
	}
	outPtr := results[0]

	_, err = function.Call(self.context, outPtr, self.ptr)
	if err != nil {
		panic(err)
	}

	// étape 3 : lire ptr,len depuis mémoire wasm
	mem := self.module.Memory()
	buf, ok := mem.Read(uint32(outPtr), 8)
	if !ok {
		panic("cannot read return area")
	}
	strPtr := binary.LittleEndian.Uint32(buf[0:4])
	strLen := binary.LittleEndian.Uint32(buf[4:8])

	// étape 4 : lire la vraie string UTF-8
	strBytes, ok := mem.Read(strPtr, strLen)
	if !ok {
		panic("cannot read string")
	}
	s := string(strBytes)

	_, _ = free.Call(self.context, uint64(strPtr), uint64(strLen))
	_, _ = free.Call(self.context, outPtr, 8)

	return s, nil
}
