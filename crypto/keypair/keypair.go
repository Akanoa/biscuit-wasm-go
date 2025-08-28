package keypair

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

type SignatureAlgorithm int

const (
	Ed25519   SignatureAlgorithm = iota
	Secp256r1                    = iota
)

type KeyPair struct {
	module  api.Module
	context context.Context
}

func Invoke(module api.Module, context context.Context) *KeyPair {
	KeyPair := &KeyPair{module: module, context: context}
	return KeyPair
}

func (self *KeyPair) New(signatureAlgorithm SignatureAlgorithm) {

	function := self.module.ExportedFunction("keypair_new")
	if function == nil {
		panic("exported function 'keypair_new' not found")
	}

	result, err := function.Call(self.context, uint64(signatureAlgorithm))
	if err != nil {
		panic(err)
	}

	if len(result) == 0 {
		panic("no result returned from keypair_new")
	}

	println("Inside the keypair")
}

//func KeyPair(signatureAlgorithm SignatureAlgorithm) {
//	println("Inside the keypair", signatureAlgorithm)
//}
