package keypair

import (
	"context"
	"fmt"

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
	ptr     uint64
}

func Invoke(module api.Module, context context.Context) *KeyPair {
	KeyPair := &KeyPair{module: module, context: context, ptr: 0}
	return KeyPair
}

func (self *KeyPair) New(signatureAlgorithm SignatureAlgorithm) error {
	function := self.module.ExportedFunction("keypair_new")
	if function == nil {
		return fmt.Errorf("exported function 'keypair_new' not found")
	}

	result, err := function.Call(self.context, uint64(signatureAlgorithm))
	if err != nil {
		return fmt.Errorf("keypair_new failed: %w", err)
	}

	if len(result) == 0 {
		return fmt.Errorf("no result returned from keypair_new")
	}

	self.ptr = result[0]

	return nil
}

func (self *KeyPair) GetPublicKey() (PublicKey, error) {

	if self.ptr == 0 {
		return NonePublicKey(self.context, self.module), fmt.Errorf("keypair not initialized")
	}

	function := self.module.ExportedFunction("keypair_getPublicKey")
	if function == nil {
		return NonePublicKey(self.context, self.module), fmt.Errorf("exported function 'keypair_getPublicKey' not found")
	}

	result, err := function.Call(self.context, uint64(self.ptr))

	if err != nil {
		return NonePublicKey(self.context, self.module), fmt.Errorf("keypair_getPublicKey failed: %w", err)
	}

	return PublicKey{
		ptr:     result[0],
		module:  self.module,
		context: self.context,
	}, nil
}

func (self *KeyPair) GetPrivateKey() (PrivateKey, error) {

	if self.ptr == 0 {
		return NonePrivateKey(self.context, self.module), fmt.Errorf("keypair not initialized")
	}

	function := self.module.ExportedFunction("keypair_getPrivateKey")
	if function == nil {
		return NonePrivateKey(self.context, self.module), fmt.Errorf("exported function 'keypair_getPrivateKey' not found")
	}

	result, err := function.Call(self.context, self.ptr)

	if err != nil {
		return NonePrivateKey(self.context, self.module), fmt.Errorf("keypair_getPrivateKey failed: %w", err)
	}

	return PrivateKey{
		ptr:     result[0],
		module:  self.module,
		context: self.context,
	}, nil
}

//func KeyPair(signatureAlgorithm SignatureAlgorithm) {
//	println("Inside the keypair", signatureAlgorithm)
//}
