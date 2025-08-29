package keypair

import (
	"biscuit-wasm-go/wasm"
	"fmt"
	"log/slog"
)

type SignatureAlgorithm int

const (
	Ed25519   SignatureAlgorithm = iota
	Secp256r1                    = iota
)

type KeyPair struct {
	env wasm.WasmEnv
	ptr uint64
}

func Invoke(env wasm.WasmEnv) *KeyPair {
	KeyPair := &KeyPair{env: env, ptr: 0}
	return KeyPair
}

func (self *KeyPair) New(signatureAlgorithm SignatureAlgorithm) error {
	function, err := self.env.GetFunction("keypair_new")
	if err != nil {
		return err
	}

	result, err := self.env.Call(function, uint64(signatureAlgorithm))
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
		slog.Error("keypair not initialized")
		return PublicKey{}, fmt.Errorf("keypair not initialized")
	}

	function, err := self.env.GetFunction("keypair_getPublicKey")
	if function != nil {
		slog.Error("exported function 'keypair_getPublicKey' not found")
		return PublicKey{}, err
	}

	result, err := self.env.Call(function, self.ptr)
	if err != nil {
		slog.Error("keypair_getPublicKey failed", slog.Any("err", err))
		return PublicKey{}, err
	}

	return PublicKey{
		ptr: result[0],
		env: self.env,
	}, nil
}

func (self *KeyPair) GetPrivateKey() (PrivateKey, error) {

	if self.ptr == 0 {
		return PrivateKey{}, fmt.Errorf("keypair not initialized")
	}

	function, err := self.env.GetFunction("keypair_getPrivateKey")
	if err != nil {
		slog.Error("exported function 'keypair_getPrivateKey' not found")
		return PrivateKey{}, err
	}

	result, err := self.env.Call(function, self.ptr)
	if err != nil {
		slog.Error("keypair_getPrivateKey failed", slog.Any("err", err))
		return PrivateKey{}, err
	}

	return PrivateKey{
		ptr: result[0],
		env: self.env,
	}, nil
}

func (self *KeyPair) FromPrivateKey(privateKey PrivateKey) error {

	function, err := self.env.GetFunction("keypair_fromPrivateKey")
	if err != nil {
		slog.Error("exported function 'keypair_fromPrivateKey' not found")
		return err
	}

	result, err := self.env.Call(function, privateKey.ptr)

	if err != nil {
		slog.Error("keypair_fromPrivateKey failed", slog.Any("err", err))
		return err
	}

	if len(result) == 0 {
		return fmt.Errorf("no result returned from keypair_fromPrivateKey")
	}

	self.ptr = result[0]

	return nil
}
