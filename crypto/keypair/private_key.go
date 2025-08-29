package keypair

import (
	"biscuit-wasm-go/wasm"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
)

type PrivateKey struct {
	env wasm.WasmEnv
	ptr uint64
}

func InvokePrivateKey(env wasm.WasmEnv) PrivateKey {
	return PrivateKey{env: env, ptr: 0}
}

func (self PrivateKey) ToString() (string, error) {
	if self.ptr == 0 {
		slog.Error("private key not initialized")
		return "", fmt.Errorf("private key not initialized")
	}

	function, err := self.env.GetFunction("privatekey_toString")
	if err != nil {
		slog.Error("exported function 'privatekey_toString' not found")
		return "", err
	}

	outPtr, err := self.env.Malloc(8)
	if err != nil {
		slog.Error("malloc failed", slog.Any("err", err))
		return "", err
	}

	_, err = self.env.Call(function, outPtr, self.ptr)
	if err != nil {
		slog.Error("privatekey_toString failed", slog.Any("err", err))
		return "", err
	}

	return self.env.GetStringValueFromPointer(outPtr)
}

func (self *PrivateKey) FromString(data string) error {
	// Note: Go strings are UTF-8 already. We must copy bytes into WASM memory
	// and pass (ptr, len) according to wasm-bindgen ABI.

	function, err := self.env.GetFunction("privatekey_fromString")
	if err != nil {
		return err
	}

	mem, err := self.env.GetMemory()
	if err != nil {
		return fmt.Errorf("exported memory not found")
	}

	size := uint64(16)

	// Allocate return area (3 u32 values: value_ptr, error_ptr, is_err)
	retPtr, err := self.env.Malloc(size)
	if err != nil {
		return fmt.Errorf("malloc for return area failed: %w", err)
	}

	// Prepare UTF-8 bytes from data
	bytes := []byte(data)
	// Allocate buffer for string bytes
	strPtr, err := self.env.Malloc(uint64(len(bytes)))
	if err != nil {
		_ = self.env.Free(retPtr, size)
		return fmt.Errorf("malloc for string failed: %w", err)
	}

	// Write bytes into memory
	if ok := mem.Write(uint32(strPtr), bytes); !ok {

		_ = self.env.Free(retPtr, size)
		_ = self.env.Free(strPtr, uint64(len(bytes)))

		return fmt.Errorf("cannot write string bytes to wasm memory")
	}

	// Call: privatekey_fromString(out_ptr, str_ptr, str_len)
	_, err = self.env.Call(function, retPtr, strPtr, uint64(len(bytes)))
	if err != nil {
		_ = self.env.Free(retPtr, size)
		_ = self.env.Free(strPtr, uint64(len(bytes)))
		return fmt.Errorf("privatekey_fromString failed: %w", err)
	}

	// Read result triple
	buf, ok := mem.Read(uint32(retPtr), uint32(size))
	if !ok {
		_ = self.env.Free(retPtr, size)
		_ = self.env.Free(strPtr, uint64(len(bytes)))
		return fmt.Errorf("cannot read return area")
	}
	valuePtr := binary.LittleEndian.Uint32(buf[0:4])
	errPtr := binary.LittleEndian.Uint32(buf[4:8])
	isErr := int32(binary.LittleEndian.Uint32(buf[8:12]))

	// Free the temporary inputs and return area
	_ = self.env.Free(retPtr, size)
	_ = self.env.Free(strPtr, uint64(len(bytes)))

	if isErr != 0 {

		serr, err := self.env.GetError(uint64(errPtr))
		if err != nil {
			return fmt.Errorf("cannot get error string: %w", err)
		}
		return errors.New(serr)
	}

	self.ptr = uint64(valuePtr)
	return nil
}
