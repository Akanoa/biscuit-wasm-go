package keypair

import (
	"context"
	"testing"

	"github.com/tetratelabs/wazero/api"
)

type EnvPrivateKey struct {
	context context.Context
	module  api.Module
}

func initWasm() EnvPrivateKey {
	Wasm
	ctx := context.Background()

	return EnvPrivateKey{}
}

func TestPrivateKey_FromString(t *testing.T) {
	testimonialPrivateKey := InvokePrivateKey()
}
