package main

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// InstantiateImportStubs instantiateImportStubs inspects the compiled module and creates host modules for each imported module,
// exporting functions that match the imported function signatures. For most imports we export no-op stubs, but
// for getrandom-related imports we provide real implementations that fill memory with random bytes.
func InstantiateImportStubs(ctx context.Context, runtime wazero.Runtime, c wazero.CompiledModule) error {
	imports := c.ImportedFunctions()
	if len(imports) == 0 {
		return nil
	}

	// Group imports by module name.
	builders := map[string]wazero.HostModuleBuilder{}
	for _, def := range imports {
		modName, name, isImport := def.Import()
		if !isImport {
			continue
		}
		builder, ok := builders[modName]
		if !ok {
			builder = runtime.NewHostModuleBuilder(modName)
			builders[modName] = builder
		}

		params := def.ParamTypes()
		results := def.ResultTypes()

		// Handle specific imports robustly using substring matches (wasm-bindgen adds mangled suffixes).
		switch {
		case containsAny(name, []string{"randomFillSync", "getRandomValues"}):
			// Entropy providers from getrandom -> fill (ptr,len) with random bytes
			builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
				mem := m.Memory()
				if mem == nil {
					return
				}
				if len(stack) >= 2 {
					ptr := uint32(stack[0])
					ln := uint32(stack[1])
					if ln > 0 {
						buf := make([]byte, ln)
						_, _ = rand.Read(buf)
						_ = mem.Write(ptr, buf)
					}
				}
			}), params, results).Export(name)
		case containsAny(name, []string{"wbg_crypto_", "wbg_msCrypto_", "wbg_process_", "wbg_versions_", "wbg_node_", "wbg_require_"}):
			// Return a non-zero value as a fake JS object handle or truthy flag when the signature expects a result.
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				if len(results) > 0 {
					// Set first result to 1 (works for i32/externref-like indices in wasm-bindgen glue)
					stack[0] = 1
				}
			}), params, results).Export(name)
		default:
			// Default: no-op stub
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				_ = stack
			}), params, results).Export(name)
		}
	}

	// Instantiate each host module.
	for modName, b := range builders {
		if _, err := b.Instantiate(ctx); err != nil {
			return fmt.Errorf("failed to instantiate host module %q: %w", modName, err)
		}
	}
	return nil
}

// containsAny reports whether s contains any of the substrings in subs.
func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && contains(s, sub) {
			return true
		}
	}
	return false
}

// small helper to avoid importing strings for a single Contains
func contains(s, sub string) bool {
	// simple substring search
	return len(sub) <= len(s) && (s == sub || (len(s) > 0 && (indexOf(s, sub) >= 0)))
}

func hasSuffix(s, suf string) bool {
	if len(suf) > len(s) {
		return false
	}
	return s[len(s)-len(suf):] == suf
}

// indexOf returns the index of sub in s or -1 if not present.
func indexOf(s, sub string) int {
	// naive search is enough for our small set
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
