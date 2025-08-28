package main

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// taLen maps a synthesized typed-array handle (we use the byte offset as the handle)
// to its length. This lets entropy functions and copy helpers know where and how
// many bytes to read/write in guest memory.
var taLen = map[uint32]uint32{}

// instantiateImportStubs inspects the compiled module and creates host modules for each imported module,
// exporting no-op functions that match the imported function signatures. This satisfies imports such as
// "__wbindgen_placeholder__" without needing to know exact names ahead of time.
func InstantiateImportStubs(ctx context.Context, runtime wazero.Runtime, c wazero.CompiledModule) error {
	imports := c.ImportedFunctions()
	if len(imports) == 0 {
		return nil
	}

	// We will only implement real entropy providers from the Rust perspective,
	// and refuse to generate generic stubs.
	builders := map[string]wazero.HostModuleBuilder{}
	for _, def := range imports {
		modName, name, isImport := def.Import()
		if !isImport {
			continue
		}

		if modName != "__wbindgen_placeholder__" && modName != "__wbindgen_externref_xform__" {
			return fmt.Errorf("unsupported import module: %s.%s", modName, name)
		}

		// Ensure we have a builder for this module
		builder, ok := builders[modName]
		if !ok {
			builder = runtime.NewHostModuleBuilder(modName)
			builders[modName] = builder
		}

		params := def.ParamTypes()
		results := def.ResultTypes()

		// Only implement the real random byte fillers and required wasm-bindgen helpers.
		if modName == "__wbindgen_externref_xform__" {
			switch name {
			case "__wbindgen_externref_table_grow":
				// (param i32) (result i32): identity
				builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
					// leave stack[0]
				}), params, results).Export(name)
				continue
			case "__wbindgen_externref_table_set_null":
				// (param i32) -> ()
				builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
					_ = stack
				}), params, results).Export(name)
				continue
			default:
				return fmt.Errorf("unsupported import function: %s.%s", modName, name)
			}
		}

		switch name {
		case "__wbg_randomFillSync_ac0988aba3254290", "__wbg_getRandomValues_b8f5dbd5f3995a9e":
			// Signature in this wasm-bindgen glue: (param i32 i32) -> () where params are (obj_handle, typed_array_handle)
			// We synthesize typed array handles equal to byte offsets into wasm memory and track their lengths.
			fn := api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
				mem := m.Memory()
				_ = api.DecodeU32(stack[0]) // obj_handle not needed
				arr := api.DecodeU32(stack[1])
				ln := taLen[arr]
				if ln == 0 {
					return
				}
				buf := make([]byte, ln)
				if n, err := rand.Read(buf); err == nil {
					if uint32(n) < ln {
						for i := n; uint32(i) < ln; i++ {
							buf[i] = 0
						}
					}
					_ = mem.Write(arr, buf)
				}
			})
			builder.NewFunctionBuilder().WithGoModuleFunction(fn, params, results).Export(name)
		case "__wbindgen_copy_to_typed_array":
			// Signature in WAT shows (param i32 i32 i32): (src_handle, src_len, dst_ptr)
			// We don't have JS objects, so we ignore src_handle and fill dst_ptr with secure random bytes of length src_len.
			fn := api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
				mem := m.Memory()
				_ = api.DecodeU32(stack[0]) // src_handle ignored
				srcLen := api.DecodeU32(stack[1])
				dstPtr := api.DecodeU32(stack[2])
				if srcLen == 0 {
					return
				}
				buf := make([]byte, srcLen)
				if n, err := rand.Read(buf); err == nil {
					if uint32(n) < srcLen {
						for i := n; uint32(i) < srcLen; i++ {
							buf[i] = 0
						}
					}
					_ = mem.Write(dstPtr, buf)
				}
			})
			builder.NewFunctionBuilder().WithGoModuleFunction(fn, params, results).Export(name)
		case "__wbindgen_object_drop_ref":
			// (param i32) -> () : ignore drops
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				// no-op
			}), params, results).Export(name)
		case "__wbindgen_object_clone_ref":
			// (param i32) (result i32) -> identity
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				// leave stack[0] as-is
			}), params, results).Export(name)
		case "__wbindgen_describe":
			// (param i32) -> () used by wasm-bindgen for type descriptions; no-op
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				_ = stack
			}), params, results).Export(name)
		case "__wbg_crypto_574e78ad8b13b65f", "__wbg_msCrypto_a61aeb35a24c1329":
			// (param i32) (result i32) -> identity: pass-through a non-null handle
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				// leave stack[0] unchanged
			}), params, results).Export(name)
		case "__wbindgen_is_object":
			// (param i32) (result i32) -> return 1 (truthy)
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				stack[0] = api.EncodeU32(1)
			}), params, results).Export(name)
		case "__wbindgen_is_function", "__wbindgen_is_string", "__wbindgen_is_undefined":
			// (param i32) (result i32) -> return 0 (falsy)
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				stack[0] = api.EncodeU32(0)
			}), params, results).Export(name)
		case "__wbg_process_dc0fbacc7c1c06f7", "__wbg_versions_c01dfd4722a88165", "__wbg_node_905d3e251edff8a2":
			// Node detection related: return 0 (null/undefined) to avoid Node path
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				stack[0] = api.EncodeU32(0)
			}), params, results).Export(name)
		case "__wbg_require_60cc747a6bc5215a":
			// (result i32) -> return 0 to indicate require() not available
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				stack[0] = api.EncodeU32(0)
			}), params, results).Export(name)
		case "__wbindgen_string_new":
			// (param i32 i32) (result i32) -> return 0 as dummy string handle
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				stack[0] = api.EncodeU32(0)
			}), params, results).Export(name)
		case "__wbg_newnoargs_105ed471475aaf50":
			// (param i32 i32) (result i32) -> return 0
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				stack[0] = api.EncodeU32(0)
			}), params, results).Export(name)
		case "__wbg_call_672a4d21634d4a24":
			// (param i32 i32) (result i32) -> return 0
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				stack[0] = api.EncodeU32(0)
			}), params, results).Export(name)
		case "__wbg_call_7cccdd69e0791ae2":
			// (param i32 i32 i32) (result i32) -> return 0
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				stack[0] = api.EncodeU32(0)
			}), params, results).Export(name)
		case "__wbg_static_accessor_GLOBAL_THIS_56578be7e9f832b0", "__wbg_static_accessor_SELF_37c5d418e4bf5819", "__wbg_static_accessor_WINDOW_5de37043a91a9c40", "__wbg_static_accessor_GLOBAL_88a902d13a557d07":
			// (result i32) -> return 0
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				stack[0] = api.EncodeU32(0)
			}), params, results).Export(name)
		case "__wbg_buffer_609cc3eee51ed158":
			// (param i32) (result i32) -> return 0
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				stack[0] = api.EncodeU32(0)
			}), params, results).Export(name)
		case "__wbg_newwithbyteoffsetandlength_d97e637ebe145a9a":
			// (param i32 i32 i32) (result i32): returns a synthesized handle equal to byte_offset and records length.
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				byteOffset := api.DecodeU32(stack[1])
				length := api.DecodeU32(stack[2])
				taLen[byteOffset] = length
				stack[0] = api.EncodeU32(byteOffset)
			}), params, results).Export(name)
		case "__wbg_new_a12002a7f91c75be":
			// (param i32) (result i32) -> return 0
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				stack[0] = api.EncodeU32(0)
			}), params, results).Export(name)
		case "__wbg_set_65595bdd868b3009":
			// (param i32 i32 i32) -> copy from src_handle to dst_ptr using recorded length
			builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
				mem := m.Memory()
				// dst_array_handle := api.DecodeU32(stack[0]) // unused
				srcHandle := api.DecodeU32(stack[1])
				dstPtr := api.DecodeU32(stack[2])
				ln := taLen[srcHandle]
				if ln == 0 {
					return
				}
				if buf, ok := mem.Read(srcHandle, ln); ok {
					_ = mem.Write(dstPtr, buf)
				}
			}), params, results).Export(name)
		case "__wbg_newwithlength_a381634e90c276d4":
			// (param i32) (result i32) -> return 0
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				stack[0] = api.EncodeU32(0)
			}), params, results).Export(name)
		case "__wbg_subarray_aa9065fa9dc5df96":
			// (param i32 i32 i32) (result i32): return a new handle = base+begin and record length = end-begin
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				base := api.DecodeU32(stack[0])
				begin := api.DecodeU32(stack[1])
				end := api.DecodeU32(stack[2])
				newHandle := base + begin
				var l uint32
				if end >= begin {
					l = end - begin
				}
				taLen[newHandle] = l
				stack[0] = api.EncodeU32(newHandle)
			}), params, results).Export(name)
		case "__wbindgen_throw":
			// (param i32 i32) -> () read string and panic
			builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
				mem := m.Memory()
				ptr := api.DecodeU32(stack[0])
				len := api.DecodeU32(stack[1])
				msgBytes, ok := mem.Read(ptr, len)
				if !ok {
					panic("__wbindgen_throw: out of memory range")
				}
				panic("__wbindgen_throw: " + string(msgBytes))
			}), params, results).Export(name)
		case "__wbindgen_memory":
			// (result i32) -> return 0 as dummy memory handle
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				stack[0] = api.EncodeU32(0)
			}), params, results).Export(name)
		default:
			// Provide minimal stubs for common wasm-bindgen placeholder helpers to avoid panics
			if modName == "__wbindgen_placeholder__" {
				switch name {
				case "__wbindgen_number_get":
					// wasm-bindgen often uses (param i32 i32) -> () to write a flag and f64 into wasm memory.
					// However signatures can vary with transforms. We just match the compiled signature dynamically.
					// If there is 1 result, return 0. If there are 2 results, return 0 in both. If there are params, zero them out.
					builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
						// If function returns something, leave zeros on the stack (already zeroed by wazero before call).
						// If it expects to set a non-null sentinel, put 0.
						for i := range stack {
							stack[i] = 0
						}
					}), params, results).Export(name)
					break
				case "__wbindgen_number_new":
					// (param f64) (result i32) usually allocates a JS number handle; we return 0 (dummy handle)
					builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
						stack[0] = api.EncodeU32(0)
					}), params, results).Export(name)
					break
				case "__wbindgen_boolean_get":
					// Return 0
					builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
						stack[0] = api.EncodeU32(0)
					}), params, results).Export(name)
					break
				default:
					// Generic fallback: export a no-op stub matching the signature, returning zeros.
					builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
						for i := range stack {
							stack[i] = 0
						}
					}), params, results).Export(name)
				}
				break
			}
			return fmt.Errorf("unsupported import function: %s.%s", modName, name)
		}
	}

	// Instantiate each supported host module.
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
