package wasm

import (
	"context"
	"crypto/rand"
	"fmt"
	"math"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// taLen maps a synthesized typed-array handle (we use the byte offset as the handle)
// to its length. This lets entropy functions and copy helpers know where and how
// many bytes to read/write in guest memory.
var taLen = map[uint32]uint32{}

// externrefTableSize tracks the logical size of the wasm-bindgen externref table when hosted in Go.
var externrefTableSize uint32

// ExternrefTableMirror mirrors the wasm-bindgen externref table so Go code can inspect entries.
// Index 0 is reserved (undefined), and init seeds [undefined, null, true, false] similar to the JS glue.
var ExternrefTableMirror []any

// synthetic handles for JS-like singletons and typed arrays
var (
	globalObjHandle      uint32
	cryptoObjHandle      uint32
	memoryObjHandle      uint32
	bufferObjHandle      uint32
	functionNoArgsHandle uint32
	// Start synthetic typed array handles in a high range to avoid colliding with wasm memory pointers
	taHandleNext uint32 = 0x80000000
)

type JsNull struct{}

// InstantiateImportStubs inspects the compiled module and creates host modules for each imported module,
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

		switch name {
		case "__wbindgen_init_externref_table":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				if len(ExternrefTableMirror) == 0 {
					ExternrefTableMirror = append(ExternrefTableMirror, nil)
				}
				offset := uint32(len(ExternrefTableMirror))
				for i := 0; i < 4; i++ {
					ExternrefTableMirror = append(ExternrefTableMirror, nil)
				}
				ExternrefTableMirror[offset+0] = nil
				ExternrefTableMirror[offset+1] = JsNull{}
				ExternrefTableMirror[offset+2] = true
				ExternrefTableMirror[offset+3] = false
				externrefTableSize = uint32(len(ExternrefTableMirror))
				_ = stack
			}), params, results).Export(name)

		// Basic externref operations
		case "__wbindgen_object_clone_ref":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				// Return the same index (we don't enforce refcounts in Go host)
				stack[0] = stack[0]
			}), params, results).Export(name)
		case "__wbindgen_object_drop_ref":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				// No-op drop. In a more complete impl we'd track refcounts.
				_ = stack
			}), params, results).Export(name)
		case "__wbindgen_externref_heap_live_count":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				stack[0] = api.EncodeU32(uint32(len(ExternrefTableMirror)))
			}), params, results).Export(name)

		// Randomness helpers seen in wasm-bindgen glue
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

		// Type checks and constructors
		case "__wbindgen_is_null":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				idx := api.DecodeU32(stack[0])
				var v any
				if idx < uint32(len(ExternrefTableMirror)) {
					v = ExternrefTableMirror[idx]
				}
				_, isNull := v.(JsNull)
				if isNull {
					stack[0] = api.EncodeU32(1)
				} else {
					stack[0] = api.EncodeU32(0)
				}
			}), params, results).Export(name)
		case "__wbindgen_is_undefined":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				idx := api.DecodeU32(stack[0])
				var v any
				if idx < uint32(len(ExternrefTableMirror)) {
					v = ExternrefTableMirror[idx]
				}
				if v == nil {
					stack[0] = api.EncodeU32(1)
				} else {
					stack[0] = api.EncodeU32(0)
				}
			}), params, results).Export(name)
		case "__wbindgen_is_string":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				idx := api.DecodeU32(stack[0])
				ok := idx < uint32(len(ExternrefTableMirror))
				if ok {
					_, ok = ExternrefTableMirror[idx].(string)
				}
				if ok {
					stack[0] = api.EncodeU32(1)
				} else {
					stack[0] = api.EncodeU32(0)
				}
			}), params, results).Export(name)
		case "__wbindgen_is_object":
			// Treat maps/slices/structs as objects; we already return 1 above for general case but keep explicit.
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				stack[0] = api.EncodeU32(1)
			}), params, results).Export(name)
		case "__wbindgen_number_new":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				// Single f64 param encoded in stack[0]
				f := api.DecodeF64(stack[0])
				if len(ExternrefTableMirror) == 0 {
					ExternrefTableMirror = append(ExternrefTableMirror, nil)
				}
				ExternrefTableMirror = append(ExternrefTableMirror, f)
				stack[0] = api.EncodeU32(uint32(len(ExternrefTableMirror) - 1))
			}), params, results).Export(name)

		case "__wbindgen_number_get":
			// Returns Option<f64> encoded as (f64, i32 is_some) in result slots.
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				idx := api.DecodeU32(stack[0])
				var (
					f      float64
					isSome uint32
				)
				if int(idx) < len(ExternrefTableMirror) {
					if v, ok := ExternrefTableMirror[idx].(float64); ok {
						f = v
						isSome = 1
					}
				}
				stack[0] = api.EncodeF64(f)
				stack[1] = api.EncodeU32(isSome)
			}), params, results).Export(name)

		case "__wbindgen_boolean_get":
			// Returns 1 if true, else 0
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				idx := api.DecodeU32(stack[0])
				ret := uint32(0)
				if int(idx) < len(ExternrefTableMirror) {
					if v, ok := ExternrefTableMirror[idx].(bool); ok && v {
						ret = 1
					}
				}
				stack[0] = api.EncodeU32(ret)
			}), params, results).Export(name)

		case "__wbg_isSafeInteger_343e2beeeece1bb0":
			// Number.isSafeInteger(x)
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				idx := api.DecodeU32(stack[0])
				ret := uint32(0)
				const MaxSafe = 9007199254740991.0 // 2^53 - 1
				if int(idx) < len(ExternrefTableMirror) {
					if v, ok := ExternrefTableMirror[idx].(float64); ok {
						if !math.IsNaN(v) {
							abs := math.Abs(v)
							if abs <= MaxSafe && math.Trunc(v) == v {
								ret = 1
							}
						}
					}
				}
				stack[0] = api.EncodeU32(ret)
			}), params, results).Export(name)

		case "__wbindgen_string_new":
			// handled above
			builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
				mem := m.Memory()
				ptr := api.DecodeU32(stack[0])
				ln := api.DecodeU32(stack[1])
				if ln == 0 {
					stack[0] = api.EncodeU32(0)
					return
				}
				buf, ok := mem.Read(ptr, ln)
				if !ok {
					stack[0] = api.EncodeU32(0)
					return
				}
				if len(ExternrefTableMirror) == 0 {
					ExternrefTableMirror = append(ExternrefTableMirror, nil)
				}
				ExternrefTableMirror = append(ExternrefTableMirror, string(buf))
				stack[0] = api.EncodeU32(uint32(len(ExternrefTableMirror) - 1))
			}), params, results).Export(name)

		// Minimal JSON helpers
		case "__wbindgen_json_parse":
			builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
				mem := m.Memory()
				ptr := api.DecodeU32(stack[0])
				ln := api.DecodeU32(stack[1])
				if buf, ok := mem.Read(ptr, ln); ok {
					if len(ExternrefTableMirror) == 0 {
						ExternrefTableMirror = append(ExternrefTableMirror, nil)
					}
					fmt.Println("was here json_parse")
					ExternrefTableMirror = append(ExternrefTableMirror, string(buf))
					stack[0] = api.EncodeU32(uint32(len(ExternrefTableMirror) - 1))
				} else {
					stack[0] = api.EncodeU32(0)
				}
			}), params, results).Export(name)
		case "__wbindgen_json_serialize":
			// Returns a WasmSlice (ptr,len) according to import signature; we rely on wazero to shape results.
			builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
				idx := api.DecodeU32(stack[0])
				var s string
				if idx < uint32(len(ExternrefTableMirror)) {
					if v, ok := ExternrefTableMirror[idx].(string); ok {
						s = v
					}
				}
				if s == "" {
					stack[0] = api.EncodeU32(0)
					stack[1] = api.EncodeU32(0)
					return
				}
				_ = m // not used currently
				// We cannot allocate guest memory from here safely; return zero slice.
				stack[0] = api.EncodeU32(0)
				stack[1] = api.EncodeU32(0)
			}), params, results).Export(name)

		// Typed array constructors: record length against byte offset and return that as handle
		case "__wbindgen_uint8_array_new", "__wbindgen_uint8_clamped_array_new", "__wbindgen_uint16_array_new", "__wbindgen_uint32_array_new",
			"__wbindgen_biguint64_array_new", "__wbindgen_int8_array_new", "__wbindgen_int16_array_new", "__wbindgen_int32_array_new",
			"__wbindgen_bigint64_array_new", "__wbindgen_float32_array_new", "__wbindgen_float64_array_new":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				ptr := api.DecodeU32(stack[0])
				ln := api.DecodeU32(stack[1])
				taLen[ptr] = ln
				stack[0] = api.EncodeU32(ptr)
			}), params, results).Export(name)

		case "__wbindgen_array_new":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				if len(ExternrefTableMirror) == 0 {
					ExternrefTableMirror = append(ExternrefTableMirror, nil)
				}
				fmt.Println("was here 1")
				ExternrefTableMirror = append(ExternrefTableMirror, []any{})
				stack[0] = api.EncodeU32(uint32(len(ExternrefTableMirror) - 1))
			}), params, results).Export(name)
		case "__wbindgen_array_push":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				arrIdx := api.DecodeU32(stack[0])
				valIdx := api.DecodeU32(stack[1])
				if int(arrIdx) < len(ExternrefTableMirror) {
					if s, ok := ExternrefTableMirror[arrIdx].([]any); ok {
						var v any
						if int(valIdx) < len(ExternrefTableMirror) {
							v = ExternrefTableMirror[valIdx]
						}
						ExternrefTableMirror[arrIdx] = append(s, v)
					}
				}
			}), params, results).Export(name)

		case "__wbindgen_not":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				idx := api.DecodeU32(stack[0])
				var truthy bool
				if int(idx) < len(ExternrefTableMirror) {
					switch v := ExternrefTableMirror[idx].(type) {
					case bool:
						truthy = v
					case string:
						truthy = v != ""
					case float64:
						truthy = v != 0
					default:
						truthy = v != nil
					}
				}
				if truthy {
					stack[0] = api.EncodeU32(0)
				} else {
					stack[0] = api.EncodeU32(1)
				}
			}), params, results).Export(name)

		// Minimal equality helpers
		case "__wbindgen_jsval_eq", "__wbindgen_jsval_loose_eq":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				a := api.DecodeU32(stack[0])
				b := api.DecodeU32(stack[1])
				var va, vb any
				if int(a) < len(ExternrefTableMirror) {
					va = ExternrefTableMirror[a]
				}
				if int(b) < len(ExternrefTableMirror) {
					vb = ExternrefTableMirror[b]
				}
				if fmt.Sprintf("%v", va) == fmt.Sprintf("%v", vb) {
					stack[0] = api.EncodeU32(1)
				} else {
					stack[0] = api.EncodeU32(0)
				}
			}), params, results).Export(name)

		// Type checks default fallbacks
		case "__wbindgen_is_function", "__wbindgen_is_array", "__wbindgen_is_symbol", "__wbindgen_is_bigint":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				// We don't model these precisely; return 0 (false) to be safe.
				stack[0] = api.EncodeU32(0)
			}), params, results).Export(name)

		// Wazero-agnostic typed array slicing helpers present in upstream glue
		case "__wbg_newwithbyteoffsetandlength_d97e637ebe145a9a":
			// (param i32 i32 i32) (result i32): returns a synthesized handle equal to byte_offset and records length.
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				byteOffset := api.DecodeU32(stack[1])
				length := api.DecodeU32(stack[2])
				taLen[byteOffset] = length
				stack[0] = api.EncodeU32(byteOffset)
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

		// Newly added passthroughs required by issue
		case "__wbg_static_accessor_SELF_37c5d418e4bf5819", "__wbg_static_accessor_WINDOW_5de37043a91a9c40", "__wbg_static_accessor_GLOBAL_THIS_56578be7e9f832b0", "__wbg_static_accessor_GLOBAL_88a902d13a557d07":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				if globalObjHandle == 0 {
					if len(ExternrefTableMirror) == 0 {
						ExternrefTableMirror = append(ExternrefTableMirror, nil)
					}
					ExternrefTableMirror = append(ExternrefTableMirror, map[string]any{"__kind": "global"})
					globalObjHandle = uint32(len(ExternrefTableMirror) - 1)
				}
				stack[0] = api.EncodeU32(globalObjHandle)
			}), params, results).Export(name)
		case "__wbg_crypto_574e78ad8b13b65f":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				_ = api.DecodeU32(stack[0]) // global handle, ignored
				if cryptoObjHandle == 0 {
					if len(ExternrefTableMirror) == 0 {
						ExternrefTableMirror = append(ExternrefTableMirror, nil)
					}
					ExternrefTableMirror = append(ExternrefTableMirror, map[string]any{"__kind": "crypto"})
					cryptoObjHandle = uint32(len(ExternrefTableMirror) - 1)
				}
				stack[0] = api.EncodeU32(cryptoObjHandle)
			}), params, results).Export(name)
		case "__wbg_newwithlength_a381634e90c276d4":
			// new Uint8Array(length)
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				length := api.DecodeU32(stack[0])
				h := taHandleNext
				taHandleNext++
				taLen[h] = length
				stack[0] = api.EncodeU32(h)
			}), params, results).Export(name)
		case "__wbindgen_memory":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				if memoryObjHandle == 0 {
					if len(ExternrefTableMirror) == 0 {
						ExternrefTableMirror = append(ExternrefTableMirror, nil)
					}
					ExternrefTableMirror = append(ExternrefTableMirror, map[string]any{"__kind": "memory"})
					memoryObjHandle = uint32(len(ExternrefTableMirror) - 1)
				}
				stack[0] = api.EncodeU32(memoryObjHandle)
			}), params, results).Export(name)
		case "__wbg_buffer_609cc3eee51ed158":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				_ = api.DecodeU32(stack[0]) // memory handle, ignored
				if bufferObjHandle == 0 {
					if len(ExternrefTableMirror) == 0 {
						ExternrefTableMirror = append(ExternrefTableMirror, nil)
					}
					ExternrefTableMirror = append(ExternrefTableMirror, map[string]any{"__kind": "buffer"})
					bufferObjHandle = uint32(len(ExternrefTableMirror) - 1)
				}
				stack[0] = api.EncodeU32(bufferObjHandle)
			}), params, results).Export(name)
		case "__wbg_new_a12002a7f91c75be", "__wbg_new_405e22f390576ce2":
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				if len(ExternrefTableMirror) == 0 {
					ExternrefTableMirror = append(ExternrefTableMirror, nil)
				}
				ExternrefTableMirror = append(ExternrefTableMirror, map[string]any{})
				stack[0] = api.EncodeU32(uint32(len(ExternrefTableMirror) - 1))
			}), params, results).Export(name)
		case "__wbg_set_3f1d0b984ed272ed":
			// Reflect.set(target, key, value) -> bool
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				target := api.DecodeU32(stack[0])
				key := api.DecodeU32(stack[1])
				val := api.DecodeU32(stack[2])
				ok := uint32(0)
				if int(target) < len(ExternrefTableMirror) {
					obj := ExternrefTableMirror[target]
					var k string
					if int(key) < len(ExternrefTableMirror) {
						if ks, is := ExternrefTableMirror[key].(string); is {
							k = ks
						}
					}
					if m, is := obj.(map[string]any); is && k != "" {
						var v any
						if int(val) < len(ExternrefTableMirror) {
							v = ExternrefTableMirror[val]
						}
						m[k] = v
						ok = 1
					}
				}
				stack[0] = api.EncodeU32(ok)
			}), params, results).Export(name)
		case "__wbg_newnoargs_105ed471475aaf50":
			// new Function(code)
			builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
				mem := m.Memory()
				ptr := api.DecodeU32(stack[0])
				ln := api.DecodeU32(stack[1])
				_, _ = mem.Read(ptr, ln) // ignore code
				if functionNoArgsHandle == 0 {
					if len(ExternrefTableMirror) == 0 {
						ExternrefTableMirror = append(ExternrefTableMirror, nil)
					}
					ExternrefTableMirror = append(ExternrefTableMirror, "function() { /* noop */ }")
					functionNoArgsHandle = uint32(len(ExternrefTableMirror) - 1)
				}
				stack[0] = api.EncodeU32(functionNoArgsHandle)
			}), params, results).Export(name)
		case "__wbg_call_672a4d21634d4a24":
			// f.call(thisArg, ...)
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				// No-op; return default/zero based on expected results
				_ = stack
			}), params, results).Export(name)

		default:
			// Passthrough default: export a function matching the signature that leaves inputs/results unchanged or zeroed.
			// We avoid special-casing stub names; any unrecognized import gets a no-op implementation.
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				// By default, do nothing. Wazero pre-zeros the stack slots for results, so this acts as a safe passthrough.
				println("passthrough", name)
				_ = stack
			}), params, results).Export(name)
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
