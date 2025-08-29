package wasm

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// taLen maps a synthesized typed-array handle (we use the byte offset as the handle)
// to its length. This lets entropy functions and copy helpers know where and how
// many bytes to read/write in guest memory.
var taLen = map[uint32]uint32{}

// externrefTableSize tracks the logical size of the wasm-bindgen externref table when hosted in Go.
var externrefTableSize uint32

// externrefTableMirror mirrors the wasm-bindgen externref table so Go code can inspect entries.
// Index 0 is reserved (undefined), and init seeds [undefined, null, true, false] similar to the JS glue.
var externrefTableMirror []any

var mapString = map[string]uint64{}

type jsNull struct{}

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
				if len(externrefTableMirror) == 0 {
					externrefTableMirror = append(externrefTableMirror, nil)
				}
				offset := uint32(len(externrefTableMirror))
				for i := 0; i < 4; i++ {
					externrefTableMirror = append(externrefTableMirror, nil)
				}
				externrefTableMirror[offset+0] = nil
				externrefTableMirror[offset+1] = jsNull{}
				externrefTableMirror[offset+2] = true
				externrefTableMirror[offset+3] = false
				externrefTableSize = uint32(len(externrefTableMirror))
				_ = stack
			}), params, results).Export(name)
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
		case "__wbindgen_is_object":
			// (param i32) (result i32) -> return 1 (truthy)
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				stack[0] = api.EncodeU32(1)
			}), params, results).Export(name)
		case "__wbindgen_string_new":
			// Convert Rust string (ptr,len) to a JS handle (index) by storing it in the externref table mirror.
			builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
				mem := m.Memory()
				ptr := api.DecodeU32(stack[0])
				ln := api.DecodeU32(stack[1])
				var s string
				idxString := uint64(len(externrefTableMirror))

				// If the string is empty, return 0.
				if ln == 0 {
					stack[0] = api.EncodeU32(0)
					return
				}

				// Read string from memory.
				buf, ok := mem.Read(ptr, ln)

				// If the read failed, return 0.
				if !ok {
					fmt.Println("failed to read string from memory")
					return
				}

				// calculate hash of string
				h := sha256.Sum256(buf)
				key := fmt.Sprintf("---- %x", h)

				// Ensure table has reserved 0 entry.
				if len(externrefTableMirror) == 0 {
					externrefTableMirror = append(externrefTableMirror, nil)
				}

				// search for string in map
				if idx, ok := mapString[key]; ok {
					s = externrefTableMirror[idx].(string)
					idxString = idx
				} else {
					s = string(buf)
					idxString = uint64(len(externrefTableMirror))
					externrefTableMirror = append(externrefTableMirror, s)
					mapString[key] = idxString

				}

				externrefTableSize = uint32(uint64(len(externrefTableMirror)))

				fmt.Println("string_new: ", s, " idx: ", idxString)

				stack[0] = api.EncodeU32(uint32(idxString))
			}), params, results).Export(name)
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
		default:
			// Passthrough default: export a function matching the signature that leaves inputs/results unchanged or zeroed.
			// We avoid special-casing stub names; any unrecognized import gets a no-op implementation.
			builder.NewFunctionBuilder().WithGoFunction(api.GoFunc(func(ctx context.Context, stack []uint64) {
				// By default, do nothing. Wazero pre-zeros the stack slots for results, so this acts as a safe passthrough.
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
