# biscuit-wasm-go

A minimal Go application that loads and invokes a Rust WebAssembly (WASM) module using wazero. The Rust side re-exports functions from the biscuit-wasm crate, and the Go side provides host stubs for required imports so the module can run in a pure Go runtime.

## Overview
- Rust library crate (cdylib) compiled for `wasm32-unknown-unknown`.
- Go application uses [wazero](https://github.com/tetratelabs/wazero) to run the compiled `.wasm` in-process.
- To satisfy wasm-bindgen/getrandom imports, we dynamically create host modules in Go (see `bootstrap.go`). We provide:
  - Real randomness for `getRandomValues` / `randomFillSync` shims (fills memory with `crypto/rand`).
  - Truthy env-probe stubs for objects like `wbg_crypto_`, `wbg_process_`, etc., returning non-zero when a result is expected.

With these in place, the example call to `keypair_new` succeeds and the app prints:

```
Inside the keypair
```

## Prerequisites
- Rust (latest stable recommended)
- Rust target: `wasm32-unknown-unknown`
- Go 1.24 or later

Install the wasm target if you don’t have it:

```
rustup target add wasm32-unknown-unknown
```

## Build the WASM module
From the project root:

```
cargo build --release --target wasm32-unknown-unknown
```

This produces:
```
target/wasm32-unknown-unknown/release/biscuit_wasm_go.wasm
```

## Run the Go app
From the project root:

```
go run .
```

Expected output:
```
Inside the keypair
```

If you see an error like `keypair.New error: wasm error: unreachable`, ensure you have built the WASM with the correct target and that the Go runtime is running with our host stubs (see below).

## How it works (host import stubs)
The compiled WASM (via wasm-bindgen and crates like `getrandom`) imports several functions that would normally be provided by a JS host (Web APIs or Node). Since we run under wazero in Go, we must provide replacements:

- In `bootstrap.go`, `InstantiateImportStubs` inspects the compiled module’s imports and generates host modules with matching functions.
- For functions whose names contain `randomFillSync` or `getRandomValues`, we implement a real entropy provider: the Go host reads cryptographically secure random bytes and writes them into the WASM memory at `(ptr, len)`.
- For env-probe imports (names containing `wbg_crypto_`, `wbg_msCrypto_`, `wbg_process_`, `wbg_versions_`, `wbg_node_`, `wbg_require_`), we return a non-zero value when a result is expected. This simulates the presence of these objects so that Rust code paths don’t panic when unwrapping their availability.

This approach avoids panics like `wasm error: unreachable` that occur when `getrandom` cannot obtain entropy or when environment detection fails.

## Troubleshooting
- "wasm error: unreachable":
  - Make sure you rebuilt the WASM for `wasm32-unknown-unknown` in release mode.
  - Confirm that `InstantiateImportStubs` is called before instantiating the module (it is in `main.go`).
  - If you modified the Rust crate and added new imports, ensure the name substrings are covered by the stub matcher in `bootstrap.go`.
- Missing wasm file:
  - Ensure `target/wasm32-unknown-unknown/release/biscuit_wasm_go.wasm` exists. If not, run the Cargo build step above.

## Project layout
- `src/lib.rs` – Re-exports biscuit-wasm so its functions are available to the `.wasm`.
- `Cargo.toml` – Rust crate setup (cdylib, panic=abort for smaller code/clearer traps).
- `bootstrap.go` – Generates and instantiates host import stubs for wazero.
- `main.go` – Loads the `.wasm`, wires stubs, runs a sample call to `keypair_new`.
- `crypto/keypair/keypair.go` – Thin wrapper around the exported WASM function.

## Notes
- The stubs use substring matching on imported function names because wasm-bindgen mangles names. Adjust the match list if future dependencies introduce new import names.
- The example prints a message after a successful keypair creation call; extend it to handle the returned values as your application requires.
