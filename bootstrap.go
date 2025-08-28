package main

import (
	"context"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// InstantiateImportStubs instantiateImportStubs inspects the compiled module and creates host modules for each imported module,
// exporting no-op functions that match the imported function signatures. This satisfies imports such as
// "__wbindgen_placeholder__" without needing to know exact names ahead of time.
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
		// Create a no-op function body that writes zeroes to result slots.
		stub := api.GoFunc(func(ctx context.Context, stack []uint64) {
			// Nothing to do. Leave default zero values in stack for results.
			// If there are results, ensure at least that we don't panic.
			_ = stack
		})
		builder.NewFunctionBuilder().WithGoFunction(stub, params, results).Export(name)
	}

	// Instantiate each host module.
	for modName, b := range builders {
		if _, err := b.Instantiate(ctx); err != nil {
			return fmt.Errorf("failed to instantiate host module %q: %w", modName, err)
		}
	}
	return nil
}
