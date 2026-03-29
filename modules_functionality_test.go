package yaraxwasm_test

import (
	"bytes"
	"testing"

	"github.com/niallnsec/yaraxwasm"
	"github.com/niallnsec/yaraxwasm/internal/moduletest"
)

func TestWASMModuleFunctionality(t *testing.T) {
	for _, harness := range []moduletest.Harness{
		{
			Name: "scan",
			Scan: scanModuleFixtureData,
		},
		{
			Name: "scan-reader-at-copy",
			Scan: scanModuleFixtureReaderAt,
		},
	} {
		t.Run(harness.Name, func(t *testing.T) {
			moduletest.Run(t, harness)
		})
	}
}

func scanModuleFixtureData(
	_ *testing.T,
	rules *yaraxwasm.Rules,
	data []byte,
	cfg moduletest.ScanConfig,
) (*yaraxwasm.ScanResults, error) {
	scanner := yaraxwasm.NewScanner(rules)
	defer scanner.Destroy()

	if cfg.ModuleOutput != nil {
		if err := scanner.SetModuleOutput(cfg.ModuleOutput); err != nil {
			return nil, err
		}
	}
	if cfg.ConsoleOutput != nil {
		scanner.SetConsoleOutput(cfg.ConsoleOutput)
	}

	return scanner.Scan(data)
}

func scanModuleFixtureReaderAt(
	_ *testing.T,
	rules *yaraxwasm.Rules,
	data []byte,
	cfg moduletest.ScanConfig,
) (*yaraxwasm.ScanResults, error) {
	scanner := yaraxwasm.NewScanner(rules)
	defer scanner.Destroy()

	if cfg.ModuleOutput != nil {
		if err := scanner.SetModuleOutput(cfg.ModuleOutput); err != nil {
			return nil, err
		}
	}
	if cfg.ConsoleOutput != nil {
		scanner.SetConsoleOutput(cfg.ConsoleOutput)
	}

	reader := bytes.NewReader(data)
	return scanner.ScanReaderAt(reader, int64(len(data)))
}
