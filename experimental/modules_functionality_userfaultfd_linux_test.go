//go:build linux

package experimental_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/niallnsec/yaraxwasm"
	"github.com/niallnsec/yaraxwasm/internal/moduletest"
)

func TestWASMModuleFunctionalityWithExperimentalUserfaultfdAllocator(t *testing.T) {
	if os.Getenv("YARAX_EXPERIMENTAL_UFFD") != "1" {
		t.Skip("set YARAX_EXPERIMENTAL_UFFD=1 to run userfaultfd-backed integration tests")
	}

	initialiseExperimentalAllocator(t)
	maybeStartTimedProfiles(t)

	moduletest.Run(t, moduletest.Harness{
		Name: "scan-reader-at-userfaultfd",
		Scan: scanModuleFixtureReaderAtWithUserfaultfd,
	})
}

func scanModuleFixtureReaderAtWithUserfaultfd(
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
