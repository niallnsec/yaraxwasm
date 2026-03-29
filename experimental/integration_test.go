package experimental_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/niallnsec/yaraxwasm"
	"github.com/niallnsec/yaraxwasm/experimental"

	"github.com/stretchr/testify/require"
)

func TestScanFileWithExperimentalMmapAllocator(t *testing.T) {
	require.NoError(t, yaraxwasm.Initialise(experimental.UseMmapMemoryAllocator()))

	rules, err := yaraxwasm.Compile(`rule t { strings: $a = "mapped" condition: $a }`)
	require.NoError(t, err)
	defer rules.Destroy()
	scanner := yaraxwasm.NewScanner(rules)
	defer scanner.Destroy()

	file := filepath.Join(t.TempDir(), "mapped.bin")
	require.NoError(t, os.WriteFile(file, []byte("mapped data"), 0o600))

	results, err := scanner.ScanFile(file)
	require.NoError(t, err)
	require.Len(t, results.MatchingRules(), 1)
}
