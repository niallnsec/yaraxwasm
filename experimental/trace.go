package experimental

import (
	"fmt"
	"os"
	"sync"
)

var (
	uffdTraceEnabledOnce sync.Once
	uffdTraceEnabled     bool
)

func logUFFDTracef(format string, args ...any) {
	uffdTraceEnabledOnce.Do(func() {
		uffdTraceEnabled = os.Getenv("YARAX_UFFD_TRACE") != ""
	})
	if !uffdTraceEnabled {
		return
	}
	fmt.Fprintf(os.Stderr, "experimental: "+format+"\n", args...)
}
