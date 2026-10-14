// Command conformance runs spec/conformance against the Go port: go run ./cmd/conformance [dir]
package main

import (
	"fmt"
	"os"
	"path/filepath"

	sw "github.com/SmartTasksOrg/sf-smartwatch/ports/go/smartwatch"
)

func main() {
	dir := filepath.Join("..", "..", "spec", "conformance")
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	total, fails, err := sw.RunConformance(dir)
	if err != nil {
		fmt.Println("go: FAILED:", err)
		os.Exit(1)
	}
	for _, f := range fails {
		fmt.Println("FAIL", f)
	}
	if len(fails) > 0 {
		fmt.Printf("go: FAILED, %d of %d vectors\n", len(fails), total)
		os.Exit(1)
	}
	fmt.Printf("go: %d/%d vectors passed\n", total, total)
}
