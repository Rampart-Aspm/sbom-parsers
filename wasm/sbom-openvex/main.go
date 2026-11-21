package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	opts := Options{ExtractVEX: envTrue("EXTRACT_VEX")}
	if err := ParseOpenVEXStream(os.Stdin, os.Stdout, opts); err != nil {
		fmt.Fprintf(os.Stderr, "openvex sbom parser error: %v\n", err)
		os.Exit(1)
	}
}

func envTrue(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
