package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	extractVulnsFlag := flag.Bool("extract-vulns", false, "Extract embedded CVEs/vulnerabilities from VDR section")
	flag.Parse()

	extractVulns := *extractVulnsFlag
	if env := os.Getenv("EXTRACT_VULNERABILITIES"); env == "true" || env == "1" {
		extractVulns = true
	}

	opts := Options{
		ExtractVulnerabilities: extractVulns,
	}

	if err := ParseCycloneDXStream(os.Stdin, os.Stdout, opts); err != nil {
		fmt.Fprintf(os.Stderr, "cyclonedx sbom parser error: %v\n", err)
		os.Exit(1)
	}
}
