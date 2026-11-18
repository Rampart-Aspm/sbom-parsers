package main_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

func compileWasm(t *testing.T) string {
	t.Helper()
	wasmPath := filepath.Join(t.TempDir(), "parser.wasm")
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", wasmPath, "main.go", "parser.go")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile wasm module: %v\nOutput: %s", err, string(out))
	}
	return wasmPath
}

func runWasm(ctx context.Context, t *testing.T, wasmCode []byte, input []byte, envVars []string) ([]byte, []byte, error) {
	t.Helper()
	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)

	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	stdin := bytes.NewReader(input)
	var stdout, stderr bytes.Buffer

	cfg := wazero.NewModuleConfig().
		WithStdin(stdin).
		WithStdout(&stdout).
		WithStderr(&stderr).
		WithArgs("parser.wasm")

	for _, e := range envVars {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			cfg = cfg.WithEnv(parts[0], parts[1])
		}
	}

	compiled, err := r.CompileModule(ctx, wasmCode)
	if err != nil {
		return nil, nil, err
	}
	defer compiled.Close(ctx)

	mod, err := r.InstantiateModule(ctx, compiled, cfg)
	if mod != nil {
		_ = mod.Close(ctx)
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

func TestCycloneDX_Wasm_DropwizardLargeGraph(t *testing.T) {
	ctx := context.Background()
	wasmPath := compileWasm(t)
	wasmCode, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("failed to read wasm module: %v", err)
	}

	dropwizardData, err := os.ReadFile("testdata/dropwizard.cdx.json")
	if err != nil {
		t.Fatalf("failed to read dropwizard.cdx.json: %v", err)
	}

	start := time.Now()
	stdout, stderr, err := runWasm(ctx, t, wasmCode, dropwizardData, nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("wasm execution failed: %v\nStderr: %s", err, string(stderr))
	}

	t.Logf("Parsed Dropwizard CycloneDX (380KB) in %v", elapsed)

	// Parse JSONL events from stdout
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	var (
		metadataCount    int
		componentCount   int
		edgeCount        int
		directEdgeCount  int
		componentsWithPurl int
	)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var raw map[string]any
		if err := json.Unmarshal(line, &raw); err != nil {
			t.Fatalf("invalid json line emitted: %s", string(line))
		}

		eventType, _ := raw["type"].(string)
		switch eventType {
		case "metadata":
			metadataCount++
			if raw["format"] != "CycloneDX" {
				t.Errorf("expected format CycloneDX, got %v", raw["format"])
			}
			t.Logf("Metadata: specVersion=%v, rootRef=%v", raw["spec_version"], raw["root_ref"])

		case "component":
			componentCount++
			if purl, ok := raw["purl"].(string); ok && purl != "" {
				componentsWithPurl++
				if raw["purl_base"] == "" {
					t.Errorf("component %v has purl %s but missing purl_base", raw["name"], purl)
				}
			}

		case "edge":
			edgeCount++
			if direct, ok := raw["direct"].(bool); ok && direct {
				directEdgeCount++
			}
		}
	}

	if metadataCount != 1 {
		t.Errorf("expected exactly 1 metadata event, got %d", metadataCount)
	}
	if componentCount < 100 {
		t.Errorf("expected >= 100 components, got %d", componentCount)
	}
	if edgeCount < 50 {
		t.Errorf("expected >= 50 edges, got %d", edgeCount)
	}
	if directEdgeCount == 0 {
		t.Errorf("expected some direct dependency edges, got 0")
	}

	t.Logf("Results: components=%d (purl=%d), total edges=%d (direct edges=%d)",
		componentCount, componentsWithPurl, edgeCount, directEdgeCount)
}

func TestCycloneDX_Wasm_JuiceShop(t *testing.T) {
	ctx := context.Background()
	wasmPath := compileWasm(t)
	wasmCode, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("failed to read wasm module: %v", err)
	}

	juiceShopData, err := os.ReadFile("testdata/juice-shop.cdx.json")
	if err != nil {
		t.Fatalf("failed to read juice-shop.cdx.json: %v", err)
	}

	start := time.Now()
	stdout, stderr, err := runWasm(ctx, t, wasmCode, juiceShopData, nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("wasm execution failed: %v\nStderr: %s", err, string(stderr))
	}

	t.Logf("Parsed OWASP Juice Shop CycloneDX (726KB) in %v", elapsed)

	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	componentCount := 0
	for scanner.Scan() {
		var raw map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &raw); err == nil {
			if raw["type"] == "component" {
				componentCount++
			}
		}
	}

	if componentCount < 200 {
		t.Errorf("expected >= 200 components in Juice Shop, got %d", componentCount)
	}
	t.Logf("Extracted %d components from Juice Shop", componentCount)
}

func TestCycloneDX_Wasm_VulnerabilitiesOption(t *testing.T) {
	ctx := context.Background()
	wasmPath := compileWasm(t)
	wasmCode, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("failed to read wasm module: %v", err)
	}

	// Payload with both components and embedded vulnerabilities (VDR)
	vdrPayload := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"components": [
			{"bom-ref": "pkg:npm/lodash@4.17.20", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"}
		],
		"dependencies": [
			{"ref": "pkg:npm/lodash@4.17.20", "dependsOn": []}
		],
		"vulnerabilities": [
			{
				"id": "CVE-2021-23337",
				"description": "Command Injection in lodash",
				"ratings": [{"severity": "high", "score": 7.2}],
				"cwes": [78],
				"affects": [{"ref": "pkg:npm/lodash@4.17.20"}]
			}
		]
	}`)

	// Run 1: Default (EXTRACT_VULNERABILITIES not set or false) -> Vulnerabilities should be IGNORED
	{
		stdout, stderr, err := runWasm(ctx, t, wasmCode, vdrPayload, []string{"EXTRACT_VULNERABILITIES=false"})
		if err != nil {
			t.Fatalf("run 1 failed: %v\nStderr: %s", err, string(stderr))
		}

		vulnCount := 0
		compCount := 0
		scanner := bufio.NewScanner(bytes.NewReader(stdout))
		for scanner.Scan() {
			var raw map[string]any
			_ = json.Unmarshal(scanner.Bytes(), &raw)
			if raw["type"] == "vulnerability" {
				vulnCount++
			}
			if raw["type"] == "component" {
				compCount++
			}
		}

		if compCount != 1 {
			t.Errorf("expected 1 component, got %d", compCount)
		}
		if vulnCount != 0 {
			t.Errorf("expected 0 vulnerabilities when EXTRACT_VULNERABILITIES=false, got %d", vulnCount)
		}
	}

	// Run 2: EXTRACT_VULNERABILITIES=true -> Vulnerabilities should be INGESTED
	{
		stdout, stderr, err := runWasm(ctx, t, wasmCode, vdrPayload, []string{"EXTRACT_VULNERABILITIES=true"})
		if err != nil {
			t.Fatalf("run 2 failed: %v\nStderr: %s", err, string(stderr))
		}

		vulnCount := 0
		var vulnID, vulnSev string
		scanner := bufio.NewScanner(bytes.NewReader(stdout))
		for scanner.Scan() {
			var raw map[string]any
			_ = json.Unmarshal(scanner.Bytes(), &raw)
			if raw["type"] == "vulnerability" {
				vulnCount++
				vulnID, _ = raw["id"].(string)
				vulnSev, _ = raw["severity"].(string)
			}
		}

		if vulnCount != 1 {
			t.Fatalf("expected 1 vulnerability when EXTRACT_VULNERABILITIES=true, got %d", vulnCount)
		}
		if vulnID != "CVE-2021-23337" || vulnSev != "high" {
			t.Errorf("expected CVE-2021-23337 with high severity, got %s / %s", vulnID, vulnSev)
		}
	}
}

func TestCycloneDX_Wasm_XML(t *testing.T) {
	ctx := context.Background()
	wasmPath := compileWasm(t)
	wasmCode, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("failed to read compiled wasm: %v", err)
	}

	xmlPayload, err := os.ReadFile("testdata/sample.cdx.xml")
	if err != nil {
		t.Fatalf("failed to read XML fixture: %v", err)
	}

	stdout, stderr, err := runWasm(ctx, t, wasmCode, xmlPayload, []string{"EXTRACT_VULNERABILITIES=true"})
	if err != nil {
		t.Fatalf("run failed: %v\nStderr: %s", err, string(stderr))
	}

	compCount := 0
	vulnCount := 0
	var vulnID, vulnSev string

	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	for scanner.Scan() {
		var raw map[string]any
		_ = json.Unmarshal(scanner.Bytes(), &raw)
		if raw["type"] == "component" {
			compCount++
		}
		if raw["type"] == "vulnerability" {
			vulnCount++
			vulnID, _ = raw["id"].(string)
			vulnSev, _ = raw["severity"].(string)
		}
	}

	if compCount != 1 {
		t.Errorf("expected 1 component, got %d", compCount)
	}
	if vulnCount != 1 {
		t.Fatalf("expected 1 vulnerability from XML, got %d", vulnCount)
	}
	if vulnID != "CVE-2021-44228" || vulnSev != "critical" {
		t.Errorf("expected CVE-2021-44228 critical, got %s / %s", vulnID, vulnSev)
	}
}
