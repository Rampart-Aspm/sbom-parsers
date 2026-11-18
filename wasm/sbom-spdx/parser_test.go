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

func TestSPDX_Wasm_ComplexGraph(t *testing.T) {
	ctx := context.Background()
	wasmPath := compileWasm(t)
	wasmCode, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("failed to read wasm module: %v", err)
	}

	data, err := os.ReadFile("testdata/complex.spdx.json")
	if err != nil {
		t.Fatalf("failed to read complex.spdx.json: %v", err)
	}

	start := time.Now()
	stdout, stderr, err := runWasm(ctx, t, wasmCode, data, nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("wasm execution failed: %v\nStderr: %s", err, string(stderr))
	}

	t.Logf("Parsed complex SPDX JSON in %v", elapsed)

	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	var (
		metadataFound  bool
		components     = make(map[string]map[string]any)
		edges          []map[string]any
		directEdgeCount int
		transitiveEdgeCount int
	)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal(line, &raw); err != nil {
			t.Fatalf("invalid json line: %s", string(line))
		}

		eventType, _ := raw["type"].(string)
		switch eventType {
		case "metadata":
			metadataFound = true
			if raw["format"] != "SPDX" {
				t.Errorf("expected format SPDX, got %v", raw["format"])
			}
			if raw["root_ref"] != "SPDXRef-Package-app" {
				t.Errorf("expected root_ref SPDXRef-Package-app, got %v", raw["root_ref"])
			}
		case "component":
			ref, _ := raw["ref"].(string)
			components[ref] = raw
		case "edge":
			edges = append(edges, raw)
			if direct, ok := raw["direct"].(bool); ok && direct {
				directEdgeCount++
			} else {
				transitiveEdgeCount++
			}
		}
	}

	if !metadataFound {
		t.Errorf("expected metadata event to be emitted")
	}
	if len(components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(components))
	}

	// Verify root package
	app := components["SPDXRef-Package-app"]
	if isRoot, ok := app["is_root"].(bool); !ok || !isRoot {
		t.Errorf("expected app to be root component, got %+v", app)
	}

	// Verify purl canonicalization
	ginPkg := components["SPDXRef-Package-gin"]
	if ginPkg["purl_base"] != "pkg:golang/github.com/gin-gonic/gin" {
		t.Errorf("expected gin purl_base, got %v", ginPkg["purl_base"])
	}

	// Verify edges
	if len(edges) != 2 {
		t.Fatalf("expected 2 dependency edges, got %d", len(edges))
	}
	if directEdgeCount != 1 || transitiveEdgeCount != 1 {
		t.Errorf("expected 1 direct edge and 1 transitive edge, got direct=%d, transitive=%d",
			directEdgeCount, transitiveEdgeCount)
	}
}

func TestSPDX_Wasm_SampleJSON(t *testing.T) {
	ctx := context.Background()
	wasmPath := compileWasm(t)
	wasmCode, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("failed to read wasm module: %v", err)
	}

	data, err := os.ReadFile("testdata/sample.spdx.json")
	if err != nil {
		t.Fatalf("failed to read sample.spdx.json: %v", err)
	}

	stdout, stderr, err := runWasm(ctx, t, wasmCode, data, nil)
	if err != nil {
		t.Fatalf("wasm execution failed: %v\nStderr: %s", err, string(stderr))
	}

	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	var compCount int
	for scanner.Scan() {
		var raw map[string]any
		_ = json.Unmarshal(scanner.Bytes(), &raw)
		if raw["type"] == "component" {
			compCount++
			if raw["name"] != "golang-jwt/jwt" {
				t.Errorf("expected name golang-jwt/jwt, got %v", raw["name"])
			}
			if raw["purl_base"] != "pkg:golang/github.com/golang-jwt/jwt/v5" {
				t.Errorf("expected purl_base, got %v", raw["purl_base"])
			}
		}
	}

	if compCount != 1 {
		t.Errorf("expected 1 component, got %d", compCount)
	}
}

func TestSPDX_Wasm_TagValue(t *testing.T) {
	ctx := context.Background()
	wasmPath := compileWasm(t)
	wasmCode, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("failed to read wasm module: %v", err)
	}

	data, err := os.ReadFile("testdata/sample.spdx")
	if err != nil {
		t.Fatalf("failed to read sample.spdx: %v", err)
	}

	stdout, stderr, err := runWasm(ctx, t, wasmCode, data, []string{"EXTRACT_VULNERABILITIES=true"})
	if err != nil {
		t.Fatalf("wasm execution failed: %v\nStderr: %s", err, string(stderr))
	}

	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	var (
		compFound bool
		vulnFound bool
	)
	for scanner.Scan() {
		var raw map[string]any
		_ = json.Unmarshal(scanner.Bytes(), &raw)
		switch raw["type"] {
		case "component":
			compFound = true
			if raw["name"] != "openssl" {
				t.Errorf("expected component openssl, got %v", raw["name"])
			}
			if raw["purl_base"] != "pkg:generic/openssl" {
				t.Errorf("expected purl_base pkg:generic/openssl, got %v", raw["purl_base"])
			}
		case "vulnerability":
			vulnFound = true
			if id, ok := raw["id"].(string); !ok || !strings.Contains(id, "openssl") {
				t.Errorf("expected vulnerability for openssl, got %v", raw["id"])
			}
		}
	}

	if !compFound {
		t.Errorf("expected openssl component to be emitted")
	}
	if !vulnFound {
		t.Errorf("expected CPE vulnerability to be extracted when EXTRACT_VULNERABILITIES=true")
	}
}
