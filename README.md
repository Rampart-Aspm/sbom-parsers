# Rampart Native SBOM Parsers

This repository contains the official Software Bill of Materials (SBOM) parsers for the **Rampart ASPM** platform. Parsers translate software supply chain inventories, dependency relationship graphs, and embedded Vulnerability Disclosure Reports (VDR) into canonical, structured events streamed over standard output.

---

## Architecture & Design Principles

Rampart eliminates monolithic, hardcoded SBOM readers in favor of decoupled, out-of-process WebAssembly engines:

1. **WebAssembly (WASM / WASI):**
   - High-throughput parsers written in Go and compiled targeting `GOOS=wasip1 GOARCH=wasm`.
   - Executed inside Rampart using the memory-safe [Wazero](https://wazero.io/) WebAssembly runtime without cgo or host filesystem access.
   - Strictly isolated with enforced memory limits (default 256MB) and execution timeouts.
   - Packaged and distributed as minimal scratch OCI artifacts on GitHub Packages (`ghcr.io/rampart-aspm/sbom-parsers/<name>`).

2. **Full CycloneDX JSON & XML Native Support:**
   - Both JSON and XML representations of CycloneDX v1.4, v1.5, and v1.6 are decoded directly inside the WASM sandbox.
   - Automatically parses components, licenses, hashes, package URLs (purl), and dependency trees.
   - Natively extracts CycloneDX Vulnerability Disclosure Reports (VDR), emitting both inventory and vulnerabilities without requiring external tools.

3. **SPDX 2.2 & 2.3 Comprehensive Graph Parsing:**
   - Ingests SPDX JSON, YAML, and Tag-Value documents.
   - Resolves package hierarchies, checksums, external references, and `DEPENDS_ON` relationship graphs.

4. **Anchore Syft Ingestion:**
   - Ingests Syft artifact catalogs with native artifact metadata, purls, and dependency graphs.

5. **Streaming JSONL Protocol:**
   - Parsers stream newline-delimited JSON events to `stdout`:
     - **Components:** `domain.SBOMComponent` (name, version, purl, cpe, license, direct/transitive flag).
     - **Dependency Edges:** `domain.DependencyEdge` (fromRef, toRef, scope).
     - **VDR Vulnerabilities:** `domain.RawFinding` (when present in CycloneDX VDR).
   - Informational diagnostics and warnings are logged to `stderr`.

---

## Parsers Directory

| Parser | Format | Specifications Supported | Features | OCI Image |
|---|---|---|---|---|
| `sbom-cyclonedx` | CycloneDX | v1.2, v1.3, v1.4, v1.5, v1.6 (JSON & XML) | Components, dependencies, purl/CPE normalization, VDR vulnerabilities | `ghcr.io/rampart-aspm/sbom-parsers/sbom-cyclonedx:latest` |
| `sbom-spdx` | SPDX | v2.2, v2.3 (JSON, YAML, Tag-Value) | Packages, dependency relationships (`DEPENDS_ON`, `CONTAINS`), licenses | `ghcr.io/rampart-aspm/sbom-parsers/sbom-spdx:latest` |
| `sbom-syft` | Anchore Syft | Syft JSON schema | Artifact catalog as components, artifact relationships as dependency edges (assets only, no findings) | `ghcr.io/rampart-aspm/sbom-parsers/sbom-syft:latest` |

---

## Kubernetes CRD Specification

Each parser is declared in Kubernetes using the `ClusterSBOMParser` CRD:

```yaml
apiVersion: rampart.aspm.dev/v1alpha1
kind: ClusterSBOMParser
metadata:
  name: sbom-cyclonedx
spec:
  format: cyclonedx
  runtime: wasm
  version: "1.0.0"
  description: "CycloneDX SBOM parser (JSON/XML) with component dependency graph and VDR vulnerabilities"
  detect:
    filenames:
      - "*cyclonedx*.json"
      - "*cyclonedx*.xml"
      - "*.cdx.json"
      - "*.cdx.xml"
    probes:
      - jsonHasKeys:
          - bomFormat
      - contains:
          - "<bom"
  source:
    oci: ghcr.io/rampart-aspm/sbom-parsers/sbom-cyclonedx:latest
  limits:
    maxMemoryMB: 256
    timeoutSeconds: 60
```

---

## Building & Compiling WASM Modules

### Prerequisites
- Go 1.23+ with `wasip1` support

### Compile a WASM Parser
```bash
cd wasm/sbom-cyclonedx
GOOS=wasip1 GOARCH=wasm go build -trimpath -ldflags="-s -w" -o parser.wasm main.go
```

### Run Tests Locally
All parsers execute end-to-end tests against real-world SBOM fixtures (Dropwizard, JuiceShop, XML catalogs, SPDX packages) using Wazero:
```bash
go test -v ./...
```

---

## Packaging & OCI Distribution

Each parser contains a minimal `Dockerfile`:
```dockerfile
FROM scratch
COPY parser.wasm /parser.wasm
ENTRYPOINT ["/parser.wasm"]
```

### Automated CI/CD
GitHub Actions workflow (`.github/workflows/ci.yml`):
1. Discovers all WASM SBOM parsers in `wasm/`.
2. Cross-compiles to `wasip1/wasm`.
3. Runs the test suite via Wazero.
4. Builds minimal OCI container images.
5. Publishes artifacts to GitHub Container Registry (`ghcr.io/rampart-aspm/sbom-parsers/<name>`).
6. Signs OCI digests using Cosign keyless signing.
7. Attests SLSA Level 3 build provenance.

---

## License
Apache-2.0
