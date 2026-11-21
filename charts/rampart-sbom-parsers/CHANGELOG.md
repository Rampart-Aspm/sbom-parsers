# Changelog

## [0.2.0]

- Add OpenVEX 0.2 WASM reader (`sbom-openvex`) as a native `ClusterSBOMParser`.
- Add `options.extractVEX` support in `ClusterSBOMParser` spec and Helm chart values for `cyclonedx` and `openvex`.
- Move OpenVEX out of report parsers (`rampart-parsers`) into `rampart-sbom-parsers` aligning with CRD-driven architecture.

## [0.1.0]

First release. The default SBOM readers of Rampart as one chart: CycloneDX (JSON and XML), SPDX and Syft, each a `ClusterSBOMParser`. They were part of Rampart's own chart; their detection is the scored `detect` that Rampart tests, and the module of each is `ghcr.io/rampart-aspm/sbom-parsers/<name>:v1`. `defaultSBOMParsers.cyclonedx.extractVulnerabilities` (off) turns the vulnerabilities a CycloneDX document states into findings.
