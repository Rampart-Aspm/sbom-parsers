# Changelog

## [0.1.0]

First release. The default SBOM readers of Rampart as one chart: CycloneDX (JSON and XML), SPDX and Syft, each a `ClusterSBOMParser`. They were part of Rampart's own chart; their detection is the scored `detect` that Rampart tests, and the module of each is `ghcr.io/rampart-aspm/sbom-parsers/<name>:v1`. `defaultSBOMParsers.cyclonedx.extractVulnerabilities` (off) turns the vulnerabilities a CycloneDX document states into findings.
