# rampart-sbom-parsers

The default SBOM readers of [Rampart](https://github.com/taha2samy-3/Rampart), one `ClusterSBOMParser` resource per format.
An SBOM reader produces assets (components and dependency edges), never findings. Rampart's server knows no reader by name:
this chart is how a cluster gets them.

```sh
helm install sbom-parsers oci://ghcr.io/rampart-aspm/charts/rampart-sbom-parsers --version 0.1.0
```

Rampart's own chart includes it as `sbomParsers`, on by default, so `sbomParsers.defaultSBOMParsers.*` there are the values below.

| Value | Default | Meaning |
|---|---|---|
| `defaultSBOMParsers.enabled` | `true` | `false` installs no reader |
| `defaultSBOMParsers.<name>.enabled` | `true` | `false` leaves that reader out (`cyclonedx`, `spdx`, `syft`) |
| `defaultSBOMParsers.cyclonedx.extractVulnerabilities` | `false` | turn the vulnerabilities a CycloneDX document states (a VDR) into findings |

## Where the manifests come from

Each reader's manifest is the `parser.yaml` next to its code (`wasm/<name>/`). `manifests/` holds a copy of each, written by
`scripts/sync-chart.sh`; CI (`scripts/check-chart.sh`) fails when a copy is stale and checks that every resource the chart
renders has exactly the spec of its manifest. The template names no reader.

The WASM module a manifest names (`source.oci`) is not installed by this chart. It reaches the Rampart pods as an image volume
or an init container, by digest (Rampart's chart, `parsers.modules`).

Report parsers are another chart: [rampart-parsers](https://github.com/Rampart-Aspm/parsers).
