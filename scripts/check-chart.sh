#!/usr/bin/env bash
# Tests the chart: the manifests are in sync with the readers, helm lint is clean, every resource it renders has exactly the
# spec of the manifest (the chart changes labels, and options.extractVulnerabilities only when the values set it), and the
# switches work.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
chart="$here/charts/rampart-sbom-parsers"
"$here/scripts/sync-chart.sh" --check
helm lint --strict "$chart" >/dev/null
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
helm template r "$chart" > "$out/all.yaml"
helm template r "$chart" --set defaultSBOMParsers.enabled=false > "$out/none.yaml"
helm template r "$chart" --set defaultSBOMParsers.spdx.enabled=false > "$out/spdx-off.yaml"
helm template r "$chart" --set defaultSBOMParsers.cyclonedx.extractVulnerabilities=true > "$out/vdr.yaml"
python3 -I - "$chart/manifests" "$out" <<'PY'
import sys, glob, yaml, os, copy
manifests, out = sys.argv[1], sys.argv[2]
want = {}
for f in glob.glob(manifests + '/*.yaml'):
    d = yaml.safe_load(open(f)); want[d['metadata']['name']] = d
def docs(name): return [d for d in yaml.safe_load_all(open(os.path.join(out, name))) if d]
got = {d['metadata']['name']: d for d in docs('all.yaml')}
assert set(got) == set(want), f"rendered {sorted(set(got) ^ set(want))} differ from the manifests"
for n, d in got.items():
    assert d['kind'] == want[n]['kind'] == 'ClusterSBOMParser', n
    expected = copy.deepcopy(want[n]['spec'])
    if n == 'sbom-cyclonedx':  # the chart's own default: the VDR is not turned into findings
        expected.setdefault('options', {})['extractVulnerabilities'] = False
    assert d['spec'] == expected, f"{n}: the rendered spec is not the manifest's spec"
    assert d['metadata']['name'].startswith('sbom-'), n
assert docs('none.yaml') == [], "defaultSBOMParsers.enabled=false must install nothing"
off = {d['metadata']['name'] for d in docs('spdx-off.yaml')}
assert set(want) - off == {'sbom-spdx'}, f"turning off spdx left {sorted(set(want) - off)} out"
vdr = {d['metadata']['name']: d for d in docs('vdr.yaml')}
assert vdr['sbom-cyclonedx']['spec']['options']['extractVulnerabilities'] is True, "the VDR switch did not reach the resource"
assert vdr['sbom-cyclonedx']['spec']['options'].get('buildDependencyGraph') == want['sbom-cyclonedx']['spec'].get('options', {}).get('buildDependencyGraph'), "setting the VDR switch must keep the other options"
print(f"chart ok: {len(got)} readers render with their manifest's spec; the switches work")
PY
