{{/* A manifest from manifests/, with the labels Helm puts on what it installs. Only the labels and, when the values set it, options.extractVulnerabilities change. */}}
{{- define "rampart-sbom-parsers.render" -}}
{{- $m := .m -}}
{{- $labels := dict "app.kubernetes.io/name" "rampart-sbom-parsers" "app.kubernetes.io/part-of" "rampart" "app.kubernetes.io/managed-by" .root.Release.Service "app.kubernetes.io/instance" .root.Release.Name "helm.sh/chart" (printf "%s-%s" .root.Chart.Name .root.Chart.Version) -}}
{{- $_ := set $m.metadata "labels" (merge (default dict $m.metadata.labels) $labels) -}}
{{- if hasKey .one "extractVulnerabilities" -}}
{{- $opts := default dict $m.spec.options -}}
{{- $_ := set $opts "extractVulnerabilities" .one.extractVulnerabilities -}}
{{- $_ := set $m.spec "options" $opts -}}
{{- end -}}
{{- toYaml $m -}}
{{- end -}}
