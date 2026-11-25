package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestOpenVEX_InheritsDocTimestampAndReadsIdentifiersAndSubcomponents(t *testing.T) {
	doc := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "https://openvex.dev/docs/example",
		"timestamp": "2023-10-15T00:00:00Z",
		"statements": [
			{
				"vulnerability": {"name": "CVE-2023-44487", "aliases": ["GHSA-m425-mq94-257g"]},
				"products": [
					{
						"@id": "https://example.com/product",
						"identifiers": {"purl": "pkg:golang/google.golang.org/grpc@v1.58.2"}
					}
				],
				"status": "not_affected",
				"justification": "vulnerable_code_not_in_execute_path",
				"impact_statement": "Not reachable"
			},
			{
				"vulnerability": {"name": "CVE-2024-0001"},
				"products": [
					{
						"@id": "https://example.com/app",
						"subcomponents": [
							{"@id": "pkg:npm/lodash@4.17.20"}
						]
					}
				],
				"status": "fixed",
				"timestamp": "2024-02-01T10:00:00Z"
			}
		]
	}`

	var out bytes.Buffer
	if err := ParseOpenVEXStream(strings.NewReader(doc), &out, Options{ExtractVEX: true}); err != nil {
		t.Fatalf("ParseOpenVEXStream: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3:\n%s", len(lines), out.String())
	}

	var ev1, ev2 VEXStatementEvent
	if err := json.Unmarshal([]byte(lines[1]), &ev1); err != nil {
		t.Fatal(err)
	}
	if ev1.Purl != "pkg:golang/google.golang.org/grpc@v1.58.2" {
		t.Errorf("ev1.Purl = %q", ev1.Purl)
	}
	if ev1.Timestamp != "2023-10-15T00:00:00Z" {
		t.Errorf("ev1.Timestamp = %q, want inherited doc timestamp", ev1.Timestamp)
	}

	if err := json.Unmarshal([]byte(lines[2]), &ev2); err != nil {
		t.Fatal(err)
	}
	if ev2.Purl != "pkg:npm/lodash@4.17.20" {
		t.Errorf("ev2.Purl = %q, want subcomponent purl", ev2.Purl)
	}
	if ev2.Timestamp != "2024-02-01T10:00:00Z" {
		t.Errorf("ev2.Timestamp = %q, want statement timestamp", ev2.Timestamp)
	}
}
