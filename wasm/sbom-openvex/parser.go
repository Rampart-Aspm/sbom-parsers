package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/rampart-aspm/sbom-parsers/pkg/normalize"
)

type Options struct {
	ExtractVEX bool
}

type MetadataEvent struct {
	Type        string `json:"type"`
	Format      string `json:"format"`
	SpecVersion string `json:"spec_version"`
}

type VEXStatementEvent struct {
	Type            string   `json:"type"`
	Vulnerability   string   `json:"vulnerability"`
	Aliases         []string `json:"aliases,omitempty"`
	Purl            string   `json:"purl,omitempty"`
	PurlBase        string   `json:"purl_base,omitempty"`
	Status          string   `json:"status"`
	Justification   string   `json:"justification,omitempty"`
	ImpactStatement string   `json:"impact_statement,omitempty"`
	ActionStatement string   `json:"action_statement,omitempty"`
	Timestamp       string   `json:"timestamp,omitempty"`
}

type openVEXDoc struct {
	Context    any                `json:"@context"`
	ID         string             `json:"@id"`
	Author     string             `json:"author"`
	Timestamp  string             `json:"timestamp"`
	Version    int                `json:"version"`
	Statements []openVEXStatement `json:"statements"`
}

type openVEXStatement struct {
	Vulnerability   any              `json:"vulnerability"`
	Products        []openVEXProduct `json:"products"`
	Status          string           `json:"status"`
	Justification   string           `json:"justification"`
	ImpactStatement string           `json:"impact_statement"`
	ActionStatement string           `json:"action_statement"`
	Timestamp       string           `json:"timestamp"`
}

type openVEXProduct struct {
	ID            string
	Purl          string
	Subcomponents []openVEXProduct
}

func (p *openVEXProduct) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		p.ID = s
		if strings.HasPrefix(s, "pkg:") {
			p.Purl = s
		}
		return nil
	}
	var o struct {
		ID          string `json:"@id"`
		Identifiers struct {
			Purl string `json:"purl"`
		} `json:"identifiers"`
		Subcomponents []openVEXProduct `json:"subcomponents"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return err
	}
	p.ID = o.ID
	p.Subcomponents = o.Subcomponents
	p.Purl = o.Identifiers.Purl
	if p.Purl == "" && strings.HasPrefix(o.ID, "pkg:") {
		p.Purl = o.ID
	}
	return nil
}

func productPURLs(products []openVEXProduct) []string {
	seen := make(map[string]bool)
	var purls []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p != "" && !seen[p] {
			seen[p] = true
			purls = append(purls, p)
		}
	}
	for _, p := range products {
		if len(p.Subcomponents) > 0 {
			for _, sc := range p.Subcomponents {
				add(sc.Purl)
			}
		} else {
			add(p.Purl)
		}
	}
	return purls
}

func ParseOpenVEXStream(r io.Reader, w io.Writer, opts Options) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	var doc openVEXDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("invalid openvex document: %w", err)
	}

	if len(doc.Statements) == 0 && doc.Context == nil {
		return errors.New("document is not recognized as openvex")
	}

	enc := json.NewEncoder(w)

	specVer := "0.2.0"
	if s, ok := doc.Context.(string); ok && strings.Contains(s, "0.1") {
		specVer = "0.1.0"
	}
	if err := enc.Encode(MetadataEvent{
		Type:        "metadata",
		Format:      "openvex",
		SpecVersion: specVer,
	}); err != nil {
		return err
	}

	if !opts.ExtractVEX {
		return nil
	}

	for _, st := range doc.Statements {
		vulnID, aliases := extractVuln(st.Vulnerability)
		if vulnID == "" {
			continue
		}

		ts := strings.TrimSpace(st.Timestamp)
		if ts == "" {
			ts = strings.TrimSpace(doc.Timestamp)
		}

		purls := productPURLs(st.Products)

		if len(purls) == 0 {
			_ = enc.Encode(VEXStatementEvent{
				Type:            "vex_statement",
				Vulnerability:   vulnID,
				Aliases:         aliases,
				Status:          st.Status,
				Justification:   st.Justification,
				ImpactStatement: st.ImpactStatement,
				ActionStatement: st.ActionStatement,
				Timestamp:       ts,
			})
			continue
		}

		for _, p := range purls {
			_, base, _ := normalize.CanonicalPURL(p)
			_ = enc.Encode(VEXStatementEvent{
				Type:            "vex_statement",
				Vulnerability:   vulnID,
				Aliases:         aliases,
				Purl:            p,
				PurlBase:        base,
				Status:          st.Status,
				Justification:   st.Justification,
				ImpactStatement: st.ImpactStatement,
				ActionStatement: st.ActionStatement,
				Timestamp:       ts,
			})
		}
	}

	return nil
}

func extractVuln(v any) (string, []string) {
	switch val := v.(type) {
	case string:
		return val, nil
	case map[string]any:
		var name string
		if n, ok := val["name"].(string); ok {
			name = n
		} else if id, ok := val["@id"].(string); ok {
			name = id
		}
		var aliases []string
		if rawAliases, ok := val["aliases"].([]any); ok {
			for _, a := range rawAliases {
				if s, ok := a.(string); ok && s != "" {
					aliases = append(aliases, s)
				}
			}
		}
		return name, aliases
	}
	return "", nil
}
