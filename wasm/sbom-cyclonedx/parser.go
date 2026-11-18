package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/rampart-aspm/sbom-parsers/pkg/normalize"
)

// Options controls how the SBOM parser handles optional sections (like embedded CVEs).
type Options struct {
	ExtractVulnerabilities bool `json:"extract_vulnerabilities"`
}

// Event types emitted as JSONL to stdout
const (
	EventMetadata      = "metadata"
	EventComponent     = "component"
	EventEdge          = "edge"
	EventVulnerability = "vulnerability"
)

// MetadataEvent describes top-level SBOM information.
type MetadataEvent struct {
	Type         string `json:"type"`
	Format       string `json:"format"`
	SpecVersion  string `json:"spec_version"`
	SerialNumber string `json:"serial_number,omitempty"`
	Timestamp    string `json:"timestamp,omitempty"`
	ToolName     string `json:"tool_name,omitempty"`
	RootRef      string `json:"root_ref,omitempty"`
}

// ComponentEvent describes an extracted software package/asset.
type ComponentEvent struct {
	Type     string            `json:"type"`
	Ref      string            `json:"ref"`
	Name     string            `json:"name"`
	Group    string            `json:"group,omitempty"`
	Version  string            `json:"version,omitempty"`
	Purl     string            `json:"purl,omitempty"`
	PurlBase string            `json:"purl_base,omitempty"`
	CompType string            `json:"component_type,omitempty"`
	Scope    string            `json:"scope,omitempty"`
	Licenses []string          `json:"licenses,omitempty"`
	Hashes   map[string]string `json:"hashes,omitempty"`
	IsRoot   bool              `json:"is_root,omitempty"`
}

// EdgeEvent describes a dependency graph relationship.
type EdgeEvent struct {
	Type   string `json:"type"`
	From   string `json:"from"`
	To     string `json:"to"`
	Direct bool   `json:"direct"`
}

// VulnerabilityEvent describes an embedded CVE / VDR finding.
type VulnerabilityEvent struct {
	Type        string  `json:"type"`
	ID          string  `json:"id"`
	Severity    string  `json:"severity,omitempty"`
	Score       float64 `json:"score,omitempty"`
	CWEs        []int   `json:"cwes,omitempty"`
	AffectedRef string  `json:"affected_ref,omitempty"`
	Description string  `json:"description,omitempty"`
	Detail      string  `json:"detail,omitempty"`
}

// raw structures for streaming unmarshal (JSON)
type cdxMetadata struct {
	Timestamp string `json:"timestamp"`
	Tools     any    `json:"tools"`
	Component *struct {
		BOMRef  string `json:"bom-ref"`
		Name    string `json:"name"`
		Group   string `json:"group"`
		Version string `json:"version"`
		Purl    string `json:"purl"`
	} `json:"component"`
}

type cdxComponent struct {
	BOMRef   string `json:"bom-ref"`
	Type     string `json:"type"`
	Group    string `json:"group"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Purl     string `json:"purl"`
	Scope    string `json:"scope"`
	Licenses []struct {
		License struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"license"`
		Expression string `json:"expression"`
	} `json:"licenses"`
	Hashes []struct {
		Alg     string `json:"alg"`
		Content string `json:"content"`
	} `json:"hashes"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type cdxVulnerability struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Detail      string `json:"detail"`
	Ratings     []struct {
		Severity string  `json:"severity"`
		Score    float64 `json:"score"`
		Method   string  `json:"method"`
	} `json:"ratings"`
	CWEs    []int `json:"cwes"`
	Affects []struct {
		Ref string `json:"ref"`
	} `json:"affects"`
}

// raw structures for unmarshal (XML)
type cdxXMLDocument struct {
	XMLName      xml.Name              `xml:"bom"`
	SpecVersion  string                `xml:"version,attr"`
	SerialNumber string                `xml:"serialNumber,attr"`
	Metadata     *cdxXMLMetadata       `xml:"metadata"`
	Components   []cdxXMLComponent     `xml:"components>component"`
	Dependencies []cdxXMLDependency    `xml:"dependencies>dependency"`
	Vulns        []cdxXMLVulnerability `xml:"vulnerabilities>vulnerability"`
}

type cdxXMLMetadata struct {
	Component *cdxXMLComponent `xml:"component"`
}

type cdxXMLComponent struct {
	BOMRef   string          `xml:"bom-ref,attr"`
	Type     string          `xml:"type,attr"`
	Group    string          `xml:"group"`
	Name     string          `xml:"name"`
	Version  string          `xml:"version"`
	Purl     string          `xml:"purl"`
	Scope    string          `xml:"scope"`
	Licenses []cdxXMLLicense `xml:"licenses>license"`
	Hashes   []cdxXMLHash    `xml:"hashes>hash"`
}

type cdxXMLLicense struct {
	ID   string `xml:"id"`
	Name string `xml:"name"`
}

type cdxXMLHash struct {
	Alg   string `xml:"alg,attr"`
	Value string `xml:",chardata"`
}

type cdxXMLDependency struct {
	Ref       string                `xml:"ref,attr"`
	DependsOn []cdxXMLDependencyRef `xml:"dependency"`
}

type cdxXMLDependencyRef struct {
	Ref string `xml:"ref,attr"`
}

type cdxXMLVulnerability struct {
	BOMRef      string             `xml:"bom-ref,attr"`
	ID          string             `xml:"id"`
	Description string             `xml:"description"`
	Detail      string             `xml:"detail"`
	Ratings     []cdxXMLRating     `xml:"ratings>rating"`
	CWEs        []int              `xml:"cwes>cwe"`
	Affects     []cdxXMLAffectsRef `xml:"affects>target"`
}

type cdxXMLRating struct {
	Severity string  `xml:"severity"`
	Score    float64 `xml:"score"`
	Method   string  `xml:"method"`
}

type cdxXMLAffectsRef struct {
	Ref string `xml:"ref"`
}

func peekNonWhitespace(br *bufio.Reader) (byte, error) {
	for {
		b, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
			_ = br.UnreadByte()
			return b, nil
		}
	}
}

// ParseCycloneDXStream streams CycloneDX (JSON or XML) into line-delimited JSON events.
func ParseCycloneDXStream(r io.Reader, w io.Writer, opts Options) error {
	br := bufio.NewReader(r)
	firstByte, err := peekNonWhitespace(br)
	if err != nil {
		return err
	}

	if firstByte == '<' {
		return parseCycloneDXXMLStream(br, w, opts)
	}
	return parseCycloneDXJSONStream(br, w, opts)
}

func parseCycloneDXXMLStream(r io.Reader, w io.Writer, opts Options) error {
	out := bufio.NewWriter(w)
	defer out.Flush()

	emit := func(v any) error {
		data, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if _, err := out.Write(data); err != nil {
			return err
		}
		return out.WriteByte('\n')
	}

	var doc cdxXMLDocument
	if err := xml.NewDecoder(r).Decode(&doc); err != nil {
		return fmt.Errorf("xml decode error: %w", err)
	}

	specVer := doc.SpecVersion
	if specVer == "" {
		specVer = "1.5"
	}

	rootRef := ""
	if doc.Metadata != nil && doc.Metadata.Component != nil {
		if doc.Metadata.Component.BOMRef != "" {
			rootRef = doc.Metadata.Component.BOMRef
		} else if doc.Metadata.Component.Purl != "" {
			rootRef = doc.Metadata.Component.Purl
		} else if doc.Metadata.Component.Name != "" {
			rootRef = doc.Metadata.Component.Name + "@" + doc.Metadata.Component.Version
		}
	}

	_ = emit(MetadataEvent{
		Type:         EventMetadata,
		Format:       "CycloneDX",
		SpecVersion:  specVer,
		SerialNumber: doc.SerialNumber,
		RootRef:      rootRef,
	})

	if doc.Metadata != nil && doc.Metadata.Component != nil && doc.Metadata.Component.Name != "" {
		c := doc.Metadata.Component
		purlBase := ""
		if c.Purl != "" {
			_, purlBase, _ = normalize.CanonicalPURL(c.Purl)
		}
		_ = emit(ComponentEvent{
			Type:     EventComponent,
			Ref:      rootRef,
			Name:     c.Name,
			Group:    c.Group,
			Version:  c.Version,
			Purl:     c.Purl,
			PurlBase: purlBase,
			IsRoot:   true,
		})
	}

	for _, comp := range doc.Components {
		ref := comp.BOMRef
		if ref == "" {
			ref = comp.Purl
		}
		if ref == "" {
			ref = comp.Name + "@" + comp.Version
		}

		var licenses []string
		for _, lic := range comp.Licenses {
			if lic.ID != "" {
				licenses = append(licenses, lic.ID)
			} else if lic.Name != "" {
				licenses = append(licenses, lic.Name)
			}
		}

		hashes := make(map[string]string)
		for _, h := range comp.Hashes {
			if h.Alg != "" && h.Value != "" {
				hashes[strings.ToUpper(h.Alg)] = strings.TrimSpace(h.Value)
			}
		}

		purlBase := ""
		if comp.Purl != "" {
			_, purlBase, _ = normalize.CanonicalPURL(comp.Purl)
		}

		_ = emit(ComponentEvent{
			Type:     EventComponent,
			Ref:      ref,
			Name:     comp.Name,
			Group:    comp.Group,
			Version:  comp.Version,
			Purl:     comp.Purl,
			PurlBase: purlBase,
			CompType: comp.Type,
			Scope:    comp.Scope,
			Licenses: licenses,
			Hashes:   hashes,
			IsRoot:   ref == rootRef,
		})
	}

	directSet := make(map[string]bool)
	for _, dep := range doc.Dependencies {
		isRootDep := false
		if rootRef != "" {
			if dep.Ref == rootRef {
				isRootDep = true
			}
		} else if len(directSet) == 0 {
			isRootDep = true
		}

		for _, child := range dep.DependsOn {
			if child.Ref == "" {
				continue
			}
			isDirect := isRootDep
			if isDirect {
				directSet[child.Ref] = true
			}
			_ = emit(EdgeEvent{
				Type:   EventEdge,
				From:   dep.Ref,
				To:     child.Ref,
				Direct: isDirect,
			})
		}
	}

	if opts.ExtractVulnerabilities {
		for _, v := range doc.Vulns {
			severity := ""
			score := 0.0
			if len(v.Ratings) > 0 {
				severity = v.Ratings[0].Severity
				score = v.Ratings[0].Score
			}

			for _, aff := range v.Affects {
				_ = emit(VulnerabilityEvent{
					Type:        EventVulnerability,
					ID:          v.ID,
					Severity:    severity,
					Score:       score,
					CWEs:        v.CWEs,
					AffectedRef: aff.Ref,
					Description: v.Description,
					Detail:      v.Detail,
				})
			}
		}
	}

	return nil
}

func parseCycloneDXJSONStream(r io.Reader, w io.Writer, opts Options) error {
	out := bufio.NewWriter(w)
	defer out.Flush()

	emit := func(v any) error {
		data, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if _, err := out.Write(data); err != nil {
			return err
		}
		return out.WriteByte('\n')
	}

	dec := json.NewDecoder(r)

	// Expect root '{'
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("failed to read start token: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("expected '{', got %v", tok)
	}

	var (
		format       = "CycloneDX"
		specVersion  = "1.4"
		serialNumber string
		rootRef      string
		directSet    = make(map[string]bool)
	)

	// Stream root keys
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			continue
		}

		switch key {
		case "bomFormat":
			var s string
			_ = dec.Decode(&s)
			if s != "" {
				format = s
			}
		case "specVersion":
			var s string
			_ = dec.Decode(&s)
			if s != "" {
				specVersion = s
			}
		case "serialNumber":
			_ = dec.Decode(&serialNumber)

		case "metadata":
			var meta cdxMetadata
			if err := dec.Decode(&meta); err == nil {
				if meta.Component != nil {
					rootRef = meta.Component.BOMRef
					if rootRef == "" {
						rootRef = meta.Component.Purl
					}
				}
				_ = emit(MetadataEvent{
					Type:         EventMetadata,
					Format:       format,
					SpecVersion:  specVersion,
					SerialNumber: serialNumber,
					Timestamp:    meta.Timestamp,
					RootRef:      rootRef,
				})
				if meta.Component != nil && meta.Component.Name != "" {
					purlBase := ""
					if meta.Component.Purl != "" {
						_, purlBase, _ = normalize.CanonicalPURL(meta.Component.Purl)
					}
					_ = emit(ComponentEvent{
						Type:     EventComponent,
						Ref:      rootRef,
						Name:     meta.Component.Name,
						Group:    meta.Component.Group,
						Version:  meta.Component.Version,
						Purl:     meta.Component.Purl,
						PurlBase: purlBase,
						IsRoot:   true,
					})
				}
			}

		case "components":
			// Read '['
			if err := expectDelim(dec, '['); err != nil {
				return err
			}
			for dec.More() {
				var comp cdxComponent
				if err := dec.Decode(&comp); err != nil {
					return fmt.Errorf("failed to decode component: %w", err)
				}

				ref := comp.BOMRef
				if ref == "" {
					ref = comp.Purl
				}
				if ref == "" {
					ref = comp.Name + "@" + comp.Version
				}

				var licenses []string
				for _, lic := range comp.Licenses {
					if lic.License.ID != "" {
						licenses = append(licenses, lic.License.ID)
					} else if lic.License.Name != "" {
						licenses = append(licenses, lic.License.Name)
					} else if lic.Expression != "" {
						licenses = append(licenses, lic.Expression)
					}
				}

				hashes := make(map[string]string)
				for _, h := range comp.Hashes {
					if h.Alg != "" && h.Content != "" {
						hashes[strings.ToUpper(h.Alg)] = h.Content
					}
				}

				purlBase := ""
				if comp.Purl != "" {
					_, purlBase, _ = normalize.CanonicalPURL(comp.Purl)
				}

				_ = emit(ComponentEvent{
					Type:     EventComponent,
					Ref:      ref,
					Name:     comp.Name,
					Group:    comp.Group,
					Version:  comp.Version,
					Purl:     comp.Purl,
					PurlBase: purlBase,
					CompType: comp.Type,
					Scope:    comp.Scope,
					Licenses: licenses,
					Hashes:   hashes,
					IsRoot:   ref == rootRef,
				})
			}
			if err := expectDelim(dec, ']'); err != nil {
				return err
			}

		case "dependencies":
			rootPrefix := rootRef
			if idx := strings.Index(rootRef, "@"); idx != -1 {
				rootPrefix = rootRef[:idx]
			}
			if idx := strings.LastIndex(rootPrefix, "/"); idx != -1 {
				rootPrefix = rootPrefix[:idx]
			}

			// Read '['
			if err := expectDelim(dec, '['); err != nil {
				return err
			}
			for dec.More() {
				var dep cdxDependency
				if err := dec.Decode(&dep); err != nil {
					return fmt.Errorf("failed to decode dependency: %w", err)
				}

				isRootDep := false
				if rootRef != "" {
					if dep.Ref == rootRef || strings.HasPrefix(dep.Ref, rootPrefix) {
						isRootDep = true
					}
				} else if len(directSet) == 0 {
					isRootDep = true
				}

				for _, child := range dep.DependsOn {
					isDirect := isRootDep
					if isDirect {
						directSet[child] = true
					}
					_ = emit(EdgeEvent{
						Type:   EventEdge,
						From:   dep.Ref,
						To:     child,
						Direct: isDirect,
					})
				}
			}
			if err := expectDelim(dec, ']'); err != nil {
				return err
			}

		case "vulnerabilities":
			if !opts.ExtractVulnerabilities {
				if err := skipValue(dec); err != nil {
					return err
				}
				continue
			}

			if err := expectDelim(dec, '['); err != nil {
				return err
			}
			for dec.More() {
				var vuln cdxVulnerability
				if err := dec.Decode(&vuln); err != nil {
					return fmt.Errorf("failed to decode vulnerability: %w", err)
				}

				severity := ""
				score := 0.0
				if len(vuln.Ratings) > 0 {
					severity = vuln.Ratings[0].Severity
					score = vuln.Ratings[0].Score
				}

				for _, aff := range vuln.Affects {
					_ = emit(VulnerabilityEvent{
						Type:        EventVulnerability,
						ID:          vuln.ID,
						Severity:    severity,
						Score:       score,
						CWEs:        vuln.CWEs,
						AffectedRef: aff.Ref,
						Description: vuln.Description,
						Detail:      vuln.Detail,
					})
				}
			}
			if err := expectDelim(dec, ']'); err != nil {
				return err
			}

		default:
			if err := skipValue(dec); err != nil {
				return err
			}
		}
	}

	return nil
}

func expectDelim(dec *json.Decoder, d json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != d {
		return fmt.Errorf("expected delimiter '%s', got %v", string(d), tok)
	}
	return nil
}

func skipValue(dec *json.Decoder) error {
	var v any
	return dec.Decode(&v)
}
