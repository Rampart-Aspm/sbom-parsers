package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/rampart-aspm/sbom-parsers/pkg/normalize"
)

// Options are the options of the reader. The host passes them in the environment.
type Options struct {
	// ExtractVulnerabilities makes the reader emit the vulnerabilities a document states in its "vulnerabilities"
	// section (a VDR). It is off by default: an SBOM is assets, and what is found in it is the matcher's work. It reads
	// that section only: never the CPE of a component, which is a guess and not a statement.
	ExtractVulnerabilities bool
	// ExtractVEX emits VEX exploitability assertions from vulnerabilities[].analysis (CycloneDX VEX).
	ExtractVEX bool
}

// Event types emitted as JSONL to stdout
const (
	EventMetadata  = "metadata"
	EventComponent = "component"
	EventEdge      = "edge"

	EventVulnerability = "vulnerability"
	EventVEXStatement  = "vex_statement"
)

// VEXStatementEvent is one VEX exploitability statement derived from a CycloneDX vulnerability analysis.
type VEXStatementEvent struct {
	Type            string   `json:"type"`
	Vulnerability   string   `json:"vulnerability"`
	Aliases         []string `json:"aliases,omitempty"`
	Purl            string   `json:"purl,omitempty"`
	PurlBase        string   `json:"purl_base,omitempty"`
	AffectedRef     string   `json:"affected_ref,omitempty"`
	Status          string   `json:"status"`
	Justification   string   `json:"justification,omitempty"`
	ImpactStatement string   `json:"impact_statement,omitempty"`
	ActionStatement string   `json:"action_statement,omitempty"`
	Timestamp       string   `json:"timestamp,omitempty"`
}

// VulnerabilityEvent is one vulnerability a VDR states about one component (one event per affected reference).
type VulnerabilityEvent struct {
	Type        string   `json:"type"`
	ID          string   `json:"id"`
	Source      string   `json:"source,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Score       float64  `json:"score,omitempty"`
	Vector      string   `json:"vector,omitempty"`
	CWEs        []int    `json:"cwes,omitempty"`
	AffectedRef string   `json:"affected_ref"`
	Description string   `json:"description,omitempty"`
	Detail      string   `json:"detail,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
}

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
	// Components nested in a component (an assembly, a bundled library) are components of the document like any other:
	// a dependency can name one by its bom-ref.
	Components []cdxComponent `json:"components"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type cdxVulnerability struct {
	ID     string `json:"id"`
	Source struct {
		Name string `json:"name"`
	} `json:"source"`
	Description string `json:"description"`
	Detail      string `json:"detail"`
	Ratings     []struct {
		Severity string  `json:"severity"`
		Score    float64 `json:"score"`
		Method   string  `json:"method"`
		Vector   string  `json:"vector"`
	} `json:"ratings"`
	CWEs    []int `json:"cwes"`
	Affects []struct {
		Ref string `json:"ref"`
	} `json:"affects"`
	// References lists the same vulnerability under other ids (a GHSA for a CVE, for example).
	References []struct {
		ID string `json:"id"`
	} `json:"references"`
	Analysis struct {
		State         string   `json:"state"`
		Justification string   `json:"justification"`
		Response      []string `json:"response"`
		Detail        string   `json:"detail"`
		FirstIssued   string   `json:"firstIssued"`
		LastUpdated   string   `json:"lastUpdated"`
	} `json:"analysis"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
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
	Timestamp string           `xml:"timestamp"`
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
	// Nested components, as in JSON.
	Components []cdxXMLComponent `xml:"components>component"`
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
	Source      cdxXMLSource       `xml:"source"`
	Description string             `xml:"description"`
	Detail      string             `xml:"detail"`
	Ratings     []cdxXMLRating     `xml:"ratings>rating"`
	CWEs        []int              `xml:"cwes>cwe"`
	Affects     []cdxXMLAffectsRef `xml:"affects>target"`
	Analysis    cdxXMLAnalysis     `xml:"analysis"`
	Properties  []cdxXMLProperty   `xml:"properties>property"`
}

type cdxXMLAnalysis struct {
	State         string   `xml:"state"`
	Justification string   `xml:"justification"`
	Responses     []string `xml:"responses>response"`
	Detail        string   `xml:"detail"`
	FirstIssued   string   `xml:"firstIssued"`
	LastUpdated   string   `xml:"lastUpdated"`
}

type cdxXMLProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type cdxXMLSource struct {
	Name string `xml:"name,attr"`
}

type cdxXMLRating struct {
	Severity string      `xml:"severity"`
	Score    cdxXMLScore `xml:"score"`
	Method   string      `xml:"method"`
	Vector   string      `xml:"vector"`
}

// cdxXMLScore reads a rating score in either form: <score><base>7.5</base></score> (the schema) or <score>7.5</score>.
type cdxXMLScore float64

func (s *cdxXMLScore) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var v struct {
		Base string `xml:"base"`
		Text string `xml:",chardata"`
	}
	if err := d.DecodeElement(&v, &start); err != nil {
		return err
	}
	txt := strings.TrimSpace(v.Base)
	if txt == "" {
		txt = strings.TrimSpace(v.Text)
	}
	if txt == "" {
		return nil
	}
	f, err := strconv.ParseFloat(txt, 64)
	if err != nil {
		return nil // a score that is not a number is no score; the severity label still counts
	}
	*s = cdxXMLScore(f)
	return nil
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

	refPurl := make(map[string]string)
	docTimestamp := ""
	if doc.Metadata != nil {
		docTimestamp = doc.Metadata.Timestamp
	}
	if doc.Metadata != nil && doc.Metadata.Component != nil && doc.Metadata.Component.Name != "" {
		c := doc.Metadata.Component
		if rootRef != "" && c.Purl != "" {
			refPurl[rootRef] = c.Purl
		}
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
		for _, ev := range xmlComponentEvents(comp, rootRef) {
			if ev.Ref != "" && ev.Purl != "" {
				refPurl[ev.Ref] = ev.Purl
			}
			_ = emit(ev)
		}
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

	for _, v := range doc.Vulns {
		refs := make([]string, 0, len(v.Affects))
		for _, a := range v.Affects {
			refs = append(refs, a.Ref)
		}
		if opts.ExtractVulnerabilities {
			ratings := make([]rating, 0, len(v.Ratings))
			for _, r := range v.Ratings {
				ratings = append(ratings, rating{severity: r.Severity, score: float64(r.Score), vector: r.Vector})
			}
			if err := emitVulnerability(emit, v.ID, v.Source.Name, v.Description, v.Detail, ratings, v.CWEs, refs, nil); err != nil {
				return err
			}
		}
		if opts.ExtractVEX && strings.TrimSpace(v.Analysis.State) != "" {
			var ownJust, ownAction string
			for _, p := range v.Properties {
				switch p.Name {
				case "rampart:justification":
					ownJust = strings.TrimSpace(p.Value)
				case "rampart:action":
					ownAction = strings.TrimSpace(p.Value)
				}
			}
			ts := firstNonEmptyStr(v.Analysis.LastUpdated, v.Analysis.FirstIssued, docTimestamp)
			if err := emitCycloneDXVEX(emit, refPurl, v.ID, nil, refs, v.Analysis.State, v.Analysis.Justification, v.Analysis.Responses, v.Analysis.Detail, ownJust, ownAction, ts); err != nil {
				return err
			}
		}
	}

	return nil
}

// jsonComponentEvents is the component, then the components nested in it, in document order.
func jsonComponentEvents(comp cdxComponent, rootRef string) []ComponentEvent {
	ref := comp.BOMRef
	if ref == "" {
		ref = comp.Purl
	}
	if ref == "" {
		ref = comp.Name + "@" + comp.Version
	}
	var licenses []string
	for _, lic := range comp.Licenses {
		switch {
		case lic.License.ID != "":
			licenses = append(licenses, lic.License.ID)
		case lic.License.Name != "":
			licenses = append(licenses, lic.License.Name)
		case lic.Expression != "":
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
	out := []ComponentEvent{{
		Type: EventComponent, Ref: ref, Name: comp.Name, Group: comp.Group, Version: comp.Version, Purl: comp.Purl, PurlBase: purlBase,
		CompType: comp.Type, Scope: comp.Scope, Licenses: licenses, Hashes: hashes, IsRoot: ref == rootRef,
	}}
	for _, sub := range comp.Components {
		out = append(out, jsonComponentEvents(sub, rootRef)...)
	}
	return out
}

// xmlComponentEvents is jsonComponentEvents for a document in XML.
func xmlComponentEvents(comp cdxXMLComponent, rootRef string) []ComponentEvent {
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
	out := []ComponentEvent{{
		Type: EventComponent, Ref: ref, Name: comp.Name, Group: comp.Group, Version: comp.Version, Purl: comp.Purl, PurlBase: purlBase,
		CompType: comp.Type, Scope: comp.Scope, Licenses: licenses, Hashes: hashes, IsRoot: ref == rootRef,
	}}
	for _, sub := range comp.Components {
		out = append(out, xmlComponentEvents(sub, rootRef)...)
	}
	return out
}

// rating is one rating of a vulnerability, whichever format it came from.
type rating struct {
	severity string
	score    float64
	vector   string
}

// bestRating picks the rating that says the most: the highest score, and when no rating has a score, the most severe label.
func bestRating(rs []rating) rating {
	var best rating
	for i, r := range rs {
		if i == 0 || r.score > best.score || (r.score == best.score && severityRank(r.severity) > severityRank(best.severity)) {
			best = r
		}
	}
	return best
}

func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium", "moderate":
		return 3
	case "low":
		return 2
	case "info", "informational":
		return 1
	}
	return 0
}

// emitVulnerability writes one event for each component the vulnerability affects. A vulnerability that names no
// component is dropped: there is nothing it could be attached to.
func emitVulnerability(emit func(any) error, id, source, description, detail string, ratings []rating, cwes []int, refs, aliases []string) error {
	if strings.TrimSpace(id) == "" {
		return nil
	}
	best := bestRating(ratings)
	for _, ref := range refs {
		if ref == "" {
			continue
		}
		if err := emit(VulnerabilityEvent{
			Type: EventVulnerability, ID: id, Source: source, Severity: best.severity, Score: best.score, Vector: best.vector,
			CWEs: cwes, AffectedRef: ref, Description: description, Detail: detail, Aliases: aliases,
		}); err != nil {
			return err
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
		docTimestamp string
		directSet    = make(map[string]bool)
		refPurl      = make(map[string]string)
		pendingVEX   []cdxVulnerability
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
				if meta.Timestamp != "" {
					docTimestamp = meta.Timestamp
				}
				if meta.Component != nil {
					rootRef = meta.Component.BOMRef
					if rootRef == "" {
						rootRef = meta.Component.Purl
					}
					if rootRef != "" && meta.Component.Purl != "" {
						refPurl[rootRef] = meta.Component.Purl
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

				for _, ev := range jsonComponentEvents(comp, rootRef) {
					if ev.Ref != "" && ev.Purl != "" {
						refPurl[ev.Ref] = ev.Purl
					}
					_ = emit(ev)
				}
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
			if !opts.ExtractVulnerabilities && !opts.ExtractVEX {
				if err := skipValue(dec); err != nil {
					return err
				}
				break
			}
			if err := expectDelim(dec, '['); err != nil {
				return err
			}
			for dec.More() {
				var v cdxVulnerability
				if err := dec.Decode(&v); err != nil {
					return fmt.Errorf("reading a vulnerability: %w", err)
				}
				if opts.ExtractVulnerabilities {
					ratings := make([]rating, 0, len(v.Ratings))
					for _, r := range v.Ratings {
						ratings = append(ratings, rating{severity: r.Severity, score: r.Score, vector: r.Vector})
					}
					refs := make([]string, 0, len(v.Affects))
					for _, a := range v.Affects {
						refs = append(refs, a.Ref)
					}
					var aliases []string
					for _, r := range v.References {
						if r.ID != "" && r.ID != v.ID {
							aliases = append(aliases, r.ID)
						}
					}
					if err := emitVulnerability(emit, v.ID, v.Source.Name, v.Description, v.Detail, ratings, v.CWEs, refs, aliases); err != nil {
						return err
					}
				}
				if opts.ExtractVEX && strings.TrimSpace(v.Analysis.State) != "" {
					pendingVEX = append(pendingVEX, v)
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

	if opts.ExtractVEX {
		for _, v := range pendingVEX {
			refs := make([]string, 0, len(v.Affects))
			for _, a := range v.Affects {
				refs = append(refs, a.Ref)
			}
			var aliases []string
			for _, r := range v.References {
				if r.ID != "" && r.ID != v.ID {
					aliases = append(aliases, r.ID)
				}
			}
			var ownJust, ownAction string
			for _, p := range v.Properties {
				switch p.Name {
				case "rampart:justification":
					ownJust = strings.TrimSpace(p.Value)
				case "rampart:action":
					ownAction = strings.TrimSpace(p.Value)
				}
			}
			ts := firstNonEmptyStr(v.Analysis.LastUpdated, v.Analysis.FirstIssued, docTimestamp)
			if err := emitCycloneDXVEX(emit, refPurl, v.ID, aliases, refs, v.Analysis.State, v.Analysis.Justification, v.Analysis.Response, v.Analysis.Detail, ownJust, ownAction, ts); err != nil {
				return err
			}
		}
	}

	return nil
}

var cdxVEXJustificationMap = map[string]string{
	"code_not_present":                "vulnerable_code_not_present",
	"code_not_reachable":              "vulnerable_code_not_in_execute_path",
	"requires_configuration":          "vulnerable_code_cannot_be_controlled_by_adversary",
	"requires_dependency":             "vulnerable_code_cannot_be_controlled_by_adversary",
	"requires_environment":            "vulnerable_code_cannot_be_controlled_by_adversary",
	"protected_by_compiler":           "inline_mitigations_already_exist",
	"protected_at_runtime":            "inline_mitigations_already_exist",
	"protected_at_perimeter":          "inline_mitigations_already_exist",
	"protected_by_mitigating_control": "inline_mitigations_already_exist",
}

func emitCycloneDXVEX(emit func(any) error, refPurl map[string]string, vulnID string, aliases, refs []string, rawState, rawJust string, responses []string, detail, ownJust, ownAction, ts string) error {
	if strings.TrimSpace(vulnID) == "" {
		return nil
	}
	var status string
	switch strings.ToLower(strings.TrimSpace(rawState)) {
	case "not_affected", "false_positive":
		status = "not_affected"
	case "exploitable", "affected":
		status = "affected"
	case "resolved", "resolved_with_pedigree", "fixed":
		status = "fixed"
	case "in_triage", "under_investigation":
		status = "under_investigation"
	default:
		return nil
	}
	justification := ownJust
	if justification == "" {
		j := strings.TrimSpace(rawJust)
		if mapped, ok := cdxVEXJustificationMap[strings.ToLower(j)]; ok {
			justification = mapped
		} else if j != "" {
			justification = j
		}
	}
	if status == "not_affected" && justification == "" && strings.EqualFold(strings.TrimSpace(rawState), "false_positive") {
		justification = "vulnerable_code_not_present"
	}
	action := ownAction
	if action == "" && len(responses) > 0 {
		action = strings.Join(responses, ", ")
	}
	if len(refs) == 0 {
		return emit(VEXStatementEvent{
			Type:            EventVEXStatement,
			Vulnerability:   vulnID,
			Aliases:         aliases,
			Status:          status,
			Justification:   justification,
			ImpactStatement: detail,
			ActionStatement: action,
			Timestamp:       ts,
		})
	}
	for _, ref := range refs {
		purl := refPurl[ref]
		if purl == "" && strings.HasPrefix(ref, "pkg:") {
			purl = ref
		}
		purlBase := ""
		if purl != "" {
			_, purlBase, _ = normalize.CanonicalPURL(purl)
		}
		if err := emit(VEXStatementEvent{
			Type:            EventVEXStatement,
			Vulnerability:   vulnID,
			Aliases:         aliases,
			Purl:            purl,
			PurlBase:        purlBase,
			AffectedRef:     ref,
			Status:          status,
			Justification:   justification,
			ImpactStatement: detail,
			ActionStatement: action,
			Timestamp:       ts,
		}); err != nil {
			return err
		}
	}
	return nil
}

func firstNonEmptyStr(vals ...string) string {
	for _, s := range vals {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
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
