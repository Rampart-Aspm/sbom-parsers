package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/rampart-aspm/sbom-parsers/pkg/normalize"
)

// Options controls how the SBOM parser handles optional sections.
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

// VulnerabilityEvent describes an embedded CVE / security finding.
type VulnerabilityEvent struct {
	Type        string  `json:"type"`
	ID          string  `json:"id"`
	Severity    string  `json:"severity,omitempty"`
	Score       float64 `json:"score,omitempty"`
	AffectedRef string  `json:"affected_ref,omitempty"`
	Description string  `json:"description,omitempty"`
}

// ParseSPDXStream streams SPDX (JSON, JSON-LD, or Tag-Value) into line-delimited JSON events.
func ParseSPDXStream(r io.Reader, w io.Writer, opts Options) error {
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

	br := bufio.NewReader(r)
	firstByte, err := peekNonWhitespace(br)
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}

	if firstByte == '{' {
		return parseSPDXJSONStream(br, emit, opts)
	}
	return parseSPDXTagValueStream(br, emit, opts)
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

// raw structures for streaming SPDX JSON
type rawSPDXCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type rawSPDXPackage struct {
	Name             string `json:"name"`
	SPDXID           string `json:"SPDXID"`
	VersionInfo      string `json:"versionInfo"`
	LicenseConcluded string `json:"licenseConcluded"`
	Checksums        []struct {
		Algorithm     string `json:"algorithm"`
		ChecksumValue string `json:"checksumValue"`
	} `json:"checksums"`
	ExternalRefs []struct {
		ReferenceCategory string `json:"referenceCategory"`
		ReferenceType     string `json:"referenceType"`
		ReferenceLocator  string `json:"referenceLocator"`
	} `json:"externalRefs"`
}

type rawSPDXRelationship struct {
	SpdxElementId      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSpdxElement string `json:"relatedSpdxElement"`
}

func parseSPDXJSONStream(r io.Reader, emit func(any) error, opts Options) error {
	dec := json.NewDecoder(r)

	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("failed to read start token: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("expected '{', got %v", tok)
	}

	var (
		format            = "SPDX"
		specVersion       = "SPDX-2.3"
		docName           = ""
		docNamespace      = ""
		rootRef           = ""
		toolName          = ""
		timestamp         = ""
		emittedMetadata   = false
		bufferedPackages  []rawSPDXPackage
		bufferedEdges     []rawSPDXRelationship
		describedElements = make(map[string]bool)
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
		case "spdxVersion":
			var s string
			_ = dec.Decode(&s)
			if s != "" {
				specVersion = s
			}
		case "name":
			_ = dec.Decode(&docName)
		case "documentNamespace":
			_ = dec.Decode(&docNamespace)
		case "creationInfo":
			var ci rawSPDXCreationInfo
			if err := dec.Decode(&ci); err == nil {
				timestamp = ci.Created
				for _, c := range ci.Creators {
					if strings.HasPrefix(c, "Tool:") {
						toolName = strings.TrimSpace(strings.TrimPrefix(c, "Tool:"))
						break
					}
				}
			}
		case "packages":
			if err := expectDelim(dec, '['); err != nil {
				return err
			}
			for dec.More() {
				var pkg rawSPDXPackage
				if err := dec.Decode(&pkg); err != nil {
					return fmt.Errorf("failed to decode spdx package: %w", err)
				}
				bufferedPackages = append(bufferedPackages, pkg)
			}
			if err := expectDelim(dec, ']'); err != nil {
				return err
			}
		case "relationships":
			if err := expectDelim(dec, '['); err != nil {
				return err
			}
			for dec.More() {
				var rel rawSPDXRelationship
				if err := dec.Decode(&rel); err != nil {
					return fmt.Errorf("failed to decode spdx relationship: %w", err)
				}
				bufferedEdges = append(bufferedEdges, rel)
				relType := strings.ToUpper(strings.TrimSpace(rel.RelationshipType))
				if relType == "DESCRIBES" && (strings.EqualFold(rel.SpdxElementId, "SPDXRef-DOCUMENT") || rel.SpdxElementId == "") {
					describedElements[rel.RelatedSpdxElement] = true
					if rootRef == "" {
						rootRef = rel.RelatedSpdxElement
					}
				} else if relType == "DESCRIBED_BY" && strings.EqualFold(rel.RelatedSpdxElement, "SPDXRef-DOCUMENT") {
					describedElements[rel.SpdxElementId] = true
					if rootRef == "" {
						rootRef = rel.SpdxElementId
					}
				}
			}
			if err := expectDelim(dec, ']'); err != nil {
				return err
			}
		case "@graph":
			// SPDX 3.0 JSON-LD
			return parseSPDX3Stream(dec, emit, opts)
		default:
			if err := skipValue(dec); err != nil {
				return err
			}
		}
	}

	// If rootRef is not established by DESCRIBES, check if the first package matches document name or fallback to first
	if rootRef == "" && len(bufferedPackages) > 0 {
		for _, pkg := range bufferedPackages {
			if docName != "" && strings.EqualFold(pkg.Name, docName) {
				rootRef = pkg.SPDXID
				break
			}
		}
		if rootRef == "" {
			rootRef = bufferedPackages[0].SPDXID
		}
	}

	// 1. Emit MetadataEvent
	_ = emit(MetadataEvent{
		Type:         EventMetadata,
		Format:       format,
		SpecVersion:  specVersion,
		SerialNumber: docNamespace,
		Timestamp:    timestamp,
		ToolName:     toolName,
		RootRef:      rootRef,
	})
	emittedMetadata = true

	// 2. Emit ComponentEvents
	for _, pkg := range bufferedPackages {
		purl := ""
		cpe := ""
		for _, ref := range pkg.ExternalRefs {
			refType := strings.ToLower(ref.ReferenceType)
			if refType == "purl" {
				purl = ref.ReferenceLocator
			} else if strings.HasPrefix(refType, "cpe") {
				cpe = ref.ReferenceLocator
			}
		}

		purlBase := ""
		if purl != "" {
			_, purlBase, _ = normalize.CanonicalPURL(purl)
		}

		var licenses []string
		if pkg.LicenseConcluded != "" && pkg.LicenseConcluded != "NOASSERTION" && pkg.LicenseConcluded != "NONE" {
			licenses = append(licenses, pkg.LicenseConcluded)
		}

		hashes := make(map[string]string)
		for _, cs := range pkg.Checksums {
			if cs.Algorithm != "" && cs.ChecksumValue != "" {
				hashes[strings.ToUpper(cs.Algorithm)] = cs.ChecksumValue
			}
		}

		isRoot := (pkg.SPDXID == rootRef)

		_ = emit(ComponentEvent{
			Type:     EventComponent,
			Ref:      pkg.SPDXID,
			Name:     pkg.Name,
			Version:  pkg.VersionInfo,
			Purl:     purl,
			PurlBase: purlBase,
			Licenses: licenses,
			Hashes:   hashes,
			IsRoot:   isRoot,
		})

		if opts.ExtractVulnerabilities && cpe != "" {
			// If options ask for vulnerability annotations
			_ = emit(VulnerabilityEvent{
				Type:        EventVulnerability,
				ID:          "CPE:" + cpe,
				AffectedRef: pkg.SPDXID,
				Description: "CPE identifier for package " + pkg.Name,
			})
		}
	}

	// 3. Emit EdgeEvents
	for _, rel := range bufferedEdges {
		relType := strings.ToUpper(strings.TrimSpace(rel.RelationshipType))
		from := rel.SpdxElementId
		to := rel.RelatedSpdxElement

		switch relType {
		case "DEPENDS_ON", "CONTAINS", "DYNAMIC_LINK", "STATIC_LINK":
			_ = emit(EdgeEvent{
				Type:   EventEdge,
				From:   from,
				To:     to,
				Direct: from == rootRef,
			})
		case "DEPENDENCY_OF", "CONTAINED_BY":
			_ = emit(EdgeEvent{
				Type:   EventEdge,
				From:   to,
				To:     from,
				Direct: to == rootRef,
			})
		}
	}

	_ = emittedMetadata
	return nil
}

func parseSPDXTagValueStream(r io.Reader, emit func(any) error, opts Options) error {
	scanner := bufio.NewScanner(r)

	var (
		format       = "SPDX"
		specVersion  = "SPDX-2.3"
		docName      = ""
		docNamespace = ""
		rootRef      = ""
		toolName     = ""
		timestamp    = ""
	)

	type tagPkg struct {
		Name             string
		SPDXID           string
		Version          string
		LicenseConcluded string
		Purl             string
		PurlBase         string
		CPE              string
		Hashes           map[string]string
	}

	var (
		packages []tagPkg
		current  *tagPkg
		edges    []EdgeEvent
	)

	flushCurrent := func() {
		if current != nil && current.Name != "" {
			if current.Purl != "" {
				_, current.PurlBase, _ = normalize.CanonicalPURL(current.Purl)
			}
			packages = append(packages, *current)
		}
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}

		tag := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch tag {
		case "SPDXVersion":
			specVersion = val
		case "DocumentName":
			docName = val
		case "DocumentNamespace":
			docNamespace = val
		case "Creator":
			if strings.HasPrefix(val, "Tool:") {
				toolName = strings.TrimSpace(strings.TrimPrefix(val, "Tool:"))
			}
		case "Created":
			timestamp = val
		case "PackageName":
			flushCurrent()
			current = &tagPkg{
				Name:   val,
				Hashes: make(map[string]string),
			}
		case "SPDXID":
			if current != nil {
				current.SPDXID = val
			}
		case "PackageVersion":
			if current != nil {
				current.Version = val
			}
		case "PackageLicenseConcluded":
			if current != nil {
				current.LicenseConcluded = val
			}
		case "PackageChecksum":
			if current != nil {
				csParts := strings.SplitN(val, ":", 2)
				if len(csParts) == 2 {
					alg := strings.ToUpper(strings.TrimSpace(csParts[0]))
					hashVal := strings.TrimSpace(csParts[1])
					current.Hashes[alg] = hashVal
				}
			}
		case "ExternalRef":
			if current != nil {
				fields := strings.Fields(val)
				if len(fields) >= 3 {
					refType := strings.ToLower(fields[1])
					refLoc := fields[2]
					if refType == "purl" {
						current.Purl = refLoc
					} else if strings.HasPrefix(refType, "cpe") {
						current.CPE = refLoc
					}
				}
			}
		case "Relationship":
			fields := strings.Fields(val)
			if len(fields) >= 3 {
				from := fields[0]
				relType := strings.ToUpper(fields[1])
				to := fields[2]

				switch relType {
				case "DESCRIBES":
					if strings.EqualFold(from, "SPDXRef-DOCUMENT") || rootRef == "" {
						rootRef = to
					}
				case "DESCRIBED_BY":
					if strings.EqualFold(to, "SPDXRef-DOCUMENT") || rootRef == "" {
						rootRef = from
					}
				case "DEPENDS_ON", "CONTAINS", "DYNAMIC_LINK", "STATIC_LINK":
					edges = append(edges, EdgeEvent{
						Type: EventEdge,
						From: from,
						To:   to,
					})
				case "DEPENDENCY_OF", "CONTAINED_BY":
					edges = append(edges, EdgeEvent{
						Type: EventEdge,
						From: to,
						To:   from,
					})
				}
			}
		}
	}
	flushCurrent()

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("tag-value scan error: %w", err)
	}

	if rootRef == "" && len(packages) > 0 {
		for _, pkg := range packages {
			if docName != "" && strings.EqualFold(pkg.Name, docName) {
				rootRef = pkg.SPDXID
				break
			}
		}
		if rootRef == "" {
			rootRef = packages[0].SPDXID
		}
	}

	// 1. Emit MetadataEvent
	_ = emit(MetadataEvent{
		Type:         EventMetadata,
		Format:       format,
		SpecVersion:  specVersion,
		SerialNumber: docNamespace,
		Timestamp:    timestamp,
		ToolName:     toolName,
		RootRef:      rootRef,
	})

	// 2. Emit ComponentEvents
	for _, pkg := range packages {
		var licenses []string
		if pkg.LicenseConcluded != "" && pkg.LicenseConcluded != "NOASSERTION" && pkg.LicenseConcluded != "NONE" {
			licenses = append(licenses, pkg.LicenseConcluded)
		}

		_ = emit(ComponentEvent{
			Type:     EventComponent,
			Ref:      pkg.SPDXID,
			Name:     pkg.Name,
			Version:  pkg.Version,
			Purl:     pkg.Purl,
			PurlBase: pkg.PurlBase,
			Licenses: licenses,
			Hashes:   pkg.Hashes,
			IsRoot:   pkg.SPDXID == rootRef,
		})

		if opts.ExtractVulnerabilities && pkg.CPE != "" {
			_ = emit(VulnerabilityEvent{
				Type:        EventVulnerability,
				ID:          "CPE:" + pkg.CPE,
				AffectedRef: pkg.SPDXID,
				Description: "CPE identifier for package " + pkg.Name,
			})
		}
	}

	// 3. Emit EdgeEvents
	for _, e := range edges {
		e.Direct = (e.From == rootRef)
		_ = emit(e)
	}

	return nil
}

func parseSPDX3Stream(dec *json.Decoder, emit func(any) error, opts Options) error {
	var elements []map[string]any
	if err := dec.Decode(&elements); err != nil {
		return fmt.Errorf("spdx 3.0 decode @graph error: %w", err)
	}

	specVer := "SPDX-3.0"
	var rootRef string

	type parsedPkg struct {
		id       string
		name     string
		version  string
		purl     string
		purlBase string
	}
	var pkgs []parsedPkg
	var edges []EdgeEvent

	for _, elem := range elements {
		elemType, _ := elem["@type"].(string)
		spdxID, _ := elem["spdxId"].(string)
		if spdxID == "" {
			spdxID, _ = elem["@id"].(string)
		}

		switch elemType {
		case "SoftwarePackage", "Package":
			name, _ := elem["name"].(string)
			version, _ := elem["packageVersion"].(string)
			purl, _ := elem["packageUrl"].(string)
			purlBase := ""
			if purl != "" {
				_, purlBase, _ = normalize.CanonicalPURL(purl)
			}
			pkgs = append(pkgs, parsedPkg{
				id:       spdxID,
				name:     name,
				version:  version,
				purl:     purl,
				purlBase: purlBase,
			})
		case "Relationship":
			from, _ := elem["from"].(string)
			relType, _ := elem["relationshipType"].(string)
			var targets []string
			if toStr, ok := elem["to"].(string); ok {
				targets = append(targets, toStr)
			} else if toSlice, ok := elem["to"].([]any); ok {
				for _, item := range toSlice {
					if str, ok := item.(string); ok {
						targets = append(targets, str)
					}
				}
			}
			normRel := strings.ToLower(relType)
			for _, target := range targets {
				switch normRel {
				case "dependson", "contains", "hasdependency":
					edges = append(edges, EdgeEvent{
						Type: EventEdge,
						From: from,
						To:   target,
					})
				case "dependencyof", "containedby":
					edges = append(edges, EdgeEvent{
						Type: EventEdge,
						From: target,
						To:   from,
					})
				case "describes":
					rootRef = target
				}
			}
		}
	}

	if rootRef == "" && len(pkgs) > 0 {
		rootRef = pkgs[0].id
	}

	_ = emit(MetadataEvent{
		Type:        EventMetadata,
		Format:      "SPDX",
		SpecVersion: specVer,
		RootRef:     rootRef,
	})

	for _, p := range pkgs {
		_ = emit(ComponentEvent{
			Type:     EventComponent,
			Ref:      p.id,
			Name:     p.name,
			Version:  p.version,
			Purl:     p.purl,
			PurlBase: p.purlBase,
			IsRoot:   p.id == rootRef,
		})
	}

	for _, e := range edges {
		e.Direct = (e.From == rootRef)
		_ = emit(e)
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
