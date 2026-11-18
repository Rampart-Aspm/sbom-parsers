package runtime

import (
	"context"
	"encoding/json"
	"io"
	"iter"

	"github.com/rampart-aspm/sbom-parsers/pkg/domain"
)

type IntegrationKind string

const KindParser IntegrationKind = "parser"

type SupportLevel string

const (
	SupportBuiltin   SupportLevel = "builtin"
	SupportCertified SupportLevel = "certified"
	SupportCommunity SupportLevel = "community"
)

// Descriptor provides metadata about an integration component.
type Descriptor struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Kind         IntegrationKind `json:"kind"`
	Category     string          `json:"category,omitempty"`
	Version      string          `json:"version"`
	SupportLevel SupportLevel    `json:"support_level"`
	Description  string          `json:"description"`
	ConfigSchema json.RawMessage `json:"config_schema,omitempty"`
	Secrets      []string        `json:"secrets,omitempty"`
	Egress       []string        `json:"egress,omitempty"`
	Capabilities []string        `json:"capabilities,omitempty"`
}

// ParserContract defines the ingestion parsing interface.
type ParserContract interface {
	Descriptor() Descriptor
	Detect(head []byte, filename string, contentType string) (confidence int)
	Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error]
}

var (
	WasmParserLoader func(name string, raw []byte) (ParserContract, error)
	LuaParserLoader  func(name string, raw []byte) (ParserContract, error)
)
