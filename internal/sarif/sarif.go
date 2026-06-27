// Package sarif renders compliance findings as a SARIF 2.1.0 log so they can be
// uploaded to GitHub code scanning and shown inline (Security tab / PR
// annotations) with file and line context.
package sarif

import (
	"encoding/json"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

// Finding is the minimal shape SARIF needs from any greenlight scanner.
type Finding struct {
	Severity  string // CRITICAL, HIGH, WARN, INFO
	Title     string
	Detail    string
	Guideline string // Apple guideline section, e.g. "2.5.1" (optional)
	File      string
	Line      int // 1-indexed; 0 means no line
}

const schemaURL = "https://json.schemastore.org/sarif-2.1.0.json"

// Write renders findings as a SARIF 2.1.0 document to w.
func Write(w io.Writer, toolName, toolVersion, infoURI string, findings []Finding) error {
	seen := map[string]bool{}
	// Both must serialize as [] (not null) when empty — SARIF requires arrays.
	rules := make([]rule, 0, len(findings))
	results := make([]result, 0, len(findings))

	for _, f := range findings {
		id := ruleID(f)
		if !seen[id] {
			seen[id] = true
			rules = append(rules, rule{
				ID:               id,
				Name:             f.Title,
				ShortDescription: textBlock{Text: f.Title},
			})
		}
		results = append(results, result{
			RuleID:    id,
			Level:     level(f.Severity),
			Message:   textBlock{Text: messageText(f)},
			Locations: locationsFor(f),
		})
	}

	doc := sarifDoc{
		Schema:  schemaURL,
		Version: "2.1.0",
		Runs: []run{{
			Tool: tool{Driver: driver{
				Name:           toolName,
				Version:        toolVersion,
				InformationURI: infoURI,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func messageText(f Finding) string {
	msg := f.Title
	if f.Guideline != "" {
		msg = "§" + f.Guideline + " " + msg
	}
	if f.Detail != "" {
		msg += ". " + f.Detail
	}
	return msg
}

func locationsFor(f Finding) []location {
	if f.File == "" {
		return nil
	}
	loc := location{PhysicalLocation: physicalLocation{
		ArtifactLocation: artifactLocation{URI: filepath.ToSlash(f.File)},
	}}
	if f.Line > 0 {
		loc.PhysicalLocation.Region = &region{StartLine: f.Line}
	}
	return []location{loc}
}

// level maps a greenlight severity to a SARIF result level.
func level(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "HIGH":
		return "error"
	case "WARN", "WARNING":
		return "warning"
	default:
		return "note"
	}
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// ruleID derives a stable SARIF rule id. greenlight findings don't carry the
// internal rule id, so we slug the title (stable per rule) and prefix the
// guideline when present so GitHub groups related findings.
func ruleID(f Finding) string {
	slug := strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(f.Title), "-"), "-")
	if slug == "" {
		slug = "finding"
	}
	if f.Guideline != "" {
		return "G" + f.Guideline + "/" + slug
	}
	return slug
}

type sarifDoc struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []rule `json:"rules"`
}

type rule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name,omitempty"`
	ShortDescription textBlock `json:"shortDescription"`
}

type result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level"`
	Message   textBlock  `json:"message"`
	Locations []location `json:"locations,omitempty"`
}

type textBlock struct {
	Text string `json:"text"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           *region          `json:"region,omitempty"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

type region struct {
	StartLine int `json:"startLine"`
}
