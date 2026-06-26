package sarif

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestWriteProducesValidSARIF(t *testing.T) {
	findings := []Finding{
		{Severity: "CRITICAL", Title: "UIWebView is no longer accepted", Guideline: "2.5.1", File: "A.swift", Line: 3},
		{Severity: "WARN", Title: "Hardcoded IPv4 address", Guideline: "2.5", File: "B.ts", Line: 10},
		{Severity: "INFO", Title: "No encryption export-compliance declaration"}, // no file/line
		{Severity: "CRITICAL", Title: "UIWebView is no longer accepted", Guideline: "2.5.1", File: "C.swift", Line: 5},
	}

	var buf bytes.Buffer
	if err := Write(&buf, "greenlight", "v1.2.3", "https://example.com", findings); err != nil {
		t.Fatal(err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", doc["version"])
	}

	run := doc["runs"].([]interface{})[0].(map[string]interface{})
	driver := run["tool"].(map[string]interface{})["driver"].(map[string]interface{})
	if driver["name"] != "greenlight" || driver["version"] != "v1.2.3" {
		t.Errorf("driver = %+v", driver)
	}
	// The two UIWebView findings share a rule id, so rules dedups to 3.
	if rules := driver["rules"].([]interface{}); len(rules) != 3 {
		t.Errorf("rules = %d, want 3 (dedup by rule id)", len(rules))
	}

	results := run["results"].([]interface{})
	if len(results) != 4 {
		t.Fatalf("results = %d, want 4", len(results))
	}

	// CRITICAL -> error, with a file+line location.
	first := results[0].(map[string]interface{})
	if first["level"] != "error" {
		t.Errorf("CRITICAL level = %v, want error", first["level"])
	}
	loc := first["locations"].([]interface{})[0].(map[string]interface{})["physicalLocation"].(map[string]interface{})
	if loc["artifactLocation"].(map[string]interface{})["uri"] != "A.swift" {
		t.Errorf("uri = %+v, want A.swift", loc["artifactLocation"])
	}
	if loc["region"].(map[string]interface{})["startLine"].(float64) != 3 {
		t.Errorf("startLine = %v, want 3", loc["region"])
	}

	// INFO with no file -> note, and no locations key.
	third := results[2].(map[string]interface{})
	if third["level"] != "note" {
		t.Errorf("INFO level = %v, want note", third["level"])
	}
	if _, ok := third["locations"]; ok {
		t.Error("a finding with no file should have no locations")
	}
}

// Zero findings must still produce schema-valid SARIF: rules and results are
// empty arrays, never null.
func TestWriteEmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "greenlight", "v1", "", nil); err != nil {
		t.Fatal(err)
	}
	// A literal "null" for either array is a schema violation.
	if bytes.Contains(buf.Bytes(), []byte(`"rules": null`)) || bytes.Contains(buf.Bytes(), []byte(`"results": null`)) {
		t.Fatalf("arrays must serialize as [], not null:\n%s", buf.String())
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	run := doc["runs"].([]interface{})[0].(map[string]interface{})
	if rules := run["tool"].(map[string]interface{})["driver"].(map[string]interface{})["rules"]; rules == nil {
		t.Error("driver.rules is null, want []")
	}
	if results := run["results"]; results == nil {
		t.Error("results is null, want []")
	}
}

func TestLevelMapping(t *testing.T) {
	for sev, want := range map[string]string{
		"CRITICAL": "error", "HIGH": "error",
		"WARN": "warning", "warning": "warning",
		"INFO": "note", "": "note", "weird": "note",
	} {
		if got := level(sev); got != want {
			t.Errorf("level(%q) = %q, want %q", sev, got, want)
		}
	}
}
