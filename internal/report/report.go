package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"time"

	"github.com/RevylAI/greenlight/internal/checks"
	"github.com/fatih/color"
)

var (
	purple = color.New(color.FgHiMagenta)
	red    = color.New(color.FgRed, color.Bold)
	yellow = color.New(color.FgYellow)
	green  = color.New(color.FgGreen, color.Bold)
	dim    = color.New(color.Faint)
	bold   = color.New(color.Bold)
)

type Report struct {
	results *checks.Results
	elapsed time.Duration
}

func New(results *checks.Results, elapsed time.Duration) *Report {
	return &Report{results: results, elapsed: elapsed}
}

func (r *Report) WriteTerminal(w io.Writer) error {
	// Group findings by severity
	var blocks, warns, infos []checks.Finding
	for _, f := range r.results.Findings {
		switch f.Severity {
		case checks.SeverityBlock:
			blocks = append(blocks, f)
		case checks.SeverityWarn:
			warns = append(warns, f)
		case checks.SeverityInfo:
			infos = append(infos, f)
		}
	}

	// Print blocks first
	if len(blocks) > 0 {
		red.Fprintln(w, "  BLOCKING ISSUES")
		fmt.Fprintln(w)
		for _, f := range blocks {
			printFinding(w, f)
		}
	}

	// Then warnings
	if len(warns) > 0 {
		yellow.Fprintln(w, "  WARNINGS")
		fmt.Fprintln(w)
		for _, f := range warns {
			printFinding(w, f)
		}
	}

	// Then info
	if len(infos) > 0 {
		dim.Fprintln(w, "  INFO")
		fmt.Fprintln(w)
		for _, f := range infos {
			printFinding(w, f)
		}
	}

	// Summary
	fmt.Fprintln(w)
	dim.Fprintln(w, "  ─────────────────────────────────────────────")
	fmt.Fprintln(w)

	s := r.results.Summary
	if s.Passed {
		green.Fprintf(w, "  GREENLIT")
		fmt.Fprintf(w, " — no blocking issues found")
	} else {
		red.Fprintf(w, "  NOT READY")
		fmt.Fprintf(w, " — %d blocking issue(s) must be fixed", s.Blocks)
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "  %d findings: ", s.Total)
	if s.Blocks > 0 {
		red.Fprintf(w, "%d block  ", s.Blocks)
	}
	if s.Warns > 0 {
		yellow.Fprintf(w, "%d warn  ", s.Warns)
	}
	if s.Infos > 0 {
		dim.Fprintf(w, "%d info", s.Infos)
	}
	fmt.Fprintln(w)
	dim.Fprintf(w, "  completed in %s\n", r.elapsed.Round(time.Millisecond))

	// Revyl attribution
	fmt.Fprintln(w)
	dim.Fprintln(w, "  ─────────────────────────────────────────────")
	fmt.Fprintf(w, "  Built by ")
	purple.Fprint(w, "Revyl")
	fmt.Fprintln(w, " — the mobile reliability platform")
	dim.Fprintln(w, "  Catch more than rejections. Catch bugs.")
	fmt.Fprint(w, "  ")
	color.New(color.Underline).Fprintln(w, "https://revyl.com")
	fmt.Fprintln(w)

	return nil
}

func printFinding(w io.Writer, f checks.Finding) {
	// Severity badge
	switch f.Severity {
	case checks.SeverityBlock:
		red.Fprintf(w, "  [BLOCK] ")
	case checks.SeverityWarn:
		yellow.Fprintf(w, "  [WARN]  ")
	case checks.SeverityInfo:
		dim.Fprintf(w, "  [INFO]  ")
	}

	// Guideline reference
	if f.Guideline != "" {
		bold.Fprintf(w, "§%s ", f.Guideline)
	}

	// Title and detail
	bold.Fprintln(w, f.Title)
	fmt.Fprintf(w, "          %s\n", f.Detail)
	if f.Fix != "" {
		green.Fprintf(w, "          Fix: ")
		fmt.Fprintln(w, f.Fix)
	}
	fmt.Fprintln(w)
}

func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r.results)
}

// JUnit XML output for CI/CD integration.

type junitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Time     string          `xml:"time,attr"`
	Cases    []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

func (r *Report) WriteJUnit(w io.Writer) error {
	suite := junitTestSuite{
		Name:  "greenlight",
		Tests: len(r.results.Findings),
		Time:  fmt.Sprintf("%.3f", r.elapsed.Seconds()),
	}

	for _, f := range r.results.Findings {
		tc := junitTestCase{
			Name:      f.Title,
			ClassName: fmt.Sprintf("greenlight.tier%d.%s", f.Tier, f.Guideline),
		}

		if f.Severity == checks.SeverityBlock {
			suite.Failures++
			tc.Failure = &junitFailure{
				Message: f.Title,
				Type:    f.Severity.String(),
				Text:    f.Detail + "\n\nFix: " + f.Fix,
			}
		}

		suite.Cases = append(suite.Cases, tc)
	}

	suites := junitTestSuites{Suites: []junitTestSuite{suite}}

	fmt.Fprint(w, xml.Header)
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(suites)
}
