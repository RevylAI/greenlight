package checks

// Severity indicates how likely a finding is to cause rejection.
type Severity int

const (
	SeverityInfo  Severity = iota // Best practice recommendation
	SeverityWarn                  // High risk of rejection
	SeverityBlock                 // Will almost certainly be rejected
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarn:
		return "WARN"
	case SeverityBlock:
		return "BLOCK"
	default:
		return "UNKNOWN"
	}
}

// Tier represents the check tier level.
type Tier int

const (
	TierMetadata Tier = 1 // API-based metadata & completeness
	TierContent  Tier = 2 // AI-powered content analysis
	TierBinary   Tier = 3 // IPA binary inspection
	TierPattern  Tier = 4 // Historical pattern matching
)

// Finding is a single issue found during scanning.
type Finding struct {
	Tier      Tier     `json:"tier"`
	Severity  Severity `json:"severity"`
	Guideline string   `json:"guideline"` // e.g. "2.1", "5.1.1"
	Title     string   `json:"title"`
	Detail    string   `json:"detail"`
	Fix       string   `json:"fix,omitempty"`
}

// Results holds the complete scan output.
type Results struct {
	AppID    string    `json:"app_id"`
	AppName  string    `json:"app_name"`
	Findings []Finding `json:"findings"`
	Summary  Summary   `json:"summary"`
}

// Summary provides aggregate counts.
type Summary struct {
	Total  int  `json:"total"`
	Blocks int  `json:"blocks"`
	Warns  int  `json:"warns"`
	Infos  int  `json:"infos"`
	Passed bool `json:"passed"` // true if zero BLOCKs
}

func (r *Results) ComputeSummary() {
	r.Summary = Summary{}
	for _, f := range r.Findings {
		r.Summary.Total++
		switch f.Severity {
		case SeverityBlock:
			r.Summary.Blocks++
		case SeverityWarn:
			r.Summary.Warns++
		case SeverityInfo:
			r.Summary.Infos++
		}
	}
	r.Summary.Passed = r.Summary.Blocks == 0
}
