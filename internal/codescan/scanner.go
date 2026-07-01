package codescan

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Scanner walks a project directory and runs pattern-based checks.
type Scanner struct {
	root    string
	verbose bool
	rules   []Rule
	cfg     *Config
}

// FileContext holds a scanned file and its lines for pattern matching.
type FileContext struct {
	Path     string
	RelPath  string
	Lines    []string
	Language string // "swift", "objc", "typescript", "javascript", "json", "plist"
}

func NewScanner(root string, verbose bool) *Scanner {
	return NewScannerWithConfig(root, verbose, nil)
}

// NewScannerWithConfig builds a scanner applying an optional .greenlight.yml
// (rule enable/disable, severity overrides, path ignores). A nil cfg is the
// default behavior.
func NewScannerWithConfig(root string, verbose bool, cfg *Config) *Scanner {
	s := &Scanner{
		root:    root,
		verbose: verbose,
		cfg:     cfg,
	}
	s.rules = cfg.applyRules(AllRules())
	return s
}

// Scan walks the project and runs all rules against matching files.
func (s *Scanner) Scan() ([]Finding, error) {
	files, err := s.collectFiles()
	if err != nil {
		return nil, err
	}

	// First pass: determine which global anti-pattern rules are satisfied
	// (i.e., anti-pattern found somewhere in the project).
	suppressed := make(map[string]bool)
	for _, rule := range s.rules {
		gar, ok := rule.(GlobalAntiPatternRule)
		if !ok || !gar.HasGlobalAntiPatterns() {
			continue
		}
		for _, f := range files {
			if !rule.Applies(f) {
				continue
			}
			if gar.AntiPatternMatched(f) {
				suppressed[gar.RuleID()] = true
				break
			}
		}
	}

	// Second pass: run all rules, skipping globally-suppressed ones.
	var (
		mu       sync.Mutex
		findings []Finding
		wg       sync.WaitGroup
	)

	sem := make(chan struct{}, 8) // limit concurrency
	for _, f := range files {
		wg.Add(1)
		sem <- struct{}{}
		go func(fc FileContext) {
			defer wg.Done()
			defer func() { <-sem }()

			for _, rule := range s.rules {
				if !rule.Applies(fc) {
					continue
				}
				// Skip rules whose global anti-patterns are satisfied.
				if gar, ok := rule.(GlobalAntiPatternRule); ok && gar.HasGlobalAntiPatterns() {
					if suppressed[gar.RuleID()] {
						continue
					}
				}
				hits := rule.Check(fc)
				if len(hits) > 0 {
					mu.Lock()
					findings = append(findings, hits...)
					mu.Unlock()
				}
			}
		}(f)
	}

	wg.Wait()

	// Collapse "missing safeguard" findings (firstMatchOnly rules) to one each
	// across the whole project, so the same project-level fact isn't reported
	// once per file that happens to trigger it.
	findings = dedupOnceRules(s.rules, findings)
	return findings, nil
}

// dedupOnceRules keeps a single finding (by title) for each firstMatchOnly rule.
// It stably sorts all findings by file/line/title first so the surviving finding
// is deterministic; other rules' findings are otherwise kept.
func dedupOnceRules(rules []Rule, findings []Finding) []Finding {
	once := make(map[string]bool)
	for _, r := range rules {
		if pr, ok := r.(*PatternRule); ok && pr.firstMatchOnly {
			once[pr.guideline+"\x00"+pr.title] = true
		}
	}
	if len(once) == 0 {
		return findings
	}
	// Findings are appended from goroutines, so their order is nondeterministic.
	// Sort by file/line/title so the surviving finding per rule is stable.
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Title < findings[j].Title
	})
	seen := make(map[string]bool)
	var out []Finding
	for _, f := range findings {
		key := f.Guideline + "\x00" + f.Title
		if once[key] {
			if seen[key] {
				continue
			}
			seen[key] = true
		}
		out = append(out, f)
	}
	return out
}

func (s *Scanner) collectFiles() ([]FileContext, error) {
	var files []FileContext

	skipDirs := map[string]bool{
		"node_modules": true, ".git": true, "Pods": true,
		"build": true, "dist": true, ".expo": true,
		"DerivedData": true, ".next": true, "vendor": true,
	}

	err := filepath.Walk(s.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip errors
		}

		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		lang := detectLanguage(path)
		if lang == "" {
			return nil
		}

		relPath, _ := filepath.Rel(s.root, path)

		// Honor .greenlight.yml ignore globs.
		if s.cfg.ignores(relPath) {
			return nil
		}

		lines, err := readLines(path)
		if err != nil {
			return nil
		}

		files = append(files, FileContext{
			Path:     path,
			RelPath:  relPath,
			Lines:    lines,
			Language: lang,
		})
		return nil
	})

	return files, err
}

func detectLanguage(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))

	switch ext {
	case ".swift":
		return "swift"
	case ".m", ".h", ".mm":
		return "objc"
	case ".ts", ".tsx":
		return "typescript"
	case ".js", ".jsx":
		return "javascript"
	case ".plist":
		return "plist"
	case ".entitlements":
		return "plist"
	case ".xcprivacy":
		return "plist"
	}

	switch base {
	case "package.json", "app.json", "app.config.js", "app.config.ts":
		return "json"
	case "info.plist":
		return "plist"
	case "privacyinfo.xcprivacy":
		return "plist"
	}

	return ""
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	// Increase buffer for large files
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
