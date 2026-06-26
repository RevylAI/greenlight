package privacy

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Required Reason API detection must match real call sites that pass arguments —
// stat(path, &st) / statfs(&buf) — not only the argument-less stat() form, which
// essentially never appears in real source. The old `stat\(\)` patterns silently
// missed both categories.
func TestRequiredReasonDetectsRealCallSites(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Disk.swift", "func freeSpace() {\n  var b = statbuf\n  statfs(\"/\", &b)\n}\n")
	writeFile(t, dir, "Files.swift", "func when(path: String) {\n  var s = statbuf\n  stat(path, &s)\n}\n")

	res, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	want := map[string]bool{"Disk Space": false, "File Timestamp": false}
	for _, api := range res.DetectedAPIs {
		if _, ok := want[api]; ok {
			want[api] = true
		}
	}
	for api, found := range want {
		if !found {
			t.Errorf("expected %q detected from a real call site; DetectedAPIs=%v", api, res.DetectedAPIs)
		}
	}
}
