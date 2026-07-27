package playscan

import (
	"archive/zip"
	"debug/elf"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// pageSize16KB is the alignment Google Play requires of native code so it can
// load on 16 KB page size devices.
const pageSize16KB = 16384

// ArchiveKind distinguishes the two upload formats.
type ArchiveKind string

const (
	KindAPK ArchiveKind = "APK"
	KindAAB ArchiveKind = "AAB"
)

// nativeLib is one shared library found in the archive.
type nativeLib struct {
	Path string
	ABI  string
	// SegmentAlign is the smallest alignment across the ELF LOAD segments.
	SegmentAlign uint64
	HasRelro     bool
	// ZipOffset is where the entry's data begins in the archive, which must be
	// 16 KB aligned for the loader to map the library directly.
	ZipOffset int64
	Stored    bool
	ParseErr  error
}

// ScanArchive checks a built APK or AAB.
//
// The manifest inside a build is the merged one, so unlike a source scan this
// sees permissions contributed by library manifests. Every policy rule runs
// against it unchanged, plus the native code checks that only exist here.
func ScanArchive(archivePath string) (*ScanResult, error) {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, fmt.Errorf("cannot open archive: %w", err)
	}
	defer zr.Close()

	kind, manifestEntry := classifyArchive(&zr.Reader)
	if kind == "" {
		return nil, fmt.Errorf("not an APK or AAB: no AndroidManifest.xml found in %s", archivePath)
	}

	result := &ScanResult{
		ProjectPath:  archivePath,
		ArchiveKind:  string(kind),
		ManifestPath: manifestEntry,
		IsArchive:    true,
	}

	var manifest *Manifest
	if manifestEntry != "" {
		data, err := readZipEntry(&zr.Reader, manifestEntry)
		if err != nil {
			return nil, fmt.Errorf("read manifest: %w", err)
		}
		switch kind {
		case KindAPK:
			manifest, err = DecodeBinaryXML(data)
		case KindAAB:
			manifest, err = DecodeProtoXML(data)
		}
		if err != nil {
			result.Findings = append(result.Findings, Finding{
				Severity: sevWarn,
				Policy:   "Scan coverage",
				Title:    "Could not decode the bundled AndroidManifest.xml",
				Detail: "The archive's manifest could not be decoded, so manifest-based policy checks were skipped: " + err.Error() +
					". Native code checks below are unaffected.",
				Fix:  "Run the scan against the project source as well, which reads the manifest before it is compiled.",
				File: manifestEntry,
			})
		}
	}

	if manifest != nil {
		result.PackageName = manifest.Package
		result.Permissions = manifest.AllPermissions()
		if manifest.UsesSDK != nil {
			result.TargetSDK = parseSDKInt(manifest.UsesSDK.TargetSDKVersion)
			result.MinSDK = parseSDKInt(manifest.UsesSDK.MinSDKVersion)
		}

		ctx := &ruleContext{
			manifest: manifest,
			// A built archive carries no Gradle state; rules that read it are
			// source-only and correctly stay silent.
			gradle:       &GradleInfo{},
			targetSDK:    result.TargetSDK,
			manifestFile: manifestEntry,
		}
		for _, rule := range allRules() {
			result.Findings = append(result.Findings, rule(ctx)...)
		}
	}

	libs := collectNativeLibs(&zr.Reader, kind)
	result.NativeLibCount = len(libs)
	result.Findings = append(result.Findings, checkPageAlignment(libs, kind)...)

	return result, nil
}

// classifyArchive determines the format and locates the manifest entry.
func classifyArchive(zr *zip.Reader) (ArchiveKind, string) {
	var hasBundleLayout bool
	for _, f := range zr.File {
		switch f.Name {
		case "AndroidManifest.xml":
			return KindAPK, f.Name
		case "base/manifest/AndroidManifest.xml":
			hasBundleLayout = true
		}
	}
	if hasBundleLayout {
		return KindAAB, "base/manifest/AndroidManifest.xml"
	}
	return "", ""
}

func readZipEntry(zr *zip.Reader, name string) ([]byte, error) {
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(io.LimitReader(rc, 32<<20))
	}
	return nil, fmt.Errorf("entry not found: %s", name)
}

// collectNativeLibs finds every packaged .so and reads what the alignment
// checks need. Both archive layouts are handled.
func collectNativeLibs(zr *zip.Reader, kind ArchiveKind) []nativeLib {
	prefix := "lib/"
	if kind == KindAAB {
		prefix = "base/lib/"
	}

	var libs []nativeLib
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, prefix) || !strings.HasSuffix(f.Name, ".so") {
			continue
		}
		lib := nativeLib{
			Path:   f.Name,
			ABI:    abiFromPath(f.Name, prefix),
			Stored: f.Method == zip.Store,
		}
		if off, err := f.DataOffset(); err == nil {
			lib.ZipOffset = off
		}

		rc, err := f.Open()
		if err != nil {
			lib.ParseErr = err
			libs = append(libs, lib)
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, 256<<20))
		rc.Close()
		if err != nil {
			lib.ParseErr = err
			libs = append(libs, lib)
			continue
		}
		readELFAlignment(&lib, data)
		libs = append(libs, lib)
	}

	sort.Slice(libs, func(i, j int) bool { return libs[i].Path < libs[j].Path })
	return libs
}

func abiFromPath(name, prefix string) string {
	rest := strings.TrimPrefix(name, prefix)
	if i := strings.Index(rest, "/"); i > 0 {
		return rest[:i]
	}
	return path.Dir(rest)
}

// readELFAlignment records the minimum LOAD segment alignment and whether the
// library has GNU_RELRO, both of which the 16 KB requirement depends on.
func readELFAlignment(lib *nativeLib, data []byte) {
	f, err := elf.NewFile(newByteReaderAt(data))
	if err != nil {
		lib.ParseErr = err
		return
	}
	defer f.Close()

	var minAlign uint64
	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_LOAD:
			if minAlign == 0 || p.Align < minAlign {
				minAlign = p.Align
			}
		case elf.PT_GNU_RELRO:
			lib.HasRelro = true
		}
	}
	lib.SegmentAlign = minAlign
}

// checkPageAlignment produces the 16 KB page size findings.
//
// Only arm64-v8a is assessed for the requirement itself: 16 KB page size
// devices are 64-bit ARM, so a 32-bit library being 4 KB aligned is not a
// violation and reporting it would be noise.
func checkPageAlignment(libs []nativeLib, kind ArchiveKind) []Finding {
	if len(libs) == 0 {
		return nil
	}

	var unaligned, missingRelro, badZipOffset []string
	for _, lib := range libs {
		if lib.ABI != "arm64-v8a" {
			continue
		}
		if lib.ParseErr != nil {
			continue
		}
		if lib.SegmentAlign > 0 && lib.SegmentAlign < pageSize16KB {
			unaligned = append(unaligned, fmt.Sprintf("%s (align %s)", path.Base(lib.Path), formatAlign(lib.SegmentAlign)))
		}
		if !lib.HasRelro {
			missingRelro = append(missingRelro, path.Base(lib.Path))
		}
		// Zip alignment only applies to an APK, where the loader maps the
		// library straight out of the archive. An AAB is repackaged by Play,
		// so its entry offsets say nothing about the delivered APK.
		if kind == KindAPK && lib.Stored && lib.ZipOffset%pageSize16KB != 0 {
			badZipOffset = append(badZipOffset, path.Base(lib.Path))
		}
	}

	var findings []Finding

	if len(unaligned) > 0 {
		findings = append(findings, Finding{
			Severity: sevCritical,
			Policy:   "16 KB page size",
			Title:    "Native libraries are not 16 KB aligned",
			Detail: fmt.Sprintf(
				"Google Play requires apps targeting Android 15 and above to support 16 KB page sizes, and these arm64-v8a libraries have LOAD segments aligned below 16384 bytes: %s. "+
					"On a 16 KB page size device the app fails to load them and crashes at startup.",
				strings.Join(truncateList(unaligned, 6), ", ")),
			Fix: "Rebuild with AGP 8.5.1+ and NDK r28+, or add -Wl,-z,max-page-size=16384 to the linker flags. Prebuilt dependencies must be updated to a 16 KB compatible release.",
			Doc: docPageSizes,
		})
	}

	if len(badZipOffset) > 0 {
		findings = append(findings, Finding{
			Severity: sevHigh,
			Policy:   "16 KB page size",
			Title:    "Uncompressed native libraries are not 16 KB zip-aligned",
			Detail: fmt.Sprintf(
				"These libraries are stored uncompressed but do not begin on a 16384-byte boundary in the archive: %s. "+
					"The loader maps them straight out of the APK, so a misaligned offset defeats 16 KB support even when the ELF segments themselves are aligned.",
				strings.Join(truncateList(badZipOffset, 6), ", ")),
			Fix: "Repackage with zipalign -P 16 4, or let AGP 8.5.1+ handle it.",
			Doc: docPageSizes,
		})
	}

	if len(missingRelro) > 0 {
		findings = append(findings, Finding{
			Severity: sevWarn,
			Policy:   "16 KB page size",
			Title:    "Native libraries are missing GNU_RELRO",
			Detail: fmt.Sprintf(
				"These libraries have no GNU_RELRO segment: %s. Combining a RELRO-enabled section with a non-RELRO one on the same page crashes the app on 16 KB devices.",
				strings.Join(truncateList(missingRelro, 6), ", ")),
			Fix: "Rebuild with a current NDK, which emits GNU_RELRO by default.",
			Doc: docPageSizes,
		})
	}

	return findings
}

func formatAlign(align uint64) string {
	switch align {
	case 4096:
		return "4 KB"
	case 8192:
		return "8 KB"
	case 16384:
		return "16 KB"
	case 65536:
		return "64 KB"
	}
	return fmt.Sprintf("%d bytes", align)
}

func truncateList(items []string, max int) []string {
	if len(items) <= max {
		return items
	}
	out := append([]string{}, items[:max]...)
	return append(out, fmt.Sprintf("and %d more", len(items)-max))
}

// byteReaderAt adapts a byte slice to io.ReaderAt for debug/elf.
type byteReaderAt struct{ b []byte }

func newByteReaderAt(b []byte) *byteReaderAt { return &byteReaderAt{b: b} }

func (r *byteReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(r.b)) {
		return 0, io.EOF
	}
	n := copy(p, r.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
