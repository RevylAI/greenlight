package playscan

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- AXML construction -------------------------------------------------
//
// Building compiled manifests by hand keeps the decoder's tests hermetic; the
// alternative is committing a real APK. The byte layouts here mirror
// ResourceTypes.h exactly, so a regression in the decoder shows up as a
// decode failure rather than a fixture mismatch.

type axmlBuilder struct {
	strings []string
	resIDs  []uint32
	body    bytes.Buffer
}

func (b *axmlBuilder) str(s string) uint32 {
	for i, existing := range b.strings {
		if existing == s {
			return uint32(i)
		}
	}
	b.strings = append(b.strings, s)
	b.resIDs = append(b.resIDs, 0)
	return uint32(len(b.strings) - 1)
}

// attr registers an attribute name that carries a framework resource ID and an
// empty pool entry, which is what aapt2 actually emits.
func (b *axmlBuilder) attrRef(resID uint32) uint32 {
	b.strings = append(b.strings, "")
	b.resIDs = append(b.resIDs, resID)
	return uint32(len(b.strings) - 1)
}

type buildAttr struct {
	nameIdx  uint32
	dataType byte
	data     uint32
	rawIdx   uint32
}

func (b *axmlBuilder) startTag(name string, attrs []buildAttr) {
	nameIdx := b.str(name)
	var buf bytes.Buffer
	// ResXMLTree_node: lineNumber, comment
	binary.Write(&buf, binary.LittleEndian, uint32(1))
	binary.Write(&buf, binary.LittleEndian, uint32(0xFFFFFFFF))
	// ResXMLTree_attrExt
	binary.Write(&buf, binary.LittleEndian, uint32(0xFFFFFFFF)) // ns
	binary.Write(&buf, binary.LittleEndian, nameIdx)
	binary.Write(&buf, binary.LittleEndian, uint16(20)) // attributeStart, from attrExt
	binary.Write(&buf, binary.LittleEndian, uint16(20)) // attributeSize
	binary.Write(&buf, binary.LittleEndian, uint16(len(attrs)))
	binary.Write(&buf, binary.LittleEndian, uint16(0)) // idIndex
	binary.Write(&buf, binary.LittleEndian, uint16(0)) // classIndex
	binary.Write(&buf, binary.LittleEndian, uint16(0)) // styleIndex
	for _, a := range attrs {
		binary.Write(&buf, binary.LittleEndian, uint32(0xFFFFFFFF)) // ns
		binary.Write(&buf, binary.LittleEndian, a.nameIdx)
		binary.Write(&buf, binary.LittleEndian, a.rawIdx)
		binary.Write(&buf, binary.LittleEndian, uint16(8)) // typed value size
		buf.WriteByte(0)                                   // res0
		buf.WriteByte(a.dataType)
		binary.Write(&buf, binary.LittleEndian, a.data)
	}
	b.writeChunk(chunkXMLStartTag, buf.Bytes())
}

func (b *axmlBuilder) endTag(name string) {
	nameIdx := b.str(name)
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(1))
	binary.Write(&buf, binary.LittleEndian, uint32(0xFFFFFFFF))
	binary.Write(&buf, binary.LittleEndian, uint32(0xFFFFFFFF))
	binary.Write(&buf, binary.LittleEndian, nameIdx)
	b.writeChunk(chunkXMLEndTag, buf.Bytes())
}

func (b *axmlBuilder) writeChunk(chunkType uint16, payload []byte) {
	binary.Write(&b.body, binary.LittleEndian, chunkType)
	binary.Write(&b.body, binary.LittleEndian, uint16(8))
	binary.Write(&b.body, binary.LittleEndian, uint32(8+len(payload)))
	b.body.Write(payload)
}

// build emits the full document: header, string pool, resource map, then tags.
func (b *axmlBuilder) build() []byte {
	var pool bytes.Buffer
	offsets := make([]uint32, len(b.strings))
	var data bytes.Buffer
	for i, s := range b.strings {
		offsets[i] = uint32(data.Len())
		// UTF-16 form: u16 length, UTF-16LE units, u16 terminator.
		binary.Write(&data, binary.LittleEndian, uint16(len(s)))
		for _, r := range s {
			binary.Write(&data, binary.LittleEndian, uint16(r))
		}
		binary.Write(&data, binary.LittleEndian, uint16(0))
	}
	headerLen := 28 + len(offsets)*4
	binary.Write(&pool, binary.LittleEndian, uint32(len(b.strings))) // stringCount
	binary.Write(&pool, binary.LittleEndian, uint32(0))              // styleCount
	binary.Write(&pool, binary.LittleEndian, uint32(0))              // flags: UTF-16
	binary.Write(&pool, binary.LittleEndian, uint32(headerLen))      // stringsStart
	binary.Write(&pool, binary.LittleEndian, uint32(0))              // stylesStart
	for _, o := range offsets {
		binary.Write(&pool, binary.LittleEndian, o)
	}
	pool.Write(data.Bytes())

	var resMap bytes.Buffer
	for _, id := range b.resIDs {
		binary.Write(&resMap, binary.LittleEndian, id)
	}

	var out bytes.Buffer
	var chunks bytes.Buffer
	writeChunkTo(&chunks, chunkStringPool, pool.Bytes())
	writeChunkTo(&chunks, chunkXMLResource, resMap.Bytes())
	chunks.Write(b.body.Bytes())

	binary.Write(&out, binary.LittleEndian, uint16(chunkXMLDocument))
	binary.Write(&out, binary.LittleEndian, uint16(8))
	binary.Write(&out, binary.LittleEndian, uint32(8+chunks.Len()))
	out.Write(chunks.Bytes())
	return out.Bytes()
}

func writeChunkTo(w *bytes.Buffer, chunkType uint16, payload []byte) {
	binary.Write(w, binary.LittleEndian, chunkType)
	binary.Write(w, binary.LittleEndian, uint16(8))
	binary.Write(w, binary.LittleEndian, uint32(8+len(payload)))
	w.Write(payload)
}

// buildTestManifest produces a compiled manifest exercising the attribute
// forms that matter: a string permission name, a boolean, an integer SDK
// level, and a foregroundServiceType bitmask.
func buildTestManifest() []byte {
	return buildTestManifestWithSplit("")
}

func buildTestManifestWithSplit(split string) []byte {
	b := &axmlBuilder{}
	nameAttr := b.attrRef(0x01010003)
	debuggableAttr := b.attrRef(0x0101000f)
	targetSdkAttr := b.attrRef(0x01010270)
	exportedAttr := b.attrRef(0x01010010)
	fgsAttr := b.attrRef(0x01010599) // verified against aapt2, see TestFrameworkAttrIDsMatchAapt2

	pkgIdx := b.str("com.example.built")
	permIdx := b.str("android.permission.READ_SMS")
	perm2Idx := b.str("android.permission.FOREGROUND_SERVICE")
	svcIdx := b.str("com.example.SyncService")
	actIdx := b.str("com.example.MainActivity")
	mainIdx := b.str("android.intent.action.MAIN")
	launcherIdx := b.str("android.intent.category.LAUNCHER")
	packageAttr := b.str("package")

	manifestAttrs := []buildAttr{
		{nameIdx: packageAttr, dataType: typeString, data: pkgIdx, rawIdx: pkgIdx},
	}
	if split != "" {
		splitAttr := b.str("split")
		splitIdx := b.str(split)
		manifestAttrs = append(manifestAttrs, buildAttr{
			nameIdx: splitAttr, dataType: typeString, data: splitIdx, rawIdx: splitIdx,
		})
	}
	b.startTag("manifest", manifestAttrs)
	b.startTag("uses-permission", []buildAttr{
		{nameIdx: nameAttr, dataType: typeString, data: permIdx, rawIdx: permIdx},
	})
	b.endTag("uses-permission")
	b.startTag("uses-permission", []buildAttr{
		{nameIdx: nameAttr, dataType: typeString, data: perm2Idx, rawIdx: perm2Idx},
	})
	b.endTag("uses-permission")
	b.startTag("uses-sdk", []buildAttr{
		{nameIdx: targetSdkAttr, dataType: typeIntDec, data: 34, rawIdx: 0xFFFFFFFF},
	})
	b.endTag("uses-sdk")
	b.startTag("application", []buildAttr{
		{nameIdx: debuggableAttr, dataType: typeIntBoolean, data: 0xFFFFFFFF, rawIdx: 0xFFFFFFFF},
	})
	b.startTag("activity", []buildAttr{
		{nameIdx: nameAttr, dataType: typeString, data: actIdx, rawIdx: actIdx},
		{nameIdx: exportedAttr, dataType: typeIntBoolean, data: 0xFFFFFFFF, rawIdx: 0xFFFFFFFF},
	})
	b.startTag("intent-filter", nil)
	b.startTag("action", []buildAttr{
		{nameIdx: nameAttr, dataType: typeString, data: mainIdx, rawIdx: mainIdx},
	})
	b.endTag("action")
	b.startTag("category", []buildAttr{
		{nameIdx: nameAttr, dataType: typeString, data: launcherIdx, rawIdx: launcherIdx},
	})
	b.endTag("category")
	b.endTag("intent-filter")
	b.endTag("activity")
	// foregroundServiceType="location" is bit 3 in compiled form.
	b.startTag("service", []buildAttr{
		{nameIdx: nameAttr, dataType: typeString, data: svcIdx, rawIdx: svcIdx},
		{nameIdx: fgsAttr, dataType: typeIntHex, data: 1 << 3, rawIdx: 0xFFFFFFFF},
	})
	b.endTag("service")
	b.endTag("application")
	b.endTag("manifest")
	return b.build()
}

func TestDecodeBinaryXML(t *testing.T) {
	m, err := DecodeBinaryXML(buildTestManifest())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if m.Package != "com.example.built" {
		t.Errorf("Package = %q", m.Package)
	}
	if !m.HasPermission("android.permission.READ_SMS") {
		t.Error("READ_SMS not decoded")
	}
	if m.UsesSDK == nil || m.UsesSDK.TargetSDKVersion != "34" {
		t.Errorf("targetSdkVersion not decoded: %+v", m.UsesSDK)
	}
	if m.Application == nil || !attrIsTrue(m.Application.Debuggable) {
		t.Error("debuggable boolean not decoded as true")
	}
	if len(m.Application.Activities) != 1 || m.Application.Activities[0].Name != "com.example.MainActivity" {
		t.Fatalf("activity not decoded: %+v", m.Application.Activities)
	}
	if !attrIsTrue(m.Application.Activities[0].Exported) {
		t.Error("exported boolean not decoded")
	}
	if !m.HasLauncherActivity() {
		t.Error("launcher intent filter not decoded")
	}
	// The compiled bitmask must render back to the source attribute name so
	// the foreground service rule needs no second code path.
	if len(m.Application.Services) != 1 || m.Application.Services[0].ForegroundSvcType != "location" {
		t.Errorf("foregroundServiceType bitmask not decoded: %+v", m.Application.Services)
	}
}

func TestForegroundServiceTypeNames(t *testing.T) {
	cases := []struct {
		mask uint32
		want string
	}{
		{1 << 0, "dataSync"},
		{1 << 3, "location"},
		{1<<3 | 1<<6, "location|camera"},
		{1 << 30, "specialUse"},
		{0, ""},
	}
	for _, tc := range cases {
		if got := foregroundServiceTypeNames(tc.mask); got != tc.want {
			t.Errorf("mask %#x = %q, want %q", tc.mask, got, tc.want)
		}
	}
}

func TestDecodeBinaryXMLRejectsNonAXML(t *testing.T) {
	if _, err := DecodeBinaryXML([]byte("<?xml version=\"1.0\"?><manifest/>")); err == nil {
		t.Error("text XML should be rejected as not binary XML")
	}
	if _, err := DecodeBinaryXML([]byte{1, 2}); err == nil {
		t.Error("truncated input should error")
	}
}

// --- ELF + archive -----------------------------------------------------

// buildTestELF produces a minimal but valid 64-bit ARM shared object with one
// PT_LOAD segment at the requested alignment, optionally with GNU_RELRO.
func buildTestELF(align uint64, relro bool) []byte {
	const phoff = 64
	phnum := 1
	if relro {
		phnum = 2
	}
	phentsize := 56
	buf := make([]byte, phoff+phnum*phentsize)

	copy(buf[0:], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = 2                                    // 64-bit
	buf[5] = 1                                    // little endian
	buf[6] = 1                                    // version
	binary.LittleEndian.PutUint16(buf[16:], 3)    // ET_DYN
	binary.LittleEndian.PutUint16(buf[18:], 0xB7) // EM_AARCH64
	binary.LittleEndian.PutUint32(buf[20:], 1)
	binary.LittleEndian.PutUint64(buf[32:], phoff)
	binary.LittleEndian.PutUint16(buf[52:], 64)
	binary.LittleEndian.PutUint16(buf[54:], uint16(phentsize))
	binary.LittleEndian.PutUint16(buf[56:], uint16(phnum))

	writeProg := func(idx int, ptype uint32, palign uint64) {
		off := phoff + idx*phentsize
		binary.LittleEndian.PutUint32(buf[off:], ptype)
		binary.LittleEndian.PutUint32(buf[off+4:], 4) // flags
		binary.LittleEndian.PutUint64(buf[off+48:], palign)
	}
	writeProg(0, 1, align) // PT_LOAD
	if relro {
		writeProg(1, 0x6474e552, 1) // PT_GNU_RELRO
	}
	return buf
}

// buildTestAPK writes an APK containing a compiled manifest and the given
// native libraries.
func buildTestAPK(t *testing.T, libs map[string][]byte) string {
	t.Helper()
	return buildTestAPKWithManifest(t, buildTestManifest(), libs)
}

func buildTestAPKWithManifest(t *testing.T, manifest []byte, libs map[string][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.apk")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	mw, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := mw.Write(manifest); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	for name, data := range libs {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return path
}

func TestScanArchiveRunsPolicyRulesOnMergedManifest(t *testing.T) {
	apk := buildTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libgood.so": buildTestELF(16384, true),
	})

	res, err := ScanArchive(apk)
	if err != nil {
		t.Fatalf("ScanArchive: %v", err)
	}
	if res.ArchiveKind != string(KindAPK) {
		t.Errorf("ArchiveKind = %q", res.ArchiveKind)
	}
	if !res.IsArchive {
		t.Error("IsArchive not set")
	}
	if res.PackageName != "com.example.built" {
		t.Errorf("PackageName = %q", res.PackageName)
	}
	if res.TargetSDK != 34 {
		t.Errorf("TargetSDK = %d, want 34 from the merged manifest", res.TargetSDK)
	}

	// The same source-tree rules must fire against the compiled manifest.
	for _, policy := range []string{
		"Target API level",             // targetSdk 34
		"SMS and Call Log permissions", // READ_SMS
		"Malicious Behavior",           // debuggable=true
		"Foreground services",          // location without its permission
	} {
		if findByPolicy(res.Findings, policy) == nil {
			t.Errorf("policy %q did not fire on the archive scan", policy)
		}
	}
	// A correctly aligned library must not be reported.
	if f := findByPolicy(res.Findings, "16 KB page size"); f != nil {
		t.Errorf("aligned library reported: %s", f.Title)
	}
}

func TestScanArchiveDetects16KBMisalignment(t *testing.T) {
	apk := buildTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libold.so": buildTestELF(4096, true),
	})
	res, err := ScanArchive(apk)
	if err != nil {
		t.Fatalf("ScanArchive: %v", err)
	}
	f := findByPolicy(res.Findings, "16 KB page size")
	if f == nil {
		t.Fatal("4 KB aligned arm64 library was not reported")
	}
	if f.Severity != sevCritical {
		t.Errorf("severity = %s, want CRITICAL", f.Severity)
	}
	if !strings.Contains(f.Detail, "libold.so") || !strings.Contains(f.Detail, "4 KB") {
		t.Errorf("detail should name the library and its alignment: %s", f.Detail)
	}
}

// 16 KB page size devices are 64-bit ARM, so a 32-bit library at 4 KB is not a
// violation and reporting it would be noise.
func TestScanArchiveIgnoresNon64BitABIs(t *testing.T) {
	apk := buildTestAPK(t, map[string][]byte{
		"lib/armeabi-v7a/libold.so": buildTestELF(4096, true),
		"lib/x86/libold.so":         buildTestELF(4096, true),
	})
	res, err := ScanArchive(apk)
	if err != nil {
		t.Fatalf("ScanArchive: %v", err)
	}
	if f := findByPolicy(res.Findings, "16 KB page size"); f != nil {
		t.Errorf("32-bit ABI reported for 16 KB alignment: %s", f.Title)
	}
}

func TestScanArchiveFlagsMissingRelro(t *testing.T) {
	apk := buildTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libnorelro.so": buildTestELF(16384, false),
	})
	res, err := ScanArchive(apk)
	if err != nil {
		t.Fatalf("ScanArchive: %v", err)
	}
	var found bool
	for _, f := range res.Findings {
		if f.Policy == "16 KB page size" && strings.Contains(f.Title, "GNU_RELRO") {
			found = true
		}
	}
	if !found {
		t.Error("library without GNU_RELRO was not reported")
	}
}

func TestScanArchiveRejectsNonAndroidZip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notanapk.zip")
	f, _ := os.Create(path)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("readme.txt")
	w.Write([]byte("hello"))
	zw.Close()
	f.Close()

	if _, err := ScanArchive(path); err == nil {
		t.Error("a zip with no AndroidManifest.xml should be rejected")
	}
}

func TestScanArchiveDetectsBundleLayout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.aab")
	f, _ := os.Create(path)
	zw := zip.NewWriter(f)
	// A bundle's manifest is protobuf, which this fixture does not supply;
	// the point here is that the AAB layout is recognised and the undecodable
	// manifest is surfaced rather than silently passing.
	w, _ := zw.Create("base/manifest/AndroidManifest.xml")
	w.Write([]byte{0x00})
	lw, _ := zw.Create("base/lib/arm64-v8a/libold.so")
	lw.Write(buildTestELF(4096, true))
	zw.Close()
	f.Close()

	res, err := ScanArchive(path)
	if err != nil {
		t.Fatalf("ScanArchive: %v", err)
	}
	if res.ArchiveKind != string(KindAAB) {
		t.Errorf("ArchiveKind = %q, want AAB", res.ArchiveKind)
	}
	if findByPolicy(res.Findings, "Scan coverage") == nil {
		t.Error("an undecodable manifest must be surfaced, not silently skipped")
	}
	// Native checks still run against the bundle's lib/ layout.
	if findByPolicy(res.Findings, "16 KB page size") == nil {
		t.Error("bundle native libraries were not checked")
	}
}

// --- AAB protobuf manifest ---------------------------------------------

// pbField encodes one length-delimited protobuf field.
func pbField(num int, payload []byte) []byte {
	var out []byte
	out = binary.AppendUvarint(out, uint64(num)<<3|2)
	out = binary.AppendUvarint(out, uint64(len(payload)))
	return append(out, payload...)
}

func pbString(num int, s string) []byte { return pbField(num, []byte(s)) }

// pbAttr builds an XmlAttribute { name = 2, value = 3 }.
func pbAttr(name, value string) []byte {
	return append(pbString(2, name), pbString(3, value)...)
}

// pbElement builds an XmlElement { name = 3, attribute = 4, child = 5 },
// wrapped in the XmlNode { element = 1 } the format nests everything in.
func pbElement(name string, attrs [][]byte, children [][]byte) []byte {
	elem := pbString(3, name)
	for _, a := range attrs {
		elem = append(elem, pbField(4, a)...)
	}
	for _, c := range children {
		elem = append(elem, pbField(5, c)...)
	}
	return pbField(1, elem)
}

func TestDecodeProtoXML(t *testing.T) {
	manifest := pbElement("manifest",
		[][]byte{pbAttr("package", "com.example.bundle")},
		[][]byte{
			pbElement("uses-permission", [][]byte{pbAttr("name", "android.permission.READ_SMS")}, nil),
			pbElement("uses-sdk", [][]byte{pbAttr("targetSdkVersion", "34")}, nil),
			pbElement("application",
				[][]byte{pbAttr("debuggable", "true")},
				[][]byte{
					pbElement("service", [][]byte{
						pbAttr("name", "com.example.Sync"),
						pbAttr("foregroundServiceType", "location"),
					}, nil),
				}),
		})

	m, err := DecodeProtoXML(manifest)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if m.Package != "com.example.bundle" {
		t.Errorf("Package = %q", m.Package)
	}
	if !m.HasPermission("android.permission.READ_SMS") {
		t.Error("permission not decoded from protobuf manifest")
	}
	if m.UsesSDK == nil || m.UsesSDK.TargetSDKVersion != "34" {
		t.Errorf("targetSdkVersion not decoded: %+v", m.UsesSDK)
	}
	if m.Application == nil || !attrIsTrue(m.Application.Debuggable) {
		t.Error("debuggable not decoded")
	}
	if len(m.Application.Services) != 1 || m.Application.Services[0].ForegroundSvcType != "location" {
		t.Errorf("nested service not decoded: %+v", m.Application)
	}
}

func TestDecodeProtoXMLRejectsGarbage(t *testing.T) {
	if _, err := DecodeProtoXML([]byte{0xFF, 0xFF, 0xFF}); err == nil {
		t.Error("malformed protobuf should error rather than yield an empty manifest")
	}
}

// A full AAB with a real protobuf manifest must run the policy rules just as
// an APK does.
func TestScanArchiveAABEndToEnd(t *testing.T) {
	manifest := pbElement("manifest",
		[][]byte{pbAttr("package", "com.example.bundle")},
		[][]byte{
			pbElement("uses-permission", [][]byte{pbAttr("name", "android.permission.QUERY_ALL_PACKAGES")}, nil),
			pbElement("uses-sdk", [][]byte{pbAttr("targetSdkVersion", "34")}, nil),
			pbElement("application", nil, nil),
		})

	path := filepath.Join(t.TempDir(), "app.aab")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	zw := zip.NewWriter(f)
	w, _ := zw.Create("base/manifest/AndroidManifest.xml")
	w.Write(manifest)
	lw, _ := zw.Create("base/lib/arm64-v8a/libok.so")
	lw.Write(buildTestELF(16384, true))
	zw.Close()
	f.Close()

	res, err := ScanArchive(path)
	if err != nil {
		t.Fatalf("ScanArchive: %v", err)
	}
	if res.ArchiveKind != string(KindAAB) {
		t.Errorf("ArchiveKind = %q", res.ArchiveKind)
	}
	if res.PackageName != "com.example.bundle" {
		t.Errorf("PackageName = %q", res.PackageName)
	}
	if res.TargetSDK != 34 {
		t.Errorf("TargetSDK = %d", res.TargetSDK)
	}
	if findByPolicy(res.Findings, "Package visibility") == nil {
		t.Error("QUERY_ALL_PACKAGES from the bundle manifest was not flagged")
	}
	// A valid protobuf manifest should decode cleanly, so the decode-failure
	// coverage finding must be absent. The dependency-coverage finding shares the
	// "Scan coverage" policy and is expected on every artifact scan, so assert on
	// the specific title rather than the category.
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "Could not decode") {
			t.Errorf("a valid protobuf manifest should decode cleanly, got: %s", f.Title)
		}
	}
	if findByTitle(res.Findings, "Dependency-based checks were skipped for this artifact") == nil {
		t.Error("an artifact scan should report the Gradle-only checks it could not run")
	}
	if f := findByPolicy(res.Findings, "16 KB page size"); f != nil {
		t.Errorf("aligned bundle library reported: %s", f.Title)
	}
}

// --- review regressions ------------------------------------------------

// Primitive's oneof field numbers are non-contiguous in Resources.proto
// (float=3, int_decimal=6, int_hex=7, boolean=8). Treating an early number as
// the boolean silently misread every compiled boolean in a bundle, so
// android:debuggable="true" decoded as neither true nor false.
func TestDecodeCompiledPrimitiveUsesRealSchema(t *testing.T) {
	// Item { Primitive prim = 7 { bool boolean_value = 8 } }
	varint := func(num int, v uint64) []byte {
		out := binary.AppendUvarint(nil, uint64(num)<<3|0)
		return binary.AppendUvarint(out, v)
	}
	boolItem := pbField(7, varint(8, 1))
	if got := decodeCompiledItem(boolItem); got != "true" {
		t.Errorf("boolean_value(field 8)=1 decoded as %q, want \"true\"", got)
	}
	falseItem := pbField(7, varint(8, 0))
	if got := decodeCompiledItem(falseItem); got != "false" {
		t.Errorf("boolean_value(field 8)=0 decoded as %q, want \"false\"", got)
	}

	// int_decimal_value = 6 uses zigzag (int32).
	zig := func(num int, v int64) []byte {
		out := binary.AppendUvarint(nil, uint64(num)<<3|0)
		return binary.AppendVarint(out, v)
	}
	intItem := pbField(7, zig(6, 34))
	if got := decodeCompiledItem(intItem); got != "34" {
		t.Errorf("int_decimal_value=34 decoded as %q", got)
	}

	// int_hexadecimal_value = 7 carries the foregroundServiceType bitmask.
	hexItem := pbField(7, varint(7, 1<<3))
	if got := decodeCompiledItem(hexItem); got != "location" {
		t.Errorf("int_hex bitmask decoded as %q, want \"location\"", got)
	}

	// Item { String str = 2 { string value = 1 } }
	strItem := pbField(2, pbString(1, "com.example.Thing"))
	if got := decodeCompiledItem(strItem); got != "com.example.Thing" {
		t.Errorf("String item decoded as %q", got)
	}
}

// A compiled boolean must reach the policy rules, so an AAB with
// debuggable stored as a Primitive is still caught.
func TestAABCompiledBooleanReachesRules(t *testing.T) {
	varint := func(num int, v uint64) []byte {
		out := binary.AppendUvarint(nil, uint64(num)<<3|0)
		return binary.AppendUvarint(out, v)
	}
	// XmlAttribute { name = 2, compiled_item = 6 } with no source text.
	debuggableAttr := append(pbString(2, "debuggable"), pbField(6, pbField(7, varint(8, 1)))...)

	manifest := pbElement("manifest",
		[][]byte{pbAttr("package", "com.example.bundle")},
		[][]byte{
			pbElement("uses-sdk", [][]byte{pbAttr("targetSdkVersion", "36")}, nil),
			pbElement("application", [][]byte{debuggableAttr}, nil),
		})

	m, err := DecodeProtoXML(manifest)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if m.Application == nil || !attrIsTrue(m.Application.Debuggable) {
		t.Fatalf("compiled debuggable boolean not decoded: %+v", m.Application)
	}
}

// The protobuf decoder recurses per nesting level, and a Go stack overflow is
// an unrecoverable process abort. A deeply nested bundle must be rejected, not
// crash the tool.
func TestDecodeProtoXMLRejectsDeepNesting(t *testing.T) {
	// Each level is XmlElement{ name, child = XmlNode{ element = <next> } }.
	// The whole thing is wrapped in one XmlNode at the end, matching what
	// DecodeProtoXML expects at the root.
	elem := pbString(3, "manifest")
	for i := 0; i < maxXMLDepth+50; i++ {
		elem = append(pbString(3, "m"), pbField(5, pbField(1, elem))...)
	}
	_, err := DecodeProtoXML(pbField(1, elem))
	if err == nil {
		t.Fatal("deeply nested manifest should be rejected")
	}
	if !strings.Contains(err.Error(), "nesting") {
		t.Errorf("error should name the nesting limit, got %v", err)
	}
}

// attrCount is a uint16 read straight from the file and need not match the
// bytes present. Uncapped, a 36-byte chunk claiming 65535 attributes forced a
// 2 MB allocation, and a file packed with them burned gigabytes.
func TestDecodeStartTagCapsAttrCountToChunkSize(t *testing.T) {
	var chunk bytes.Buffer
	binary.Write(&chunk, binary.LittleEndian, uint16(chunkXMLStartTag))
	binary.Write(&chunk, binary.LittleEndian, uint16(8))
	binary.Write(&chunk, binary.LittleEndian, uint32(36))
	binary.Write(&chunk, binary.LittleEndian, uint32(1))          // lineNumber
	binary.Write(&chunk, binary.LittleEndian, uint32(0xFFFFFFFF)) // comment
	binary.Write(&chunk, binary.LittleEndian, uint32(0xFFFFFFFF)) // ns
	binary.Write(&chunk, binary.LittleEndian, uint32(0))          // name
	binary.Write(&chunk, binary.LittleEndian, uint16(20))         // attributeStart
	binary.Write(&chunk, binary.LittleEndian, uint16(20))         // attributeSize
	binary.Write(&chunk, binary.LittleEndian, uint16(65535))      // attributeCount, a lie
	binary.Write(&chunk, binary.LittleEndian, uint16(0))
	binary.Write(&chunk, binary.LittleEndian, uint16(0))
	binary.Write(&chunk, binary.LittleEndian, uint16(0))

	_, attrs, err := decodeStartTag(chunk.Bytes(), []string{"tag"}, nil)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(attrs) != 0 {
		t.Errorf("got %d attributes from a chunk with room for none", len(attrs))
	}
	if c := cap(attrs); c > 8 {
		t.Errorf("allocated capacity %d for a chunk with room for 0 attributes", c)
	}
}

// Framework attribute resource IDs are the fallback when aapt2 omits an
// attribute's name from the string pool, which it routinely does. A wrong ID
// fails silently: the attribute never resolves and its rules stop firing.
//
// These values were read back from `aapt2 dump xmltree` on a manifest
// declaring each one, and are identical on android-34, -35 and -36. An earlier
// hand-recalled value for foregroundServiceType (0x01010596) was wrong, which
// would have disabled the CRITICAL foreground-service checks on any manifest
// that relied on the fallback.
func TestFrameworkAttrIDsMatchAapt2(t *testing.T) {
	verified := map[uint32]string{
		0x01010003: "name",
		0x01010006: "permission",
		0x0101000f: "debuggable",
		0x01010010: "exported",
		0x0101020c: "minSdkVersion",
		0x0101028e: "required",
		0x01010270: "targetSdkVersion",
		0x01010280: "allowBackup",
		0x010104ec: "usesCleartextTraffic",
		0x01010599: "foregroundServiceType",
	}
	for id, name := range verified {
		got, ok := frameworkAttrIDs[id]
		if !ok {
			t.Errorf("resource ID %#x (%s) missing from the table", id, name)
			continue
		}
		if got != name {
			t.Errorf("resource ID %#x maps to %q, want %q", id, got, name)
		}
	}
	for id, name := range frameworkAttrIDs {
		if _, ok := verified[id]; !ok {
			t.Errorf("table carries unverified resource ID %#x (%q); confirm it with aapt2 before adding", id, name)
		}
	}
}

// The fallback must actually resolve when the string pool entry is empty,
// which is the only situation the table exists for.
func TestAttrNameFallsBackToResourceMap(t *testing.T) {
	pool := []string{""}
	resMap := []uint32{0x01010599}
	if got := attrName(pool, resMap, 0); got != "foregroundServiceType" {
		t.Errorf("attrName with an empty pool entry = %q, want foregroundServiceType", got)
	}
	// A populated pool entry always wins over the map.
	if got := attrName([]string{"exported"}, []uint32{0x01010599}, 0); got != "exported" {
		t.Errorf("string pool name should take precedence, got %q", got)
	}
}

// --- review regressions: native code coverage ---------------------------

// buildTestAAB writes a bundle with the given zip entries plus a decodable
// protobuf manifest at base/manifest/AndroidManifest.xml.
func buildTestAAB(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.aab")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	mw, err := zw.Create("base/manifest/AndroidManifest.xml")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	manifest := pbElement("manifest",
		[][]byte{pbAttr("package", "com.example.bundle")},
		[][]byte{
			pbElement("uses-sdk", [][]byte{pbAttr("targetSdkVersion", "36")}, nil),
			pbElement("application", nil, nil),
		},
	)
	if _, err := mw.Write(manifest); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return path
}

// An AAB can carry native code in any module, not just base. Scanning only
// base/lib/ let a misaligned feature-module library pass.
func TestScanArchiveScansFeatureModuleLibs(t *testing.T) {
	aab := buildTestAAB(t, map[string][]byte{
		"base/lib/arm64-v8a/libbase.so":      buildTestELF(16384, true),
		"payments/lib/arm64-v8a/libpay.so":   buildTestELF(4096, true),
		"onboarding/lib/arm64-v8a/libonb.so": buildTestELF(16384, true),
	})

	res, err := ScanArchive(aab)
	if err != nil {
		t.Fatalf("ScanArchive: %v", err)
	}
	if res.NativeLibCount != 3 {
		t.Errorf("NativeLibCount = %d, want 3 (base + two feature modules)", res.NativeLibCount)
	}
	f := findByPolicy(res.Findings, "16 KB page size")
	if f == nil {
		t.Fatal("a misaligned feature-module library was not flagged")
	}
	if !strings.Contains(f.Detail, "libpay.so") {
		t.Errorf("finding does not name the offending library: %s", f.Detail)
	}
}

// Play requires a 64-bit library for every 32-bit ABI shipped.
func TestScanArchive64BitParity(t *testing.T) {
	t.Run("32-bit only is flagged", func(t *testing.T) {
		apk := buildTestAPK(t, map[string][]byte{
			"lib/armeabi-v7a/libnative.so": buildTestELF(16384, true),
		})
		res, err := ScanArchive(apk)
		if err != nil {
			t.Fatalf("ScanArchive: %v", err)
		}
		f := findByPolicy(res.Findings, "64-bit requirement")
		if f == nil {
			t.Fatal("armeabi-v7a without arm64-v8a was not flagged")
		}
		if f.Severity != sevCritical {
			t.Errorf("severity = %v, want CRITICAL", f.Severity)
		}
	})

	t.Run("partial library gap is named", func(t *testing.T) {
		apk := buildTestAPK(t, map[string][]byte{
			"lib/armeabi-v7a/libzeta.so": buildTestELF(16384, true),
			"lib/armeabi-v7a/libfoo.so":  buildTestELF(16384, true),
			"lib/armeabi-v7a/libbar.so":  buildTestELF(16384, true),
			"lib/arm64-v8a/libfoo.so":    buildTestELF(16384, true),
		})
		res, err := ScanArchive(apk)
		if err != nil {
			t.Fatalf("ScanArchive: %v", err)
		}
		f := findByPolicy(res.Findings, "64-bit requirement")
		if f == nil {
			t.Fatal("a 32-bit library without a matching 64-bit build was not flagged")
		}
		if f.Severity != sevHigh {
			t.Errorf("severity = %v, want HIGH", f.Severity)
		}
		if !strings.Contains(f.Detail, "libbar.so, libzeta.so") {
			t.Errorf("detail should name missing libraries in sorted order: %s", f.Detail)
		}
		if strings.Contains(f.Detail, "libfoo.so") {
			t.Errorf("detail should not name a library that has a 64-bit build: %s", f.Detail)
		}
	})

	t.Run("whole and partial gaps are reported separately", func(t *testing.T) {
		apk := buildTestAPK(t, map[string][]byte{
			"lib/armeabi-v7a/libfoo.so": buildTestELF(16384, true),
			"lib/armeabi-v7a/libbar.so": buildTestELF(16384, true),
			"lib/arm64-v8a/libfoo.so":   buildTestELF(16384, true),
			"lib/x86/libnative.so":      buildTestELF(16384, true),
		})
		res, err := ScanArchive(apk)
		if err != nil {
			t.Fatalf("ScanArchive: %v", err)
		}
		if got := countByPolicy(res.Findings, "64-bit requirement"); got != 2 {
			t.Fatalf("64-bit findings = %d, want one CRITICAL and one HIGH", got)
		}
		if f := findByPolicy(res.Findings, "64-bit requirement"); f.Severity != sevCritical {
			t.Errorf("first 64-bit finding severity = %v, want CRITICAL", f.Severity)
		}
		if f := findByTitle(res.Findings, "32-bit native libraries are missing 64-bit builds"); f == nil || f.Severity != sevHigh {
			t.Errorf("partial gap finding = %+v, want HIGH", f)
		}
	})

	t.Run("both ABIs present is clean", func(t *testing.T) {
		apk := buildTestAPK(t, map[string][]byte{
			"lib/armeabi-v7a/libnative.so": buildTestELF(16384, true),
			"lib/arm64-v8a/libnative.so":   buildTestELF(16384, true),
		})
		res, err := ScanArchive(apk)
		if err != nil {
			t.Fatalf("ScanArchive: %v", err)
		}
		if f := findByPolicy(res.Findings, "64-bit requirement"); f != nil {
			t.Errorf("a 32/64 pair should not be flagged: %s", f.Title)
		}
	})

	t.Run("64-bit only is clean", func(t *testing.T) {
		apk := buildTestAPK(t, map[string][]byte{
			"lib/arm64-v8a/libnative.so": buildTestELF(16384, true),
		})
		res, err := ScanArchive(apk)
		if err != nil {
			t.Fatalf("ScanArchive: %v", err)
		}
		if f := findByPolicy(res.Findings, "64-bit requirement"); f != nil {
			t.Errorf("a 64-bit-only app should not be flagged: %s", f.Title)
		}
	})

	t.Run("no native code is clean", func(t *testing.T) {
		apk := buildTestAPK(t, nil)
		res, err := ScanArchive(apk)
		if err != nil {
			t.Fatalf("ScanArchive: %v", err)
		}
		if f := findByPolicy(res.Findings, "64-bit requirement"); f != nil {
			t.Errorf("an app without native code should not be flagged: %s", f.Title)
		}
	})

	t.Run("config split is exempt", func(t *testing.T) {
		apk := buildTestAPKWithManifest(t, buildTestManifestWithSplit("config.armeabi_v7a"), map[string][]byte{
			"lib/armeabi-v7a/libnative.so": buildTestELF(16384, true),
		})
		res, err := ScanArchive(apk)
		if err != nil {
			t.Fatalf("ScanArchive: %v", err)
		}
		if f := findByPolicy(res.Findings, "64-bit requirement"); f != nil {
			t.Errorf("a config split should not be checked in isolation: %s", f.Title)
		}
	})

	t.Run("x86 without x86_64 is flagged", func(t *testing.T) {
		apk := buildTestAPK(t, map[string][]byte{
			"lib/x86/libnative.so": buildTestELF(16384, true),
		})
		res, err := ScanArchive(apk)
		if err != nil {
			t.Fatalf("ScanArchive: %v", err)
		}
		if findByPolicy(res.Findings, "64-bit requirement") == nil {
			t.Error("x86 without x86_64 was not flagged")
		}
	})
}

// An artifact scan cannot read the Gradle model, so it must say which checks it
// skipped rather than presenting a partial scan as a complete one.
func TestScanArchiveReportsGradleOnlyCoverageGap(t *testing.T) {
	apk := buildTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libnative.so": buildTestELF(16384, true),
	})
	res, err := ScanArchive(apk)
	if err != nil {
		t.Fatalf("ScanArchive: %v", err)
	}
	f := findByTitle(res.Findings, "Dependency-based checks were skipped for this artifact")
	if f == nil {
		t.Fatal("artifact scan did not report its coverage gap")
	}
	for _, want := range []string{"Play Billing", "ads-SDK", "auth-SDK"} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("coverage finding does not mention %q: %s", want, f.Detail)
		}
	}
}

// --- code review regressions --------------------------------------------

// buildTestAABWithFeature writes a bundle whose protobuf manifest declares a
// uses-feature and a targetSdk, which is what a real Wear or TV bundle looks
// like after the merge.
func buildTestAABWithFeature(t *testing.T, feature, required string, targetSDK string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.aab")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	featureAttrs := [][]byte{pbAttr("name", feature)}
	if required != "" {
		featureAttrs = append(featureAttrs, pbAttr("required", required))
	}

	zw := zip.NewWriter(f)
	mw, err := zw.Create("base/manifest/AndroidManifest.xml")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	manifest := pbElement("manifest",
		[][]byte{pbAttr("package", "com.example.bundle")},
		[][]byte{
			pbElement("uses-sdk", [][]byte{pbAttr("targetSdkVersion", targetSDK)}, nil),
			pbElement("uses-feature", featureAttrs, nil),
			pbElement("application", nil, nil),
		},
	)
	if _, err := mw.Write(manifest); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return path
}

// The form-factor rule was inert on the archive path: applyElement had no
// uses-feature case, so a compiled manifest never populated UsesFeatures and a
// Wear bundle still got the phone schedule's CRITICAL.
func TestScanArchiveDecodesUsesFeatureForFormFactor(t *testing.T) {
	aab := buildTestAABWithFeature(t, "android.hardware.type.watch", "", "33")
	res, err := ScanArchive(aab)
	if err != nil {
		t.Fatalf("ScanArchive: %v", err)
	}
	f := findByPolicy(res.Findings, "Target API level")
	if f == nil {
		t.Fatal("no target API finding")
	}
	if f.Severity != sevWarn {
		t.Errorf("severity = %v, want WARN — a Wear bundle must not be gated on the phone schedule (got %q)", f.Severity, f.Title)
	}
	if !strings.Contains(f.Title, string(FormFactorWear)) {
		t.Errorf("finding does not name the form factor: %s", f.Title)
	}
}

// A phone app that also ships to TV declares leanback with required="false".
// Treating that as a TV app would downgrade a genuine phone CRITICAL.
func TestScanArchiveIgnoresUnrequiredFormFactorFeature(t *testing.T) {
	aab := buildTestAABWithFeature(t, "android.software.leanback", "false", "33")
	res, err := ScanArchive(aab)
	if err != nil {
		t.Fatalf("ScanArchive: %v", err)
	}
	f := findByPolicy(res.Findings, "Target API level")
	if f == nil {
		t.Fatal("no target API finding")
	}
	if f.Severity != sevCritical {
		t.Errorf("severity = %v, want CRITICAL — leanback required=false is a phone app, not a TV app", f.Severity)
	}
}

// The Gradle coverage gap exists whether or not the manifest decoded.
func TestScanArchiveReportsCoverageGapWhenManifestUndecodable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.aab")
	f, _ := os.Create(path)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("base/manifest/AndroidManifest.xml")
	w.Write([]byte{0x00})
	zw.Close()
	f.Close()

	res, err := ScanArchive(path)
	if err != nil {
		t.Fatalf("ScanArchive: %v", err)
	}
	if findByTitle(res.Findings, "Dependency-based checks were skipped for this artifact") == nil {
		t.Error("the Gradle-only gap must be reported even when the manifest cannot be decoded")
	}
}

// The APK path decodes uses-feature from binary XML, where android:required is
// a typed boolean rather than the literal string "false". Both compiled forms
// must reach the form-factor logic identically.
func TestBinaryXMLDecodesUsesFeatureRequired(t *testing.T) {
	build := func(requiredData uint32, withRequired bool) *Manifest {
		t.Helper()
		b := &axmlBuilder{}
		nameAttr := b.attrRef(0x01010003)
		requiredAttr := b.attrRef(0x0101028e) // android:required
		pkgIdx := b.str("com.example.tv")
		featIdx := b.str("android.software.leanback")
		packageAttr := b.str("package")

		b.startTag("manifest", []buildAttr{
			{nameIdx: packageAttr, dataType: typeString, data: pkgIdx, rawIdx: pkgIdx},
		})
		attrs := []buildAttr{
			{nameIdx: nameAttr, dataType: typeString, data: featIdx, rawIdx: featIdx},
		}
		if withRequired {
			attrs = append(attrs, buildAttr{
				nameIdx: requiredAttr, dataType: typeIntBoolean, data: requiredData, rawIdx: 0xFFFFFFFF,
			})
		}
		b.startTag("uses-feature", attrs)
		b.endTag("uses-feature")
		b.startTag("application", nil)
		b.endTag("application")
		b.endTag("manifest")

		m, err := DecodeBinaryXML(b.build())
		if err != nil {
			t.Fatalf("DecodeBinaryXML: %v", err)
		}
		return m
	}

	t.Run("required=false is not a TV app", func(t *testing.T) {
		m := build(0, true)
		if len(m.UsesFeatures) != 1 {
			t.Fatalf("UsesFeatures = %d, want 1 (binary XML must decode uses-feature)", len(m.UsesFeatures))
		}
		if got := m.FormFactor(); got != FormFactorPhone {
			t.Errorf("FormFactor = %q, want phone — leanback required=false is a phone app", got)
		}
	})

	t.Run("required=true is a TV app", func(t *testing.T) {
		if got := build(0xFFFFFFFF, true).FormFactor(); got != FormFactorTV {
			t.Errorf("FormFactor = %q, want %q", got, FormFactorTV)
		}
	})

	t.Run("absent required defaults to true", func(t *testing.T) {
		if got := build(0, false).FormFactor(); got != FormFactorTV {
			t.Errorf("FormFactor = %q, want %q — required defaults to true when absent", got, FormFactorTV)
		}
	})
}
