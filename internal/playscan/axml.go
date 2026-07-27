package playscan

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Android binary XML (AXML) chunk types. A compiled AndroidManifest.xml inside
// an APK is a sequence of these chunks rather than text, so reading the merged
// manifest that actually ships means decoding the format directly.
const (
	chunkStringPool  = 0x0001
	chunkXMLDocument = 0x0003
	chunkXMLResource = 0x0180
	chunkXMLStartTag = 0x0102
	chunkXMLEndTag   = 0x0103
)

// Typed attribute value formats, from ResourceTypes.h.
const (
	typeReference   = 0x01
	typeString      = 0x03
	typeIntDec      = 0x10
	typeIntHex      = 0x11
	typeIntBoolean  = 0x12
	typeNull        = 0x00
	attrRecordBytes = 20
)

// stringPoolUTF8Flag marks a pool whose strings are UTF-8 rather than UTF-16.
const stringPoolUTF8Flag = 1 << 8

// axmlAttr is one decoded attribute of an element.
type axmlAttr struct {
	Name  string
	Value string
}

// DecodeBinaryXML decodes a compiled AndroidManifest.xml into the same Manifest
// the source-tree parser produces, so every existing policy rule runs unchanged
// against the merged manifest.
func DecodeBinaryXML(data []byte) (*Manifest, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("binary XML too short (%d bytes)", len(data))
	}
	if t := binary.LittleEndian.Uint16(data[0:2]); t != chunkXMLDocument {
		return nil, fmt.Errorf("not Android binary XML (chunk type 0x%04x)", t)
	}

	var pool []string
	var resMap []uint32
	// Element stack, used to attach parsed children to the right parent.
	m := &Manifest{}
	var path []string
	var currentActivity *Component
	var currentComponentKind string

	offset := int(binary.LittleEndian.Uint16(data[2:4])) // header size
	for offset+8 <= len(data) {
		chunkType := binary.LittleEndian.Uint16(data[offset : offset+2])
		chunkSize := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		if chunkSize < 8 || offset+chunkSize > len(data) {
			break
		}
		chunk := data[offset : offset+chunkSize]

		switch chunkType {
		case chunkStringPool:
			p, err := decodeStringPool(chunk)
			if err != nil {
				return nil, err
			}
			pool = p

		case chunkXMLStartTag:
			name, attrs, err := decodeStartTag(chunk, pool, resMap)
			if err != nil {
				return nil, err
			}
			path = append(path, name)
			applyElement(m, name, attrs, path, &currentActivity, &currentComponentKind)

		case chunkXMLEndTag:
			if len(path) > 0 {
				closing := path[len(path)-1]
				path = path[:len(path)-1]
				if closing == currentComponentKind {
					currentActivity, currentComponentKind = nil, ""
				}
			}

		case chunkXMLResource:
			resMap = decodeResourceMap(chunk)
		}

		offset += chunkSize
	}

	if m.Application == nil && len(m.Permissions) == 0 {
		return nil, fmt.Errorf("no manifest content decoded")
	}
	return m, nil
}

// applyElement folds one decoded element into the Manifest being built.
//
// Nesting matters: an <intent-filter> belongs to whichever component is open,
// and only components directly inside <application> are the app's own.
func applyElement(m *Manifest, name string, attrs []axmlAttr, path []string, current **Component, currentKind *string) {
	get := func(key string) string {
		for _, a := range attrs {
			if a.Name == key {
				return a.Value
			}
		}
		return ""
	}

	switch name {
	case "manifest":
		m.Package = get("package")

	case "uses-permission":
		m.Permissions = append(m.Permissions, UsesPermission{Name: get("name")})
	case "uses-permission-sdk-23":
		m.PermissionsSDK23 = append(m.PermissionsSDK23, UsesPermission{Name: get("name")})

	case "uses-sdk":
		m.UsesSDK = &UsesSDK{
			MinSDKVersion:    get("minSdkVersion"),
			TargetSDKVersion: get("targetSdkVersion"),
		}

	case "application":
		m.Application = &Application{
			Name:                 get("name"),
			Debuggable:           get("debuggable"),
			AllowBackup:          get("allowBackup"),
			UsesCleartextTraffic: get("usesCleartextTraffic"),
			NetworkSecurityConf:  get("networkSecurityConfig"),
		}

	case "activity", "activity-alias", "service", "receiver", "provider":
		if m.Application == nil {
			return
		}
		comp := Component{
			Name:              get("name"),
			Exported:          get("exported"),
			Permission:        get("permission"),
			ForegroundSvcType: get("foregroundServiceType"),
		}
		switch name {
		case "activity":
			m.Application.Activities = append(m.Application.Activities, comp)
			*current = &m.Application.Activities[len(m.Application.Activities)-1]
		case "activity-alias":
			m.Application.ActivityAliases = append(m.Application.ActivityAliases, comp)
			*current = &m.Application.ActivityAliases[len(m.Application.ActivityAliases)-1]
		case "service":
			m.Application.Services = append(m.Application.Services, comp)
			*current = &m.Application.Services[len(m.Application.Services)-1]
		case "receiver":
			m.Application.Receivers = append(m.Application.Receivers, comp)
			*current = &m.Application.Receivers[len(m.Application.Receivers)-1]
		case "provider":
			m.Application.Providers = append(m.Application.Providers, comp)
			*current = &m.Application.Providers[len(m.Application.Providers)-1]
		}
		*currentKind = name

	case "intent-filter":
		if *current != nil {
			(*current).IntentFilters = append((*current).IntentFilters, IntentFilter{})
		}

	case "action", "category":
		if *current == nil || len((*current).IntentFilters) == 0 {
			return
		}
		f := &(*current).IntentFilters[len((*current).IntentFilters)-1]
		entry := struct {
			Name string `xml:"name,attr"`
		}{Name: get("name")}
		if name == "action" {
			f.Actions = append(f.Actions, entry)
		} else {
			f.Categories = append(f.Categories, entry)
		}
	}
}

// decodeStartTag reads one RES_XML_START_ELEMENT chunk.
//
// Layout: ResXMLTree_node is header(8) + lineNumber(4) + comment(4) = 16 bytes,
// followed by ResXMLTree_attrExt. attributeStart is an offset from the start of
// attrExt, NOT from the start of the chunk, so it has to be rebased by 16.
func decodeStartTag(chunk []byte, pool []string, resMap []uint32) (string, []axmlAttr, error) {
	const attrExtOffset = 16
	if len(chunk) < 36 {
		return "", nil, fmt.Errorf("start tag chunk too short")
	}
	nameIdx := binary.LittleEndian.Uint32(chunk[20:24])
	attrStart := int(binary.LittleEndian.Uint16(chunk[24:26]))
	attrSize := int(binary.LittleEndian.Uint16(chunk[26:28]))
	attrCount := int(binary.LittleEndian.Uint16(chunk[28:30]))

	// The record stride is declared per file rather than fixed.
	if attrSize <= 0 {
		attrSize = attrRecordBytes
	}

	name := poolAt(pool, nameIdx)

	attrs := make([]axmlAttr, 0, attrCount)
	for i := 0; i < attrCount; i++ {
		off := attrExtOffset + attrStart + i*attrSize
		if off < 0 || off+attrRecordBytes > len(chunk) {
			break
		}
		rec := chunk[off : off+attrRecordBytes]
		attrNameIdx := binary.LittleEndian.Uint32(rec[4:8])
		rawValueIdx := binary.LittleEndian.Uint32(rec[8:12])
		dataType := rec[15]
		data := binary.LittleEndian.Uint32(rec[16:20])

		attrs = append(attrs, axmlAttr{
			Name:  attrName(pool, resMap, attrNameIdx),
			Value: attrValue(pool, rawValueIdx, dataType, data),
		})
	}
	return name, attrs, nil
}

// frameworkAttrIDs maps android framework attribute resource IDs to their
// names. aapt2 commonly emits an empty string-pool entry for a framework
// attribute and identifies it only by resource ID, so without this table every
// android:* attribute in a compiled manifest reads as unnamed.
var frameworkAttrIDs = map[uint32]string{
	0x01010003: "name",
	0x01010006: "permission",
	0x0101000f: "debuggable",
	0x01010010: "exported",
	0x0101020c: "minSdkVersion",
	0x01010270: "targetSdkVersion",
	0x01010280: "allowBackup",
	0x010104ec: "usesCleartextTraffic",
	0x0101048f: "networkSecurityConfig",
	0x01010507: "networkSecurityConfig",
	0x01010596: "foregroundServiceType",
}

// attrName resolves an attribute's name, preferring the string pool and
// falling back to the resource ID map when the pool entry is empty.
func attrName(pool []string, resMap []uint32, idx uint32) string {
	if s := poolAt(pool, idx); s != "" {
		return s
	}
	if int(idx) < len(resMap) {
		if name, ok := frameworkAttrIDs[resMap[idx]]; ok {
			return name
		}
	}
	return ""
}

// decodeResourceMap reads RES_XML_RESOURCE_MAP, an array of resource IDs
// indexed in parallel with the string pool.
func decodeResourceMap(chunk []byte) []uint32 {
	headerSize := int(binary.LittleEndian.Uint16(chunk[2:4]))
	if headerSize < 8 || headerSize > len(chunk) {
		headerSize = 8
	}
	body := chunk[headerSize:]
	ids := make([]uint32, 0, len(body)/4)
	for i := 0; i+4 <= len(body); i += 4 {
		ids = append(ids, binary.LittleEndian.Uint32(body[i:i+4]))
	}
	return ids
}

// attrValue renders a typed attribute value as the string the rules expect.
func attrValue(pool []string, rawIdx uint32, dataType byte, data uint32) string {
	// A present raw value is the literal source text and is always preferred.
	if rawIdx != 0xFFFFFFFF {
		if s := poolAt(pool, rawIdx); s != "" {
			return s
		}
	}
	switch dataType {
	case typeString:
		return poolAt(pool, data)
	case typeIntBoolean:
		if data != 0 {
			return "true"
		}
		return "false"
	case typeIntDec:
		return strconv.FormatUint(uint64(data), 10)
	case typeIntHex:
		// foregroundServiceType is a flags bitmask in compiled form; render it
		// back to the pipe-separated names the source manifest would carry so
		// the policy rules do not need a second code path.
		if names := foregroundServiceTypeNames(data); names != "" {
			return names
		}
		return "0x" + strconv.FormatUint(uint64(data), 16)
	case typeReference:
		if data == 0 {
			return ""
		}
		return "@" + strconv.FormatUint(uint64(data), 16)
	case typeNull:
		return ""
	}
	return ""
}

// foregroundServiceTypeBits maps the compiled bitmask back to the manifest
// attribute names, from android.content.pm.ServiceInfo.
var foregroundServiceTypeBits = []struct {
	bit  uint32
	name string
}{
	{1 << 0, "dataSync"},
	{1 << 1, "mediaPlayback"},
	{1 << 2, "phoneCall"},
	{1 << 3, "location"},
	{1 << 4, "connectedDevice"},
	{1 << 5, "mediaProjection"},
	{1 << 6, "camera"},
	{1 << 7, "microphone"},
	{1 << 8, "health"},
	{1 << 9, "remoteMessaging"},
	{1 << 10, "systemExempted"},
	{1 << 11, "shortService"},
	{1 << 12, "fileManagement"},
	{1 << 13, "mediaProcessing"},
	{1 << 30, "specialUse"},
}

func foregroundServiceTypeNames(mask uint32) string {
	var names []string
	for _, b := range foregroundServiceTypeBits {
		if mask&b.bit != 0 {
			names = append(names, b.name)
		}
	}
	return strings.Join(names, "|")
}

func poolAt(pool []string, idx uint32) string {
	if idx == 0xFFFFFFFF || int(idx) >= len(pool) {
		return ""
	}
	return pool[idx]
}

// decodeStringPool reads a RES_STRING_POOL chunk in either encoding.
func decodeStringPool(chunk []byte) ([]string, error) {
	if len(chunk) < 28 {
		return nil, fmt.Errorf("string pool chunk too short")
	}
	count := int(binary.LittleEndian.Uint32(chunk[8:12]))
	flags := binary.LittleEndian.Uint32(chunk[16:20])
	stringsStart := int(binary.LittleEndian.Uint32(chunk[20:24]))
	utf8 := flags&stringPoolUTF8Flag != 0

	if count < 0 || 28+count*4 > len(chunk) {
		return nil, fmt.Errorf("string pool count %d out of range", count)
	}

	out := make([]string, count)
	for i := 0; i < count; i++ {
		offAt := 28 + i*4
		rel := int(binary.LittleEndian.Uint32(chunk[offAt : offAt+4]))
		pos := stringsStart + rel
		if pos < 0 || pos >= len(chunk) {
			continue
		}
		if utf8 {
			out[i] = decodeUTF8String(chunk, pos)
		} else {
			out[i] = decodeUTF16String(chunk, pos)
		}
	}
	return out, nil
}

// decodeUTF8String reads a length-prefixed UTF-8 string. Both the UTF-16 length
// and the byte length are stored, each as one or two bytes depending on a high
// bit, so both prefixes have to be stepped over to reach the bytes.
func decodeUTF8String(b []byte, pos int) string {
	if pos >= len(b) {
		return ""
	}
	_, pos = readUTF8Len(b, pos)
	byteLen, pos := readUTF8Len(b, pos)
	if pos+byteLen > len(b) || byteLen < 0 {
		return ""
	}
	return string(b[pos : pos+byteLen])
}

func readUTF8Len(b []byte, pos int) (int, int) {
	if pos >= len(b) {
		return 0, pos
	}
	n := int(b[pos])
	pos++
	if n&0x80 != 0 {
		if pos >= len(b) {
			return 0, pos
		}
		n = ((n & 0x7F) << 8) | int(b[pos])
		pos++
	}
	return n, pos
}

// decodeUTF16String reads a length-prefixed UTF-16LE string.
func decodeUTF16String(b []byte, pos int) string {
	if pos+2 > len(b) {
		return ""
	}
	n := int(binary.LittleEndian.Uint16(b[pos : pos+2]))
	pos += 2
	if n&0x8000 != 0 {
		if pos+2 > len(b) {
			return ""
		}
		n = ((n & 0x7FFF) << 16) | int(binary.LittleEndian.Uint16(b[pos:pos+2]))
		pos += 2
	}
	if pos+n*2 > len(b) || n < 0 {
		return ""
	}
	units := make([]uint16, n)
	for i := 0; i < n; i++ {
		units[i] = binary.LittleEndian.Uint16(b[pos+i*2 : pos+i*2+2])
	}
	return string(utf16.Decode(units))
}
