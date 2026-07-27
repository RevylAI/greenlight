package playscan

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
)

// An AAB stores its manifest as a protobuf-encoded XmlNode (aapt2's
// Resources.proto) rather than the binary XML an APK uses. Only a handful of
// fields are needed, and the protobuf wire format is self-describing enough to
// walk directly, which avoids taking a protobuf dependency for one file.
//
// The relevant subset of the schema:
//
//	XmlNode      { XmlElement element = 1; string text = 2 }
//	XmlElement   { XmlNamespace namespace_declaration = 1; string namespace_uri = 2;
//	               string name = 3; XmlAttribute attribute = 4; XmlNode child = 5 }
//	XmlAttribute { string namespace_uri = 1; string name = 2; string value = 3;
//	               Source source = 4; uint32 resource_id = 5; Item compiled_item = 6 }
//	Item         { String str = 2; Primitive prim = 7 }  // used when value is empty
const (
	fieldElement      = 1
	fieldElemName     = 3
	fieldElemAttr     = 4
	fieldElemChild    = 5
	fieldAttrName     = 2
	fieldAttrValue    = 3
	fieldAttrCompiled = 6
)

// Protobuf wire types.
const (
	wireVarint = 0
	wireI64    = 1
	wireBytes  = 2
	wireI32    = 5
)

// DecodeProtoXML decodes an AAB's protobuf AndroidManifest.xml into the same
// Manifest the other parsers produce.
func DecodeProtoXML(data []byte) (*Manifest, error) {
	root, err := findElement(data)
	if err != nil {
		return nil, err
	}

	m := &Manifest{}
	var current *Component
	var currentKind string
	if err := walkProtoElement(root, m, &current, &currentKind, 0); err != nil {
		return nil, err
	}
	if m.Application == nil && len(m.Permissions) == 0 {
		return nil, fmt.Errorf("no manifest content decoded")
	}
	return m, nil
}

// findElement pulls the XmlElement out of the top-level XmlNode wrapper.
func findElement(node []byte) ([]byte, error) {
	var elem []byte
	err := eachField(node, func(num int, wire int, val []byte) error {
		if num == fieldElement && wire == wireBytes {
			elem = val
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if elem == nil {
		return nil, fmt.Errorf("no XmlElement in manifest root")
	}
	return elem, nil
}

// walkProtoElement decodes one element and recurses into its children.
func walkProtoElement(elem []byte, m *Manifest, current **Component, currentKind *string, depth int) error {
	if depth > maxXMLDepth {
		return fmt.Errorf("manifest nesting exceeds %d levels", maxXMLDepth)
	}
	var name string
	var attrs []axmlAttr
	var children [][]byte

	err := eachField(elem, func(num, wire int, val []byte) error {
		switch {
		case num == fieldElemName && wire == wireBytes:
			name = string(val)
		case num == fieldElemAttr && wire == wireBytes:
			a, err := decodeProtoAttr(val)
			if err != nil {
				return err
			}
			attrs = append(attrs, a)
		case num == fieldElemChild && wire == wireBytes:
			children = append(children, val)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if name == "" {
		return nil
	}

	applyElement(m, name, attrs, nil, current, currentKind)

	for _, childNode := range children {
		childElem, err := findElement(childNode)
		if err != nil {
			// A text node has no element; that is normal, not an error.
			continue
		}
		if err := walkProtoElement(childElem, m, current, currentKind, depth+1); err != nil {
			return err
		}
	}

	// Closing this element ends whichever component it opened.
	if name == *currentKind {
		*current, *currentKind = nil, ""
	}
	return nil
}

// decodeProtoAttr reads one XmlAttribute, falling back to the compiled value
// when the source text was not retained (booleans and ints commonly are not).
func decodeProtoAttr(b []byte) (axmlAttr, error) {
	var a axmlAttr
	var compiled []byte
	err := eachField(b, func(num, wire int, val []byte) error {
		switch {
		case num == fieldAttrName && wire == wireBytes:
			a.Name = string(val)
		case num == fieldAttrValue && wire == wireBytes:
			a.Value = string(val)
		case num == fieldAttrCompiled && wire == wireBytes:
			compiled = val
		}
		return nil
	})
	if err != nil {
		return a, err
	}
	if a.Value == "" && compiled != nil {
		a.Value = decodeCompiledItem(compiled)
	}
	return a, nil
}

// Item and Primitive field numbers, from aapt2's Resources.proto.
//
// These are not guessable — Primitive's oneof is deliberately non-contiguous
// (float is 3, int_decimal is 6, boolean is 8), so treating an early field
// number as the boolean silently misreads every compiled boolean in a bundle.
const (
	itemFieldStr  = 2
	itemFieldPrim = 7

	primFloat      = 3
	primIntDecimal = 6
	primIntHex     = 7
	primBoolean    = 8

	stringFieldValue = 1
)

// maxXMLDepth bounds manifest nesting. The decoder walks the tree recursively,
// and a Go stack overflow is a process abort that recover() cannot catch, so an
// attacker-supplied bundle must not be able to drive the depth. Android's own
// XML parser caps nesting at 100; a real manifest is under 10 levels deep.
const maxXMLDepth = 100

// decodeCompiledItem extracts a scalar from a compiled Item, which is how an
// AAB stores an attribute value whose source text was not retained.
func decodeCompiledItem(b []byte) string {
	var out string
	_ = eachField(b, func(num, wire int, val []byte) error {
		if wire != wireBytes || out != "" {
			return nil
		}
		switch num {
		case itemFieldStr:
			// String { string value = 1 }
			_ = eachField(val, func(snum, swire int, sval []byte) error {
				if snum == stringFieldValue && swire == wireBytes {
					out = string(sval)
				}
				return nil
			})
		case itemFieldPrim:
			out = decodePrimitive(val)
		}
		return nil
	})
	return out
}

// decodePrimitive renders a Primitive as the string the policy rules expect.
func decodePrimitive(b []byte) string {
	var out string
	_ = eachField(b, func(num, wire int, val []byte) error {
		if out != "" {
			return nil
		}
		switch num {
		case primBoolean:
			if wire != wireVarint {
				return nil
			}
			v, _ := binary.Uvarint(val)
			if v != 0 {
				out = "true"
			} else {
				out = "false"
			}
		case primIntDecimal:
			if wire != wireVarint {
				return nil
			}
			v, n := binary.Varint(val)
			if n > 0 {
				out = strconv.FormatInt(v, 10)
			}
		case primIntHex:
			if wire != wireVarint {
				return nil
			}
			v, _ := binary.Uvarint(val)
			// foregroundServiceType arrives here as a flags bitmask; render it
			// back to the names the source manifest would carry.
			if names := foregroundServiceTypeNames(uint32(v)); names != "" {
				out = names
			} else {
				out = strconv.FormatUint(v, 10)
			}
		case primFloat:
			if wire != wireI32 || len(val) != 4 {
				return nil
			}
			out = strconv.FormatFloat(float64(math.Float32frombits(binary.LittleEndian.Uint32(val))), 'g', -1, 32)
		}
		return nil
	})
	return out
}

// eachField walks a protobuf message, invoking fn per field. Varint payloads
// are handed back as their raw encoding so the caller can decode them.
func eachField(b []byte, fn func(num, wire int, val []byte) error) error {
	for i := 0; i < len(b); {
		key, n := binary.Uvarint(b[i:])
		if n <= 0 {
			return fmt.Errorf("malformed protobuf field key")
		}
		i += n
		num := int(key >> 3)
		wire := int(key & 0x7)

		switch wire {
		case wireVarint:
			_, vn := binary.Uvarint(b[i:])
			if vn <= 0 {
				return fmt.Errorf("malformed varint")
			}
			if err := fn(num, wire, b[i:i+vn]); err != nil {
				return err
			}
			i += vn
		case wireI64:
			if i+8 > len(b) {
				return fmt.Errorf("truncated 64-bit field")
			}
			if err := fn(num, wire, b[i:i+8]); err != nil {
				return err
			}
			i += 8
		case wireBytes:
			l, ln := binary.Uvarint(b[i:])
			if ln <= 0 {
				return fmt.Errorf("malformed length prefix")
			}
			i += ln
			if l > uint64(len(b)-i) {
				return fmt.Errorf("length-delimited field overruns message")
			}
			if err := fn(num, wire, b[i:i+int(l)]); err != nil {
				return err
			}
			i += int(l)
		case wireI32:
			if i+4 > len(b) {
				return fmt.Errorf("truncated 32-bit field")
			}
			if err := fn(num, wire, b[i:i+4]); err != nil {
				return err
			}
			i += 4
		default:
			return fmt.Errorf("unsupported protobuf wire type %d", wire)
		}
	}
	return nil
}
