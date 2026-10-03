package obfs

import "encoding/binary"

// findSNI locates the host_name value inside a TLS ClientHello and returns the
// offsets of its first and last bytes within b.
//
// This exists because of a mistake that is easy to make and easy to miss.
// "Split the first write at a fixed offset" sounds like it defeats an SNI
// matcher, and it does stop the *first* segment from containing the hostname —
// but if the offset lands before the SNI, the hostname ends up whole and
// contiguous in the second segment, and a matcher that inspects each segment
// independently still matches it. Fragmentation only works if the split lands
// *inside* the name, which means knowing where the name is.
//
// The parse is strictly bounds checked at every step and allocates nothing. It
// deliberately understands only as much TLS as it needs: enough to walk to the
// server_name extension and no further. Anything it does not recognise, or any
// length that does not fit, returns ok=false and the caller falls back to a
// fixed offset rather than failing the connection — an obfuscation layer that
// breaks traffic it cannot classify is worse than one that passes it through.
//
// TLS 1.3 encrypted ClientHello (ECH) makes this moot where it is deployed,
// because there is no plaintext SNI left to find. The fallback path is what
// runs then, which is correct: with no cleartext name there is nothing for a
// name matcher to match.
func findSNI(b []byte) (start, end int, ok bool) {
	// TLS record header: content type, version, length.
	const recordHeaderLen = 5
	if len(b) < recordHeaderLen {
		return 0, 0, false
	}
	if b[0] != 0x16 { // handshake
		return 0, 0, false
	}
	// The record length is not trusted to match the buffer: a ClientHello may
	// legitimately be split across records by the sender, and we only parse
	// what is actually present.
	body := b[recordHeaderLen:]

	// Handshake header: type, 3-byte length.
	const handshakeHeaderLen = 4
	if len(body) < handshakeHeaderLen {
		return 0, 0, false
	}
	if body[0] != 0x01 { // client_hello
		return 0, 0, false
	}
	hello := body[handshakeHeaderLen:]
	base := recordHeaderLen + handshakeHeaderLen

	// client_version (2) + random (32)
	off := 2 + 32
	if len(hello) < off+1 {
		return 0, 0, false
	}

	// session_id
	sessionIDLen := int(hello[off])
	off++
	if len(hello) < off+sessionIDLen+2 {
		return 0, 0, false
	}
	off += sessionIDLen

	// cipher_suites
	cipherLen := int(binary.BigEndian.Uint16(hello[off : off+2]))
	off += 2
	if len(hello) < off+cipherLen+1 {
		return 0, 0, false
	}
	off += cipherLen

	// compression_methods
	compLen := int(hello[off])
	off++
	if len(hello) < off+compLen+2 {
		return 0, 0, false
	}
	off += compLen

	// extensions
	extensionsLen := int(binary.BigEndian.Uint16(hello[off : off+2]))
	off += 2
	if extensionsLen > len(hello)-off {
		// Trust the buffer over the declared length; see the note above about
		// records being split by the sender.
		extensionsLen = len(hello) - off
	}
	extensions := hello[off : off+extensionsLen]
	extBase := base + off

	for i := 0; i+4 <= len(extensions); {
		extType := binary.BigEndian.Uint16(extensions[i : i+2])
		extLen := int(binary.BigEndian.Uint16(extensions[i+2 : i+4]))
		dataStart := i + 4
		if dataStart+extLen > len(extensions) {
			return 0, 0, false
		}
		if extType != 0x0000 { // server_name
			i = dataStart + extLen
			continue
		}

		// server_name extension data: 2-byte list length, then entries of
		// [name_type (1)][length (2)][value].
		data := extensions[dataStart : dataStart+extLen]
		if len(data) < 2 {
			return 0, 0, false
		}
		listLen := int(binary.BigEndian.Uint16(data[0:2]))
		if listLen > len(data)-2 {
			return 0, 0, false
		}
		list := data[2 : 2+listLen]
		for j := 0; j+3 <= len(list); {
			nameType := list[j]
			nameLen := int(binary.BigEndian.Uint16(list[j+1 : j+3]))
			valueStart := j + 3
			if valueStart+nameLen > len(list) {
				return 0, 0, false
			}
			if nameType == 0 && nameLen > 0 { // host_name
				absStart := extBase + dataStart + 2 + valueStart
				return absStart, absStart + nameLen - 1, true
			}
			j = valueStart + nameLen
		}
		return 0, 0, false
	}
	return 0, 0, false
}
