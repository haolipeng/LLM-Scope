package analyzer

import "encoding/hex"

// detectDataType reports whether data looks like text or binary.
func detectDataType(data string) string {
	for _, r := range data {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return "binary"
		}
	}
	return "text"
}

// dataToString normalizes text or binary data for log output.
func dataToString(data string) string {
	if detectDataType(data) == "text" {
		return data
	}
	return "HEX:" + hex.EncodeToString([]byte(data))
}
