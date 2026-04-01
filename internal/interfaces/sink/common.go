package sink

import "encoding/hex"

func detectDataType(data string) string {
	for _, r := range data {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return "binary"
		}
	}
	return "text"
}

func dataToString(data string) string {
	if detectDataType(data) == "text" {
		return data
	}
	return "HEX:" + hex.EncodeToString([]byte(data))
}
