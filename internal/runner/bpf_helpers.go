package runner

import (
	"fmt"
	"strings"
)

// cStringToGo converts a C-style null-terminated int8 array to a Go string.
func cStringToGo(b []int8) string {
	var sb strings.Builder
	for _, c := range b {
		if c == 0 {
			break
		}
		sb.WriteByte(byte(c))
	}
	return sb.String()
}

// cBytesToGo converts a C-style null-terminated uint8 array to a Go string.
func cBytesToGo(b []uint8) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// ipv4ToString converts a network-byte-order uint32 IPv4 address to dotted-decimal notation.
func ipv4ToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

// ipv6ToString converts a 16-byte IPv6 address to colon-separated hex notation.
func ipv6ToString(ip [16]uint8) string {
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
		ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
}
