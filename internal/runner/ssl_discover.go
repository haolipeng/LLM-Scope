package runner

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// commonSSLPaths lists common locations for SSL libraries.
var commonSSLPaths = []string{
	"/usr/lib/x86_64-linux-gnu",
	"/usr/lib64",
	"/usr/lib",
	"/lib/x86_64-linux-gnu",
	"/lib64",
	"/lib",
	"/usr/local/lib",
	"/usr/local/lib64",
}

// findLibraryPath discovers the full path of a shared library using ldconfig.
func findLibraryPath(libname string) string {
	// Try ldconfig first
	if path := findLibraryViaLdconfig(libname); path != "" {
		return path
	}
	// Fallback: search common paths
	return findLibraryInCommonPaths(libname)
}

func findLibraryViaLdconfig(libname string) string {
	cmd := exec.Command("ldconfig", "-p")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, libname) {
			continue
		}
		// Format: "	libssl.so.3 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libssl.so.3"
		idx := strings.Index(line, "=>")
		if idx < 0 {
			continue
		}
		path := strings.TrimSpace(line[idx+2:])
		if path != "" {
			return path
		}
	}
	return ""
}

func findLibraryInCommonPaths(libname string) string {
	for _, dir := range commonSSLPaths {
		matches, _ := filepath.Glob(filepath.Join(dir, libname+"*"))
		for _, match := range matches {
			info, err := os.Stat(match)
			if err == nil && !info.IsDir() {
				return match
			}
		}
	}
	return ""
}

// discoverSSLLibraries finds OpenSSL, GnuTLS, and NSS library paths.
func discoverSSLLibraries(openssl, gnutls, nss bool) map[string]string {
	libs := make(map[string]string)
	if openssl {
		if path := findLibraryPath("libssl.so"); path != "" {
			libs["openssl"] = path
		}
	}
	if gnutls {
		if path := findLibraryPath("libgnutls.so"); path != "" {
			libs["gnutls"] = path
		}
	}
	if nss {
		if path := findLibraryPath("libnspr4.so"); path != "" {
			libs["nss"] = path
		}
	}
	return libs
}

// sslUprobeSpec describes a uprobe to attach for SSL monitoring.
type sslUprobeSpec struct {
	symbol    string
	prog      string // program field name in sslsniffPrograms
	isRetprobe bool
}

// opensslUprobes lists all uprobe specs for OpenSSL.
var opensslUprobes = []sslUprobeSpec{
	{"SSL_write", "ProbeSSL_rwEnter", false},
	{"SSL_write", "ProbeSSL_writeExit", true},
	{"SSL_read", "ProbeSSL_rwEnter", false},
	{"SSL_read", "ProbeSSL_readExit", true},
	{"SSL_write_ex", "ProbeSSL_writeExEnter", false},
	{"SSL_write_ex", "ProbeSSL_writeExExit", true},
	{"SSL_read_ex", "ProbeSSL_readExEnter", false},
	{"SSL_read_ex", "ProbeSSL_readExExit", true},
	{"SSL_do_handshake", "ProbeSSL_doHandshakeEnter", false},
	{"SSL_do_handshake", "ProbeSSL_doHandshakeExit", true},
}

// gnutlsUprobes lists uprobe specs for GnuTLS.
var gnutlsUprobes = []sslUprobeSpec{
	{"gnutls_record_send", "ProbeSSL_rwEnter", false},
	{"gnutls_record_send", "ProbeSSL_writeExit", true},
	{"gnutls_record_recv", "ProbeSSL_rwEnter", false},
	{"gnutls_record_recv", "ProbeSSL_readExit", true},
}

// nssUprobes lists uprobe specs for NSS.
var nssUprobes = []sslUprobeSpec{
	{"PR_Write", "ProbeSSL_rwEnter", false},
	{"PR_Write", "ProbeSSL_writeExit", true},
	{"PR_Send", "ProbeSSL_rwEnter", false},
	{"PR_Send", "ProbeSSL_writeExit", true},
	{"PR_Read", "ProbeSSL_rwEnter", false},
	{"PR_Read", "ProbeSSL_readExit", true},
	{"PR_Recv", "ProbeSSL_rwEnter", false},
	{"PR_Recv", "ProbeSSL_readExit", true},
}

// formatSSLLibInfo returns a human-readable summary of discovered SSL libraries.
func formatSSLLibInfo(libs map[string]string) string {
	var parts []string
	for name, path := range libs {
		parts = append(parts, fmt.Sprintf("%s=%s", name, path))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}
