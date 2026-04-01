package sslsniff

import "github.com/cilium/ebpf"

// Export generated bpf2go types as stable package-level names.
type (
	Objects      = sslsniffObjects
	Programs     = sslsniffPrograms
	Maps         = sslsniffMaps
	Variables    = sslsniffVariables
	ProbeSSLDataT = sslsniffProbeSSL_dataT
)

// LoadSpec returns the embedded CollectionSpec for the sslsniff BPF program.
func LoadSpec() (*ebpf.CollectionSpec, error) {
	return loadSslsniff()
}

// LoadObjects loads BPF objects into the kernel.
func LoadObjects(obj *Objects, opts *ebpf.CollectionOptions) error {
	return loadSslsniffObjects(obj, opts)
}

// LoadPrograms loads only program objects into the kernel.
func LoadPrograms(progs *Programs, opts *ebpf.CollectionOptions) error {
	return loadSslsniffObjects(progs, opts)
}

// LoadMaps loads only map objects into the kernel.
func LoadMaps(maps *Maps, opts *ebpf.CollectionOptions) error {
	return loadSslsniffObjects(maps, opts)
}
