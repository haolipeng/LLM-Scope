package sslsniff

import "github.com/cilium/ebpf"

// Exported type aliases for the generated bpf2go types.
type Objects = sslsniffObjects
type Programs = sslsniffPrograms
type Maps = sslsniffMaps
type Variables = sslsniffVariables
type ProbeSSLDataT = sslsniffProbeSSL_dataT

// LoadSpec returns the embedded CollectionSpec for the sslsniff BPF program.
func LoadSpec() (*ebpf.CollectionSpec, error) {
	return loadSslsniff()
}

// LoadObjects loads BPF objects into the kernel.
func LoadObjects(obj *Objects, opts *ebpf.CollectionOptions) error {
	return loadSslsniffObjects(obj, opts)
}
