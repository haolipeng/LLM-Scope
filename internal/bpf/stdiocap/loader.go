package stdiocap

import "github.com/cilium/ebpf"

// Exported type aliases for the generated bpf2go types.
type Objects = stdiocapObjects
type Programs = stdiocapPrograms
type Maps = stdiocapMaps
type Variables = stdiocapVariables
type StdiocapEventT = stdiocapStdiocapEventT

// LoadSpec returns the embedded CollectionSpec for the stdiocap BPF program.
func LoadSpec() (*ebpf.CollectionSpec, error) {
	return loadStdiocap()
}

// LoadObjects loads BPF objects into the kernel.
func LoadObjects(obj *Objects, opts *ebpf.CollectionOptions) error {
	return loadStdiocapObjects(obj, opts)
}
