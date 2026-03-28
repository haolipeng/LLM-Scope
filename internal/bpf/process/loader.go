package process

import "github.com/cilium/ebpf"

// Exported type aliases for the generated bpf2go types.
type Objects = processObjects
type Programs = processPrograms
type Maps = processMaps
type Variables = processVariables
type Event = processEvent

// LoadSpec returns the embedded CollectionSpec for the process BPF program.
func LoadSpec() (*ebpf.CollectionSpec, error) {
	return loadProcess()
}

// LoadObjects loads BPF objects into the kernel.
func LoadObjects(obj *Objects, opts *ebpf.CollectionOptions) error {
	return loadProcessObjects(obj, opts)
}
