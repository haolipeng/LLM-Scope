package stdiocap

import "github.com/cilium/ebpf"

// 将 bpf2go 生成的类型以稳定的包级名称导出。
type (
	Objects        = stdiocapObjects
	Programs       = stdiocapPrograms
	Maps           = stdiocapMaps
	Variables      = stdiocapVariables
	StdiocapEventT = stdiocapStdiocapEventT
)

// LoadSpec 返回内嵌的 stdiocap BPF 程序 CollectionSpec。
func LoadSpec() (*ebpf.CollectionSpec, error) { return loadStdiocap() }

// LoadObjects 将完整的 BPF 对象加载到内核中。
func LoadObjects(obj *Objects, opts *ebpf.CollectionOptions) error { return loadStdiocapObjects(obj, opts) }

// LoadPrograms 仅将程序对象加载到内核中。
func LoadPrograms(progs *Programs, opts *ebpf.CollectionOptions) error { return loadStdiocapObjects(progs, opts) }

// LoadMaps 仅将 map 对象加载到内核中。
func LoadMaps(maps *Maps, opts *ebpf.CollectionOptions) error { return loadStdiocapObjects(maps, opts) }
