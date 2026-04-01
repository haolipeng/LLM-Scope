package process

import (
	"github.com/cilium/ebpf"
	legacy "github.com/haolipeng/LLM-Scope/internal/bpf/process"
)

// 将 bpf2go 生成的 internal/bpf/process 类型与加载函数导出为 runtime 包 API。
type (
	Objects   = legacy.Objects
	Programs  = legacy.Programs
	Maps      = legacy.Maps
	Variables = legacy.Variables
	Event     = legacy.Event
)

func LoadSpec() (*ebpf.CollectionSpec, error) { return legacy.LoadSpec() }

func LoadObjects(obj *Objects, opts *ebpf.CollectionOptions) error { return legacy.LoadObjects(obj, opts) }

func LoadPrograms(progs *Programs, opts *ebpf.CollectionOptions) error { return legacy.LoadPrograms(progs, opts) }

func LoadMaps(maps *Maps, opts *ebpf.CollectionOptions) error { return legacy.LoadMaps(maps, opts) }
