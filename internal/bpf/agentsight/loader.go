package agentsight

import "github.com/cilium/ebpf"

type (
	Objects      = agentsightObjects
	Programs     = agentsightPrograms
	Maps         = agentsightMaps
	Variables    = agentsightVariables
	ProcessEvent = agentsightEvent
	SSLEvent     = agentsightProbeSSL_dataT
	StdioEvent   = agentsightStdiocapEventT
)

func LoadSpec() (*ebpf.CollectionSpec, error) { return loadAgentsight() }

func LoadObjects(obj *Objects, opts *ebpf.CollectionOptions) error {
	return loadAgentsightObjects(obj, opts)
}
