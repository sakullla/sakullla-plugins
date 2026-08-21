package dockerapp

import (
	"fmt"
	"sort"
)

const AppLabel = "nre.app.id"

type ContainerObservation struct {
	ID           string
	Labels       map[string]string
	ExposedPorts []uint16
}

type Discovery struct {
	ContainerID string
	AppID       string
	Ports       []uint16
	Candidate   bool
}

// EngineObservation is supplied by the Agent-local Docker engine observation.
// Discover and ProjectEngineReady never open a socket, take a connection form,
// or install the engine.
type EngineObservation struct {
	Installed bool
	Version   string
}

// Discover consumes observations supplied by a future typed broker handle.
// It performs no Engine call: labeled containers are owned discoveries, while
// unlabeled exposed ports are candidates requiring explicit adoption.
func Discover(observations []ContainerObservation) ([]Discovery, error) {
	if len(observations) > MaxDiscoveries {
		return nil, fmt.Errorf("%w: discoveries maximum is %d", ErrBoundExceeded, MaxDiscoveries)
	}
	result := make([]Discovery, 0, len(observations))
	for _, observation := range observations {
		if !boundedText(observation.ID, 128) || len(observation.ExposedPorts) > 64 {
			return nil, ErrBoundExceeded
		}
		ports := append([]uint16(nil), observation.ExposedPorts...)
		sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
		for _, port := range ports {
			if port == 0 {
				return nil, fmt.Errorf("container %q exposes port zero", observation.ID)
			}
		}
		if appID := observation.Labels[AppLabel]; appID != "" {
			if !validID(appID) {
				return nil, fmt.Errorf("container %q has invalid app label", observation.ID)
			}
			result = append(result, Discovery{ContainerID: observation.ID, AppID: appID, Ports: ports})
		} else if len(ports) != 0 {
			result = append(result, Discovery{ContainerID: observation.ID, Ports: ports, Candidate: true})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ContainerID < result[j].ContainerID })
	return result, nil
}
