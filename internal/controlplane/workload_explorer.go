package controlplane

import (
	"fmt"
	"sort"
	"strings"
)

const (
	WorkloadExplorerItemLimit  = 250
	WorkloadExplorerEventLimit = 100
)

func NormalizeClusterWorkloadExplorer(v ClusterWorkloadExplorer) (ClusterWorkloadExplorer, error) {
	v.Authority = WorkloadExplorerAuthorityMethod
	if len(v.Workloads) > WorkloadExplorerItemLimit || len(v.Services) > WorkloadExplorerItemLimit || len(v.Ingresses) > WorkloadExplorerItemLimit || len(v.PVCs) > WorkloadExplorerItemLimit || len(v.Events) > WorkloadExplorerEventLimit {
		return ClusterWorkloadExplorer{}, fmt.Errorf("%w: workload explorer payload exceeds bounded inventory limits", ErrValidation)
	}
	for i := range v.Workloads {
		v.Workloads[i].Kind = strings.TrimSpace(v.Workloads[i].Kind)
		v.Workloads[i].Namespace = strings.TrimSpace(v.Workloads[i].Namespace)
		v.Workloads[i].Name = strings.TrimSpace(v.Workloads[i].Name)
		if v.Workloads[i].Kind == "" || v.Workloads[i].Namespace == "" || v.Workloads[i].Name == "" || v.Workloads[i].DesiredReplicas < 0 || v.Workloads[i].ReadyReplicas < 0 || v.Workloads[i].Succeeded < 0 || v.Workloads[i].Failed < 0 {
			return ClusterWorkloadExplorer{}, fmt.Errorf("%w: workload observations require kind/namespace/name and non-negative counters", ErrValidation)
		}
		v.Workloads[i].Images = dedupeSortedStrings(v.Workloads[i].Images)
	}
	for i := range v.Services {
		v.Services[i].Namespace = strings.TrimSpace(v.Services[i].Namespace)
		v.Services[i].Name = strings.TrimSpace(v.Services[i].Name)
		v.Services[i].Type = strings.TrimSpace(v.Services[i].Type)
		if v.Services[i].Namespace == "" || v.Services[i].Name == "" {
			return ClusterWorkloadExplorer{}, fmt.Errorf("%w: service observations require namespace and name", ErrValidation)
		}
		v.Services[i].ExternalIPs = dedupeSortedStrings(v.Services[i].ExternalIPs)
	}
	for i := range v.Ingresses {
		v.Ingresses[i].Namespace = strings.TrimSpace(v.Ingresses[i].Namespace)
		v.Ingresses[i].Name = strings.TrimSpace(v.Ingresses[i].Name)
		if v.Ingresses[i].Namespace == "" || v.Ingresses[i].Name == "" {
			return ClusterWorkloadExplorer{}, fmt.Errorf("%w: ingress observations require namespace and name", ErrValidation)
		}
		v.Ingresses[i].Hosts = dedupeSortedStrings(v.Ingresses[i].Hosts)
		v.Ingresses[i].TLSHosts = dedupeSortedStrings(v.Ingresses[i].TLSHosts)
	}
	for i := range v.PVCs {
		v.PVCs[i].Namespace = strings.TrimSpace(v.PVCs[i].Namespace)
		v.PVCs[i].Name = strings.TrimSpace(v.PVCs[i].Name)
		if v.PVCs[i].Namespace == "" || v.PVCs[i].Name == "" {
			return ClusterWorkloadExplorer{}, fmt.Errorf("%w: PVC observations require namespace and name", ErrValidation)
		}
	}
	for i := range v.Events {
		v.Events[i].Namespace = strings.TrimSpace(v.Events[i].Namespace)
		v.Events[i].Message = strings.TrimSpace(v.Events[i].Message)
		if len(v.Events[i].Message) > 2048 {
			v.Events[i].Message = v.Events[i].Message[:2048]
			v.Truncated = true
		}
	}
	sort.Slice(v.Workloads, func(i, j int) bool {
		if v.Workloads[i].Namespace != v.Workloads[j].Namespace {
			return v.Workloads[i].Namespace < v.Workloads[j].Namespace
		}
		if v.Workloads[i].Kind != v.Workloads[j].Kind {
			return v.Workloads[i].Kind < v.Workloads[j].Kind
		}
		return v.Workloads[i].Name < v.Workloads[j].Name
	})
	sort.Slice(v.Services, func(i, j int) bool {
		if v.Services[i].Namespace != v.Services[j].Namespace {
			return v.Services[i].Namespace < v.Services[j].Namespace
		}
		return v.Services[i].Name < v.Services[j].Name
	})
	sort.Slice(v.Ingresses, func(i, j int) bool {
		if v.Ingresses[i].Namespace != v.Ingresses[j].Namespace {
			return v.Ingresses[i].Namespace < v.Ingresses[j].Namespace
		}
		return v.Ingresses[i].Name < v.Ingresses[j].Name
	})
	sort.Slice(v.PVCs, func(i, j int) bool {
		if v.PVCs[i].Namespace != v.PVCs[j].Namespace {
			return v.PVCs[i].Namespace < v.PVCs[j].Namespace
		}
		return v.PVCs[i].Name < v.PVCs[j].Name
	})
	sort.Slice(v.Events, func(i, j int) bool {
		a, b := v.Events[i], v.Events[j]
		if !a.LastObservedAt.Equal(b.LastObservedAt) {
			return a.LastObservedAt.After(b.LastObservedAt)
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		if a.RegardingKind != b.RegardingKind {
			return a.RegardingKind < b.RegardingKind
		}
		if a.RegardingName != b.RegardingName {
			return a.RegardingName < b.RegardingName
		}
		if a.Message != b.Message {
			return a.Message < b.Message
		}
		return a.Count < b.Count
	})
	return v, nil
}
