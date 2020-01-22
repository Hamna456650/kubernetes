/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package topologymanager

import (
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager/bitmask"
	"k8s.io/kubernetes/pkg/kubelet/lifecycle"
)

type bestEffortPolicy struct {
	//List of NUMA Nodes available on the underlying machine
	numaNodes []int
}

var _ Policy = &bestEffortPolicy{}

// PolicyBestEffort policy name.
const PolicyBestEffort string = "best-effort"

// NewBestEffortPolicy returns best-effort policy.
func NewBestEffortPolicy(numaNodes []int) Policy {
	return &bestEffortPolicy{numaNodes: numaNodes}
}

func (p *bestEffortPolicy) Name() string {
	return PolicyBestEffort
}

func (p *bestEffortPolicy) canAdmitPodResult(hint *TopologyHint) lifecycle.PodAdmitResult {
	return lifecycle.PodAdmitResult{
		Admit: true,
	}
}

func (p *bestEffortPolicy) Merge(providersHints []map[string][]TopologyHint) (TopologyHint, lifecycle.PodAdmitResult) {
	filteredProvidersHints := filterProvidersHints(providersHints)
	hint := p.mergeProvidersHints(filteredProvidersHints)
	admit := p.canAdmitPodResult(&hint)
	return hint, admit
}

// Merge the hints from all hint providers to find the best one.
func (p *bestEffortPolicy) mergeProvidersHints(filteredHints [][]TopologyHint) TopologyHint {
	// Set the default affinity as an any-numa affinity containing the list
	// of NUMA Nodes available on this machine.
	defaultAffinity, _ := bitmask.NewBitMask(p.numaNodes...)

	// Iterate over all permutations of hints in 'allProviderHints'. Merge the
	// hints in each permutation by taking the bitwise-and of their affinity masks.
	// Return the hint with the narrowest NUMANodeAffinity of all merged
	// permutations that have at least one NUMA ID set. If no merged mask can be
	// found that has at least one NUMA ID set, return the 'defaultAffinity'.
	bestHint := TopologyHint{defaultAffinity, false}
	iterateAllProviderTopologyHints(filteredHints, func(permutation []TopologyHint) {
		// Get the NUMANodeAffinity from each hint in the permutation and see if any
		// of them encode unpreferred allocations.
		mergedHint := mergePermutation(p.numaNodes, permutation)

		// Only consider mergedHints that result in a NUMANodeAffinity > 0 to
		// replace the current bestHint.
		if mergedHint.NUMANodeAffinity.Count() == 0 {
			return
		}

		// If the current bestHint is non-preferred and the new mergedHint is
		// preferred, always choose the preferred hint over the non-preferred one.
		if mergedHint.Preferred && !bestHint.Preferred {
			bestHint = mergedHint
			return
		}

		// If the current bestHint is preferred and the new mergedHint is
		// non-preferred, never update bestHint, regardless of mergedHint's
		// narowness.
		if !mergedHint.Preferred && bestHint.Preferred {
			return
		}

		// If mergedHint and bestHint has the same preference, only consider
		// mergedHints that have a narrower NUMANodeAffinity than the
		// NUMANodeAffinity in the current bestHint.
		if !mergedHint.NUMANodeAffinity.IsNarrowerThan(bestHint.NUMANodeAffinity) {
			return
		}

		// In all other cases, update bestHint to the current mergedHint
		bestHint = mergedHint
	})

	return bestHint
}
