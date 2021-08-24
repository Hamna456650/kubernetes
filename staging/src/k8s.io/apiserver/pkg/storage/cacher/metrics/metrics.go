/*
Copyright 2015 The Kubernetes Authors.

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

package metrics

import (
	"sync"

	compbasemetrics "k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
)

/*
 * By default, all the following metrics are defined as falling under
 * ALPHA stability level https://github.com/kubernetes/enhancements/blob/master/keps/sig-instrumentation/1209-metrics-stability/kubernetes-control-plane-metrics-stability.md#stability-classes)
 *
 * Promoting the stability level of the metric is a responsibility of the component owner, since it
 * involves explicitly acknowledging support for the metric across multiple releases, in accordance with
 * the metric stability policy.
 */
var (
	listCacheNumFetched = compbasemetrics.NewHistogramVec(
		&compbasemetrics.HistogramOpts{
			Name:           "apiserver_list_cache_num_fetched",
			Help:           "Number of objects read from watch cache in the course of serving a LIST request, split by path_prefix and index_used",
			Buckets:        []float64{40, 80, 160, 320, 640, 1280, 2560, 5120, 10240},
			StabilityLevel: compbasemetrics.ALPHA,
		},
		[]string{"path_prefix", "index_used"},
	)
	listCacheNumSelectorEvals = compbasemetrics.NewHistogramVec(
		&compbasemetrics.HistogramOpts{
			Name:           "apiserver_list_cache_num_selector_evals",
			Help:           "Number of label or field selector evaluations in the course of serving a LIST request from watch cache, split by path_prefix and index_used",
			Buckets:        []float64{40, 80, 160, 320, 640, 1280, 2560, 5120, 10240, 20480},
			StabilityLevel: compbasemetrics.ALPHA,
		},
		[]string{"path_prefix", "index_used"},
	)
	listCacheNumReturned = compbasemetrics.NewHistogramVec(
		&compbasemetrics.HistogramOpts{
			Name:           "apiserver_list_cache_num_returned",
			Help:           "Number of objects returned for a LIST request from watch cache, split by path_prefix and index_used",
			Buckets:        []float64{40, 80, 160, 320, 640, 1280, 2560, 5120, 10240},
			StabilityLevel: compbasemetrics.ALPHA,
		},
		[]string{"path_prefix", "index_used"},
	)
)

var registerMetrics sync.Once

// Register all metrics.
func Register() {
	// Register the metrics.
	registerMetrics.Do(func() {
		legacyregistry.MustRegister(listCacheNumFetched)
		legacyregistry.MustRegister(listCacheNumSelectorEvals)
		legacyregistry.MustRegister(listCacheNumReturned)
	})
}

// RecordListCacheMetrics notes various metrics of the cost to serve a LIST request
func RecordListCacheMetrics(pathPrefix, indexUsed string, numFetched, numSelectorEvals, numReturned int) {
	listCacheNumFetched.WithLabelValues(pathPrefix, indexUsed).Observe(float64(numFetched))
	listCacheNumSelectorEvals.WithLabelValues(pathPrefix, indexUsed).Observe(float64(numSelectorEvals))
	listCacheNumReturned.WithLabelValues(pathPrefix, indexUsed).Observe(float64(numReturned))
}
