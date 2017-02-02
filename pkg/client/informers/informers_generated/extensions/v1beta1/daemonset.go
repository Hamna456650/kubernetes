/*
Copyright 2017 The Kubernetes Authors.

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

// This file was automatically generated by informer-gen

package v1beta1

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
	extensions_v1beta1 "k8s.io/kubernetes/pkg/apis/extensions/v1beta1"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/clientset"
	internalinterfaces "k8s.io/kubernetes/pkg/client/informers/informers_generated/internalinterfaces"
	v1beta1 "k8s.io/kubernetes/pkg/client/listers/extensions/v1beta1"
	time "time"
)

// DaemonSetInformer provides access to a shared informer and lister for
// DaemonSets.
type DaemonSetInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1beta1.DaemonSetLister
}

type daemonSetInformer struct {
	factory internalinterfaces.SharedInformerFactory
}

func newDaemonSetInformer(client clientset.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	sharedIndexInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				return client.ExtensionsV1beta1().DaemonSets(v1.NamespaceAll).List(options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				return client.ExtensionsV1beta1().DaemonSets(v1.NamespaceAll).Watch(options)
			},
		},
		&extensions_v1beta1.DaemonSet{},
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	return sharedIndexInformer
}

func (f *daemonSetInformer) Informer() cache.SharedIndexInformer {
	return f.factory.VersionedInformerFor(&extensions_v1beta1.DaemonSet{}, newDaemonSetInformer)
}

func (f *daemonSetInformer) Lister() v1beta1.DaemonSetLister {
	return v1beta1.NewDaemonSetLister(f.Informer().GetIndexer())
}
