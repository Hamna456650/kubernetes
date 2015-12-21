/*
Copyright 2016 The Kubernetes Authors All rights reserved.

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

package unversioned

import (
	api "k8s.io/kubernetes/pkg/api"
	registered "k8s.io/kubernetes/pkg/apimachinery/registered"
	unversioned "k8s.io/kubernetes/pkg/client/unversioned"
)

type LegacyInterface interface {
	ComponentStatusGetter
	EndpointsGetter
	EventsGetter
	LimitRangesGetter
	NamespacesGetter
	NodesGetter
	PersistentVolumesGetter
	PersistentVolumeClaimsGetter
	PodsGetter
	PodTemplatesGetter
	ReplicationControllersGetter
	ResourceQuotasGetter
	SecretsGetter
	ServicesGetter
	ServiceAccountsGetter
}

// LegacyClient is used to interact with features provided by the Legacy group.
type LegacyClient struct {
	*unversioned.RESTClient
}

func (c *LegacyClient) ComponentStatus() ComponentStatusInterface {
	return newComponentStatus(c)
}

func (c *LegacyClient) Endpoints(namespace string) EndpointsInterface {
	return newEndpoints(c, namespace)
}

func (c *LegacyClient) Events(namespace string) EventInterface {
	return newEvents(c, namespace)
}

func (c *LegacyClient) LimitRanges(namespace string) LimitRangeInterface {
	return newLimitRanges(c, namespace)
}

func (c *LegacyClient) Namespaces() NamespaceInterface {
	return newNamespaces(c)
}

func (c *LegacyClient) Nodes() NodeInterface {
	return newNodes(c)
}

func (c *LegacyClient) PersistentVolumes() PersistentVolumeInterface {
	return newPersistentVolumes(c)
}

func (c *LegacyClient) PersistentVolumeClaims(namespace string) PersistentVolumeClaimInterface {
	return newPersistentVolumeClaims(c, namespace)
}

func (c *LegacyClient) Pods(namespace string) PodInterface {
	return newPods(c, namespace)
}

func (c *LegacyClient) PodTemplates(namespace string) PodTemplateInterface {
	return newPodTemplates(c, namespace)
}

func (c *LegacyClient) ReplicationControllers(namespace string) ReplicationControllerInterface {
	return newReplicationControllers(c, namespace)
}

func (c *LegacyClient) ResourceQuotas(namespace string) ResourceQuotaInterface {
	return newResourceQuotas(c, namespace)
}

func (c *LegacyClient) Secrets(namespace string) SecretInterface {
	return newSecrets(c, namespace)
}

func (c *LegacyClient) Services(namespace string) ServiceInterface {
	return newServices(c, namespace)
}

func (c *LegacyClient) ServiceAccounts(namespace string) ServiceAccountInterface {
	return newServiceAccounts(c, namespace)
}

// NewForConfig creates a new LegacyClient for the given config.
func NewForConfig(c *unversioned.Config) (*LegacyClient, error) {
	config := *c
	if err := setConfigDefaults(&config); err != nil {
		return nil, err
	}
	client, err := unversioned.RESTClientFor(&config)
	if err != nil {
		return nil, err
	}
	return &LegacyClient{client}, nil
}

// NewForConfigOrDie creates a new LegacyClient for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *unversioned.Config) *LegacyClient {
	client, err := NewForConfig(c)
	if err != nil {
		panic(err)
	}
	return client
}

// New creates a new LegacyClient for the given RESTClient.
func New(c *unversioned.RESTClient) *LegacyClient {
	return &LegacyClient{c}
}

func setConfigDefaults(config *unversioned.Config) error {
	// if legacy group is not registered, return an error
	g, err := registered.Group("")
	if err != nil {
		return err
	}
	config.APIPath = "/api"
	if config.UserAgent == "" {
		config.UserAgent = unversioned.DefaultKubernetesUserAgent()
	}
	// TODO: Unconditionally set the config.Version, until we fix the config.
	//if config.Version == "" {
	copyGroupVersion := g.GroupVersion
	config.GroupVersion = &copyGroupVersion
	//}

	config.Codec = api.Codecs.LegacyCodec(*config.GroupVersion)
	if config.QPS == 0 {
		config.QPS = 5
	}
	if config.Burst == 0 {
		config.Burst = 10
	}
	return nil
}
