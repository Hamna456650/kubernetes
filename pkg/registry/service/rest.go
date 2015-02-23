/*
Copyright 2014 Google Inc. All rights reserved.

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

package service

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/api/errors"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/api/rest"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/api/validation"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/cloudprovider"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/labels"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/registry/minion"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/runtime"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/watch"
	"github.com/golang/glog"
)

// REST adapts a service registry into apiserver's RESTStorage model.
type REST struct {
	registry    Registry
	cloud       cloudprovider.Interface
	machines    minion.Registry
	portalMgr   *ipAllocator
	clusterName string
}

// NewREST returns a new REST.
func NewREST(registry Registry, cloud cloudprovider.Interface, machines minion.Registry, portalNet *net.IPNet,
	clusterName string) *REST {
	// TODO: Before we can replicate masters, this has to be synced (e.g. lives in etcd)
	ipa := newIPAllocator(portalNet)
	if ipa == nil {
		glog.Fatalf("Failed to create an IP allocator. Is subnet '%v' valid?", portalNet)
	}
	reloadIPsFromStorage(ipa, registry)

	return &REST{
		registry:    registry,
		cloud:       cloud,
		machines:    machines,
		portalMgr:   ipa,
		clusterName: clusterName,
	}
}

// Helper: mark all previously allocated IPs in the allocator.
func reloadIPsFromStorage(ipa *ipAllocator, registry Registry) {
	services, err := registry.ListServices(api.NewContext())
	if err != nil {
		// This is really bad.
		glog.Errorf("can't list services to init service REST: %v", err)
		return
	}
	for i := range services.Items {
		service := &services.Items[i]
		if service.Spec.PortalIP == "" {
			glog.Warningf("service %q has no PortalIP", service.Name)
			continue
		}
		if err := ipa.Allocate(net.ParseIP(service.Spec.PortalIP)); err != nil {
			// This is really bad.
			glog.Errorf("service %q PortalIP %s could not be allocated: %v", service.Name, service.Spec.PortalIP, err)
		}
	}
}

func (rs *REST) Create(ctx api.Context, obj runtime.Object) (runtime.Object, error) {
	service := obj.(*api.Service)

	if err := rest.BeforeCreate(rest.Services, ctx, obj); err != nil {
		return nil, err
	}

	if len(service.Spec.PortalIP) == 0 {
		// Allocate next available.
		ip, err := rs.portalMgr.AllocateNext()
		if err != nil {
			return nil, err
		}
		service.Spec.PortalIP = ip.String()
	} else {
		// Try to respect the requested IP.
		if err := rs.portalMgr.Allocate(net.ParseIP(service.Spec.PortalIP)); err != nil {
			el := errors.ValidationErrorList{errors.NewFieldInvalid("spec.portalIP", service.Spec.PortalIP, err.Error())}
			return nil, errors.NewInvalid("Service", service.Name, el)
		}
	}

	// TODO: Move this to post-creation rectification loop, so that we make/remove external load balancers
	// correctly no matter what http operations happen.
	if service.Spec.CreateExternalLoadBalancer {
		err := rs.createExternalLoadBalancer(ctx, service)
		if err != nil {
			rs.portalMgr.Release(net.ParseIP(service.Spec.PortalIP))
			return nil, err
		}
	}

	out, err := rs.registry.CreateService(ctx, service)
	if err != nil {
		rs.portalMgr.Release(net.ParseIP(service.Spec.PortalIP))
		err = rest.CheckGeneratedNameError(rest.Services, err, service)
	}
	return out, err
}

func hostsFromMinionList(list *api.NodeList) []string {
	result := make([]string, len(list.Items))
	for ix := range list.Items {
		result[ix] = list.Items[ix].Name
	}
	return result
}

func (rs *REST) Delete(ctx api.Context, id string) (runtime.Object, error) {
	service, err := rs.registry.GetService(ctx, id)
	if err != nil {
		return nil, err
	}
	rs.portalMgr.Release(net.ParseIP(service.Spec.PortalIP))
	if service.Spec.CreateExternalLoadBalancer {
		rs.deleteExternalLoadBalancer(ctx, service)
	}
	return &api.Status{Status: api.StatusSuccess}, rs.registry.DeleteService(ctx, id)
}

func (rs *REST) Get(ctx api.Context, id string) (runtime.Object, error) {
	service, err := rs.registry.GetService(ctx, id)
	if err != nil {
		return nil, err
	}
	return service, err
}

// TODO: implement field selector?
func (rs *REST) List(ctx api.Context, label, field labels.Selector) (runtime.Object, error) {
	list, err := rs.registry.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	var filtered []api.Service
	for _, service := range list.Items {
		if label.Matches(labels.Set(service.Labels)) {
			filtered = append(filtered, service)
		}
	}
	list.Items = filtered
	return list, err
}

// Watch returns Services events via a watch.Interface.
// It implements apiserver.ResourceWatcher.
func (rs *REST) Watch(ctx api.Context, label, field labels.Selector, resourceVersion string) (watch.Interface, error) {
	return rs.registry.WatchServices(ctx, label, field, resourceVersion)
}

func (*REST) New() runtime.Object {
	return &api.Service{}
}

func (*REST) NewList() runtime.Object {
	return &api.ServiceList{}
}

func (rs *REST) Update(ctx api.Context, obj runtime.Object) (runtime.Object, bool, error) {
	service := obj.(*api.Service)
	if !api.ValidNamespace(ctx, &service.ObjectMeta) {
		return nil, false, errors.NewConflict("service", service.Namespace, fmt.Errorf("Service.Namespace does not match the provided context"))
	}

	oldService, err := rs.registry.GetService(ctx, service.Name)
	if err != nil {
		return nil, false, err
	}

	// Copy over non-user fields
	// TODO: make this a merge function
	if errs := validation.ValidateServiceUpdate(oldService, service); len(errs) > 0 {
		return nil, false, errors.NewInvalid("service", service.Name, errs)
	}
	// Recreate external load balancer if changed.
	if externalLoadBalancerNeedsUpdate(oldService, service) {
		// TODO: support updating existing balancers
		if oldService.Spec.CreateExternalLoadBalancer {
			err = rs.deleteExternalLoadBalancer(ctx, oldService)
			if err != nil {
				return nil, false, err
			}
		}
		if service.Spec.CreateExternalLoadBalancer {
			err = rs.createExternalLoadBalancer(ctx, service)
			if err != nil {
				return nil, false, err
			}
		}
	}
	out, err := rs.registry.UpdateService(ctx, service)
	return out, false, err
}

// ResourceLocation returns a URL to which one can send traffic for the specified service.
func (rs *REST) ResourceLocation(ctx api.Context, id string) (string, error) {
	// Allow ID as "svcname" or "svcname:port".  Choose an endpoint at
	// random.  If the port is specified as a number, use that value
	// directly.  If the port is specified as a name, try to look up that
	// name on the chosen endpoint. If port is not specified, try to use
	// the first unnamed port on the chosen endpoint.  If there are no
	// unnamed ports, try to use the first defined port.
	parts := strings.Split(id, ":")
	if len(parts) > 2 {
		return "", errors.NewBadRequest(fmt.Sprintf("invalid service request %q", id))
	}
	name := parts[0]
	port := ""
	if len(parts) == 2 {
		port = parts[1]
	}

	eps, err := rs.registry.GetEndpoints(ctx, name)
	if err != nil {
		return "", err
	}
	if len(eps.Endpoints) == 0 {
		return "", fmt.Errorf("no endpoints available for %v", name)
	}
	ep := &eps.Endpoints[rand.Intn(len(eps.Endpoints))]

	// Try to figure out a port.
	if _, err := strconv.Atoi(port); err != nil {
		// Do nothing - port is correct as is.
	} else {
		// Try a name lookup, even if name is "".
		for i := range ep.Ports {
			if ep.Ports[i].Name == port {
				port = strconv.Itoa(ep.Ports[i].Port)
				break
			}
		}
	}
	if port == "" {
		// Still nothing - try the first defined port.
		if len(ep.Ports) > 0 {
			port = strconv.Itoa(ep.Ports[0].Port)
		}
	}

	// We leave off the scheme ('http://') because we have no idea what sort of server
	// is listening at this endpoint.
	loc := ep.IP
	if port != "" {
		loc += fmt.Sprintf(":%s", port)
	}
	return loc, nil
}

func (rs *REST) getLoadbalancerName(ctx api.Context, service *api.Service) string {
	return rs.clusterName + "-" + api.NamespaceValue(ctx) + "-" + service.Name
}

func (rs *REST) createExternalLoadBalancer(ctx api.Context, service *api.Service) error {
	if rs.cloud == nil {
		return fmt.Errorf("requested an external service, but no cloud provider supplied.")
	}
	if service.Spec.Protocol != api.ProtocolTCP {
		// TODO: Support UDP here too.
		return fmt.Errorf("external load balancers for non TCP services are not currently supported.")
	}
	balancer, ok := rs.cloud.TCPLoadBalancer()
	if !ok {
		return fmt.Errorf("the cloud provider does not support external TCP load balancers.")
	}
	zones, ok := rs.cloud.Zones()
	if !ok {
		return fmt.Errorf("the cloud provider does not support zone enumeration.")
	}
	hosts, err := rs.machines.ListMinions(ctx)
	if err != nil {
		return err
	}
	zone, err := zones.GetZone()
	if err != nil {
		return err
	}
	name := rs.getLoadbalancerName(ctx, service)
	// TODO: We should be able to rely on valid input, and not do defaulting here.
	var affinityType api.AffinityType = service.Spec.SessionAffinity
	if len(service.Spec.PublicIPs) > 0 {
		for _, publicIP := range service.Spec.PublicIPs {
			_, err = balancer.CreateTCPLoadBalancer(name, zone.Region, net.ParseIP(publicIP), service.Spec.Port, hostsFromMinionList(hosts), affinityType)
			if err != nil {
				// TODO: have to roll-back any successful calls.
				return err
			}
		}
	} else {
		ip, err := balancer.CreateTCPLoadBalancer(name, zone.Region, nil, service.Spec.Port, hostsFromMinionList(hosts), affinityType)
		if err != nil {
			return err
		}
		service.Spec.PublicIPs = []string{ip.String()}
	}
	return nil
}

func (rs *REST) deleteExternalLoadBalancer(ctx api.Context, service *api.Service) error {
	if rs.cloud == nil {
		return fmt.Errorf("requested an external service, but no cloud provider supplied.")
	}
	zones, ok := rs.cloud.Zones()
	if !ok {
		// We failed to get zone enumerator.
		// As this should have failed when we tried in "create" too,
		// assume external load balancer was never created.
		return nil
	}
	balancer, ok := rs.cloud.TCPLoadBalancer()
	if !ok {
		// See comment above.
		return nil
	}
	zone, err := zones.GetZone()
	if err != nil {
		return err
	}
	if err := balancer.DeleteTCPLoadBalancer(rs.getLoadbalancerName(ctx, service), zone.Region); err != nil {
		return err
	}
	return nil
}

func externalLoadBalancerNeedsUpdate(old, new *api.Service) bool {
	if !old.Spec.CreateExternalLoadBalancer && !new.Spec.CreateExternalLoadBalancer {
		return false
	}
	if old.Spec.CreateExternalLoadBalancer != new.Spec.CreateExternalLoadBalancer ||
		old.Spec.Port != new.Spec.Port ||
		old.Spec.SessionAffinity != new.Spec.SessionAffinity ||
		old.Spec.Protocol != new.Spec.Protocol {
		return true
	}
	if len(old.Spec.PublicIPs) != len(new.Spec.PublicIPs) {
		return true
	}
	for i := range old.Spec.PublicIPs {
		if old.Spec.PublicIPs[i] != new.Spec.PublicIPs[i] {
			return true
		}
	}
	return false
}
