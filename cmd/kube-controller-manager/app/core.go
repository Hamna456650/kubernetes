/*
Copyright 2016 The Kubernetes Authors.

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

// Package app implements a server that runs a set of active
// components.  This includes replication controllers, service endpoints and
// nodes.
//
package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"k8s.io/klog/v2"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/quota/v1/generic"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	restclient "k8s.io/client-go/rest"
	cloudnodelifecyclecontroller "k8s.io/cloud-provider/controllers/nodelifecycle"
	routecontroller "k8s.io/cloud-provider/controllers/route"
	servicecontroller "k8s.io/cloud-provider/controllers/service"
	"k8s.io/component-base/metrics/prometheus/ratelimiter"
	csitrans "k8s.io/csi-translation-lib"
	"k8s.io/kubernetes/cmd/kube-controller-manager/app/options"
	"k8s.io/kubernetes/pkg/controller"
	endpointcontroller "k8s.io/kubernetes/pkg/controller/endpoint"
	"k8s.io/kubernetes/pkg/controller/garbagecollector"
	namespacecontroller "k8s.io/kubernetes/pkg/controller/namespace"
	nodeipamcontroller "k8s.io/kubernetes/pkg/controller/nodeipam"
	nodeipamconfig "k8s.io/kubernetes/pkg/controller/nodeipam/config"
	"k8s.io/kubernetes/pkg/controller/nodeipam/ipam"
	lifecyclecontroller "k8s.io/kubernetes/pkg/controller/nodelifecycle"
	"k8s.io/kubernetes/pkg/controller/podgc"
	replicationcontroller "k8s.io/kubernetes/pkg/controller/replication"
	resourcequotacontroller "k8s.io/kubernetes/pkg/controller/resourcequota"
	serviceaccountcontroller "k8s.io/kubernetes/pkg/controller/serviceaccount"
	"k8s.io/kubernetes/pkg/controller/storageversiongc"
	ttlcontroller "k8s.io/kubernetes/pkg/controller/ttl"
	"k8s.io/kubernetes/pkg/controller/ttlafterfinished"
	"k8s.io/kubernetes/pkg/controller/volume/attachdetach"
	"k8s.io/kubernetes/pkg/controller/volume/ephemeral"
	"k8s.io/kubernetes/pkg/controller/volume/expand"
	persistentvolumecontroller "k8s.io/kubernetes/pkg/controller/volume/persistentvolume"
	"k8s.io/kubernetes/pkg/controller/volume/pvcprotection"
	"k8s.io/kubernetes/pkg/controller/volume/pvprotection"
	"k8s.io/kubernetes/pkg/features"
	quotainstall "k8s.io/kubernetes/pkg/quota/v1/install"
	"k8s.io/kubernetes/pkg/volume/csimigration"
	netutils "k8s.io/utils/net"
)

const (
	// defaultNodeMaskCIDRIPv4 is default mask size for IPv4 node cidr
	defaultNodeMaskCIDRIPv4 = 24
	// defaultNodeMaskCIDRIPv6 is default mask size for IPv6 node cidr
	defaultNodeMaskCIDRIPv6 = 64
)

func startServiceController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	serviceController, err := servicecontroller.New(
		controllerContext.Cloud,
		controllerContext.ClientBuilder.ClientOrDie("service-controller"),
		controllerContext.InformerFactory.Core().V1().Services(),
		controllerContext.InformerFactory.Core().V1().Nodes(),
		controllerContext.ComponentConfig.KubeCloudShared.ClusterName,
		utilfeature.DefaultFeatureGate,
	)
	if err != nil {
		// This error shouldn't fail. It lives like this as a legacy.
		klog.Errorf("Failed to start service controller: %v", err)
		return nil, false, nil
	}
	go serviceController.Run(ctx, controllerContext.Stop, int(controllerContext.ComponentConfig.ServiceController.ConcurrentServiceSyncs))
	return nil, true, nil
}

func startNodeIpamController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	var serviceCIDR *net.IPNet
	var secondaryServiceCIDR *net.IPNet

	// should we start nodeIPAM
	if !controllerContext.ComponentConfig.KubeCloudShared.AllocateNodeCIDRs {
		return nil, false, nil
	}

	// failure: bad cidrs in config
	clusterCIDRs, dualStack, err := processCIDRs(controllerContext.ComponentConfig.KubeCloudShared.ClusterCIDR)
	if err != nil {
		return nil, false, err
	}

	// failure: more than one cidr and dual stack is not enabled
	if len(clusterCIDRs) > 1 && !utilfeature.DefaultFeatureGate.Enabled(features.IPv6DualStack) {
		return nil, false, fmt.Errorf("len of ClusterCIDRs==%v and dualstack or EndpointSlice feature is not enabled", len(clusterCIDRs))
	}

	// failure: more than one cidr but they are not configured as dual stack
	if len(clusterCIDRs) > 1 && !dualStack {
		return nil, false, fmt.Errorf("len of ClusterCIDRs==%v and they are not configured as dual stack (at least one from each IPFamily)", len(clusterCIDRs))
	}

	// failure: more than cidrs is not allowed even with dual stack
	if len(clusterCIDRs) > 2 {
		return nil, false, fmt.Errorf("len of clusters is:%v > more than max allowed of 2", len(clusterCIDRs))
	}

	// service cidr processing
	if len(strings.TrimSpace(controllerContext.ComponentConfig.NodeIPAMController.ServiceCIDR)) != 0 {
		_, serviceCIDR, err = net.ParseCIDR(controllerContext.ComponentConfig.NodeIPAMController.ServiceCIDR)
		if err != nil {
			klog.Warningf("Unsuccessful parsing of service CIDR %v: %v", controllerContext.ComponentConfig.NodeIPAMController.ServiceCIDR, err)
		}
	}

	if len(strings.TrimSpace(controllerContext.ComponentConfig.NodeIPAMController.SecondaryServiceCIDR)) != 0 {
		_, secondaryServiceCIDR, err = net.ParseCIDR(controllerContext.ComponentConfig.NodeIPAMController.SecondaryServiceCIDR)
		if err != nil {
			klog.Warningf("Unsuccessful parsing of service CIDR %v: %v", controllerContext.ComponentConfig.NodeIPAMController.SecondaryServiceCIDR, err)
		}
	}

	// the following checks are triggered if both serviceCIDR and secondaryServiceCIDR are provided
	if serviceCIDR != nil && secondaryServiceCIDR != nil {
		// should have dual stack flag enabled
		if !utilfeature.DefaultFeatureGate.Enabled(features.IPv6DualStack) {
			return nil, false, fmt.Errorf("secondary service cidr is provided and IPv6DualStack feature is not enabled")
		}

		// should be dual stack (from different IPFamilies)
		dualstackServiceCIDR, err := netutils.IsDualStackCIDRs([]*net.IPNet{serviceCIDR, secondaryServiceCIDR})
		if err != nil {
			return nil, false, fmt.Errorf("failed to perform dualstack check on serviceCIDR and secondaryServiceCIDR error:%v", err)
		}
		if !dualstackServiceCIDR {
			return nil, false, fmt.Errorf("serviceCIDR and secondaryServiceCIDR are not dualstack (from different IPfamiles)")
		}
	}

	var nodeCIDRMaskSizeIPv4, nodeCIDRMaskSizeIPv6 int
	if dualStack {
		// only --node-cidr-mask-size-ipv4 and --node-cidr-mask-size-ipv6 supported with dual stack clusters.
		// --node-cidr-mask-size flag is incompatible with dual stack clusters.
		nodeCIDRMaskSizeIPv4, nodeCIDRMaskSizeIPv6, err = setNodeCIDRMaskSizesDualStack(controllerContext.ComponentConfig.NodeIPAMController)
	} else {
		// only --node-cidr-mask-size supported with single stack clusters.
		// --node-cidr-mask-size-ipv4 and --node-cidr-mask-size-ipv6 flags are incompatible with single stack clusters.
		nodeCIDRMaskSizeIPv4, nodeCIDRMaskSizeIPv6, err = setNodeCIDRMaskSizes(controllerContext.ComponentConfig.NodeIPAMController)
	}

	if err != nil {
		return nil, false, err
	}

	// get list of node cidr mask sizes
	nodeCIDRMaskSizes := getNodeCIDRMaskSizes(clusterCIDRs, nodeCIDRMaskSizeIPv4, nodeCIDRMaskSizeIPv6)

	nodeIpamController, err := nodeipamcontroller.NewNodeIpamController(
		controllerContext.InformerFactory.Core().V1().Nodes(),
		controllerContext.Cloud,
		controllerContext.ClientBuilder.ClientOrDie("node-controller"),
		clusterCIDRs,
		serviceCIDR,
		secondaryServiceCIDR,
		nodeCIDRMaskSizes,
		ipam.CIDRAllocatorType(controllerContext.ComponentConfig.KubeCloudShared.CIDRAllocatorType),
	)
	if err != nil {
		return nil, true, err
	}
	go nodeIpamController.Run(controllerContext.Stop)
	return nil, true, nil
}

func startNodeLifecycleController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	lifecycleController, err := lifecyclecontroller.NewNodeLifecycleController(
		controllerContext.InformerFactory.Coordination().V1().Leases(),
		controllerContext.InformerFactory.Core().V1().Pods(),
		controllerContext.InformerFactory.Core().V1().Nodes(),
		controllerContext.InformerFactory.Apps().V1().DaemonSets(),
		// node lifecycle controller uses existing cluster role from node-controller
		controllerContext.ClientBuilder.ClientOrDie("node-controller"),
		controllerContext.ComponentConfig.KubeCloudShared.NodeMonitorPeriod.Duration,
		controllerContext.ComponentConfig.NodeLifecycleController.NodeStartupGracePeriod.Duration,
		controllerContext.ComponentConfig.NodeLifecycleController.NodeMonitorGracePeriod.Duration,
		controllerContext.ComponentConfig.NodeLifecycleController.PodEvictionTimeout.Duration,
		controllerContext.ComponentConfig.NodeLifecycleController.NodeEvictionRate,
		controllerContext.ComponentConfig.NodeLifecycleController.SecondaryNodeEvictionRate,
		controllerContext.ComponentConfig.NodeLifecycleController.LargeClusterSizeThreshold,
		controllerContext.ComponentConfig.NodeLifecycleController.UnhealthyZoneThreshold,
		controllerContext.ComponentConfig.NodeLifecycleController.EnableTaintManager,
	)
	if err != nil {
		return nil, true, err
	}
	go lifecycleController.Run(ctx, controllerContext.Stop)
	return nil, true, nil
}

func startCloudNodeLifecycleController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	cloudNodeLifecycleController, err := cloudnodelifecyclecontroller.NewCloudNodeLifecycleController(
		controllerContext.InformerFactory.Core().V1().Nodes(),
		// cloud node lifecycle controller uses existing cluster role from node-controller
		controllerContext.ClientBuilder.ClientOrDie("node-controller"),
		controllerContext.Cloud,
		controllerContext.ComponentConfig.KubeCloudShared.NodeMonitorPeriod.Duration,
	)
	if err != nil {
		// the controller manager should continue to run if the "Instances" interface is not
		// supported, though it's unlikely for a cloud provider to not support it
		klog.Errorf("failed to start cloud node lifecycle controller: %v", err)
		return nil, false, nil
	}

	go cloudNodeLifecycleController.Run(ctx, controllerContext.Stop)
	return nil, true, nil
}

func startRouteController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	if !controllerContext.ComponentConfig.KubeCloudShared.AllocateNodeCIDRs || !controllerContext.ComponentConfig.KubeCloudShared.ConfigureCloudRoutes {
		klog.Infof("Will not configure cloud provider routes for allocate-node-cidrs: %v, configure-cloud-routes: %v.", controllerContext.ComponentConfig.KubeCloudShared.AllocateNodeCIDRs, controllerContext.ComponentConfig.KubeCloudShared.ConfigureCloudRoutes)
		return nil, false, nil
	}
	if controllerContext.Cloud == nil {
		klog.Warning("configure-cloud-routes is set, but no cloud provider specified. Will not configure cloud provider routes.")
		return nil, false, nil
	}
	routes, ok := controllerContext.Cloud.Routes()
	if !ok {
		klog.Warning("configure-cloud-routes is set, but cloud provider does not support routes. Will not configure cloud provider routes.")
		return nil, false, nil
	}

	// failure: bad cidrs in config
	clusterCIDRs, dualStack, err := processCIDRs(controllerContext.ComponentConfig.KubeCloudShared.ClusterCIDR)
	if err != nil {
		return nil, false, err
	}

	// failure: more than one cidr and dual stack is not enabled
	if len(clusterCIDRs) > 1 && !utilfeature.DefaultFeatureGate.Enabled(features.IPv6DualStack) {
		return nil, false, fmt.Errorf("len of ClusterCIDRs==%v and dualstack feature is not enabled", len(clusterCIDRs))
	}

	// failure: more than one cidr but they are not configured as dual stack
	if len(clusterCIDRs) > 1 && !dualStack {
		return nil, false, fmt.Errorf("len of ClusterCIDRs==%v and they are not configured as dual stack (at least one from each IPFamily", len(clusterCIDRs))
	}

	// failure: more than cidrs is not allowed even with dual stack
	if len(clusterCIDRs) > 2 {
		return nil, false, fmt.Errorf("length of clusterCIDRs is:%v more than max allowed of 2", len(clusterCIDRs))
	}

	routeController := routecontroller.New(routes,
		controllerContext.ClientBuilder.ClientOrDie("route-controller"),
		controllerContext.InformerFactory.Core().V1().Nodes(),
		controllerContext.ComponentConfig.KubeCloudShared.ClusterName,
		clusterCIDRs)
	go routeController.Run(ctx, controllerContext.Stop, controllerContext.ComponentConfig.KubeCloudShared.RouteReconciliationPeriod.Duration)
	return nil, true, nil
}

func startPersistentVolumeBinderController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	plugins, err := ProbeControllerVolumePlugins(controllerContext.Cloud, controllerContext.ComponentConfig.PersistentVolumeBinderController.VolumeConfiguration)
	if err != nil {
		return nil, true, fmt.Errorf("failed to probe volume plugins when starting persistentvolume controller: %v", err)
	}
	filteredDialOptions, err := options.ParseVolumeHostFilters(
		controllerContext.ComponentConfig.PersistentVolumeBinderController.VolumeHostCIDRDenylist,
		controllerContext.ComponentConfig.PersistentVolumeBinderController.VolumeHostAllowLocalLoopback)
	if err != nil {
		return nil, true, err
	}
	params := persistentvolumecontroller.ControllerParameters{
		KubeClient:                controllerContext.ClientBuilder.ClientOrDie("persistent-volume-binder"),
		SyncPeriod:                controllerContext.ComponentConfig.PersistentVolumeBinderController.PVClaimBinderSyncPeriod.Duration,
		VolumePlugins:             plugins,
		Cloud:                     controllerContext.Cloud,
		ClusterName:               controllerContext.ComponentConfig.KubeCloudShared.ClusterName,
		VolumeInformer:            controllerContext.InformerFactory.Core().V1().PersistentVolumes(),
		ClaimInformer:             controllerContext.InformerFactory.Core().V1().PersistentVolumeClaims(),
		ClassInformer:             controllerContext.InformerFactory.Storage().V1().StorageClasses(),
		PodInformer:               controllerContext.InformerFactory.Core().V1().Pods(),
		NodeInformer:              controllerContext.InformerFactory.Core().V1().Nodes(),
		EnableDynamicProvisioning: controllerContext.ComponentConfig.PersistentVolumeBinderController.VolumeConfiguration.EnableDynamicProvisioning,
		FilteredDialOptions:       filteredDialOptions,
	}
	volumeController, volumeControllerErr := persistentvolumecontroller.NewController(params)
	if volumeControllerErr != nil {
		return nil, true, fmt.Errorf("failed to construct persistentvolume controller: %v", volumeControllerErr)
	}
	go volumeController.Run(ctx, controllerContext.Stop)
	return nil, true, nil
}

func startAttachDetachController(_ context.Context, ctx ControllerContext) (http.Handler, bool, error) {
	if ctx.ComponentConfig.AttachDetachController.ReconcilerSyncLoopPeriod.Duration < time.Second {
		return nil, true, fmt.Errorf("duration time must be greater than one second as set via command line option reconcile-sync-loop-period")
	}

	csiNodeInformer := ctx.InformerFactory.Storage().V1().CSINodes()
	csiDriverInformer := ctx.InformerFactory.Storage().V1().CSIDrivers()

	plugins, err := ProbeAttachableVolumePlugins()
	if err != nil {
		return nil, true, fmt.Errorf("failed to probe volume plugins when starting attach/detach controller: %v", err)
	}

	filteredDialOptions, err := options.ParseVolumeHostFilters(
		ctx.ComponentConfig.PersistentVolumeBinderController.VolumeHostCIDRDenylist,
		ctx.ComponentConfig.PersistentVolumeBinderController.VolumeHostAllowLocalLoopback)
	if err != nil {
		return nil, true, err
	}

	attachDetachController, attachDetachControllerErr :=
		attachdetach.NewAttachDetachController(
			ctx.ClientBuilder.ClientOrDie("attachdetach-controller"),
			ctx.InformerFactory.Core().V1().Pods(),
			ctx.InformerFactory.Core().V1().Nodes(),
			ctx.InformerFactory.Core().V1().PersistentVolumeClaims(),
			ctx.InformerFactory.Core().V1().PersistentVolumes(),
			csiNodeInformer,
			csiDriverInformer,
			ctx.InformerFactory.Storage().V1().VolumeAttachments(),
			ctx.Cloud,
			plugins,
			GetDynamicPluginProber(ctx.ComponentConfig.PersistentVolumeBinderController.VolumeConfiguration),
			ctx.ComponentConfig.AttachDetachController.DisableAttachDetachReconcilerSync,
			ctx.ComponentConfig.AttachDetachController.ReconcilerSyncLoopPeriod.Duration,
			attachdetach.DefaultTimerConfig,
			filteredDialOptions,
		)
	if attachDetachControllerErr != nil {
		return nil, true, fmt.Errorf("failed to start attach/detach controller: %v", attachDetachControllerErr)
	}
	go attachDetachController.Run(ctx.Stop)
	return nil, true, nil
}

func startVolumeExpandController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	if utilfeature.DefaultFeatureGate.Enabled(features.ExpandPersistentVolumes) {
		plugins, err := ProbeExpandableVolumePlugins(controllerContext.ComponentConfig.PersistentVolumeBinderController.VolumeConfiguration)
		if err != nil {
			return nil, true, fmt.Errorf("failed to probe volume plugins when starting volume expand controller: %v", err)
		}
		csiTranslator := csitrans.New()
		filteredDialOptions, err := options.ParseVolumeHostFilters(
			controllerContext.ComponentConfig.PersistentVolumeBinderController.VolumeHostCIDRDenylist,
			controllerContext.ComponentConfig.PersistentVolumeBinderController.VolumeHostAllowLocalLoopback)
		if err != nil {
			return nil, true, err
		}
		expandController, expandControllerErr := expand.NewExpandController(
			controllerContext.ClientBuilder.ClientOrDie("expand-controller"),
			controllerContext.InformerFactory.Core().V1().PersistentVolumeClaims(),
			controllerContext.InformerFactory.Core().V1().PersistentVolumes(),
			controllerContext.Cloud,
			plugins,
			csiTranslator,
			csimigration.NewPluginManager(csiTranslator, utilfeature.DefaultFeatureGate),
			filteredDialOptions,
		)

		if expandControllerErr != nil {
			return nil, true, fmt.Errorf("failed to start volume expand controller: %v", expandControllerErr)
		}
		go expandController.Run(ctx, controllerContext.Stop)
		return nil, true, nil
	}
	return nil, false, nil
}

func startEphemeralVolumeController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	if utilfeature.DefaultFeatureGate.Enabled(features.GenericEphemeralVolume) {
		ephemeralController, err := ephemeral.NewController(
			controllerContext.ClientBuilder.ClientOrDie("ephemeral-volume-controller"),
			controllerContext.InformerFactory.Core().V1().Pods(),
			controllerContext.InformerFactory.Core().V1().PersistentVolumeClaims())
		if err != nil {
			return nil, true, fmt.Errorf("failed to start ephemeral volume controller: %v", err)
		}
		// TODO (before beta at the latest): make this configurable similar to the EndpointController
		go ephemeralController.Run(ctx, 1 /* int(controllerContext.ComponentConfig.EphemeralController.ConcurrentEphemeralVolumeSyncs) */, controllerContext.Stop)
		return nil, true, nil
	}
	return nil, false, nil
}

func startEndpointController(ctx context.Context, controllerCtx ControllerContext) (http.Handler, bool, error) {
	go endpointcontroller.NewEndpointController(
		controllerCtx.InformerFactory.Core().V1().Pods(),
		controllerCtx.InformerFactory.Core().V1().Services(),
		controllerCtx.InformerFactory.Core().V1().Endpoints(),
		controllerCtx.ClientBuilder.ClientOrDie("endpoint-controller"),
		controllerCtx.ComponentConfig.EndpointController.EndpointUpdatesBatchPeriod.Duration,
	).Run(ctx, int(controllerCtx.ComponentConfig.EndpointController.ConcurrentEndpointSyncs), controllerCtx.Stop)
	return nil, true, nil
}

func startReplicationController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	go replicationcontroller.NewReplicationManager(
		controllerContext.InformerFactory.Core().V1().Pods(),
		controllerContext.InformerFactory.Core().V1().ReplicationControllers(),
		controllerContext.ClientBuilder.ClientOrDie("replication-controller"),
		replicationcontroller.BurstReplicas,
	).Run(ctx, int(controllerContext.ComponentConfig.ReplicationController.ConcurrentRCSyncs), controllerContext.Stop)
	return nil, true, nil
}

func startPodGCController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	go podgc.NewPodGC(
		controllerContext.ClientBuilder.ClientOrDie("pod-garbage-collector"),
		controllerContext.InformerFactory.Core().V1().Pods(),
		controllerContext.InformerFactory.Core().V1().Nodes(),
		int(controllerContext.ComponentConfig.PodGCController.TerminatedPodGCThreshold),
	).Run(ctx, controllerContext.Stop)
	return nil, true, nil
}

func startResourceQuotaController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	resourceQuotaControllerClient := controllerContext.ClientBuilder.ClientOrDie("resourcequota-controller")
	resourceQuotaControllerDiscoveryClient := controllerContext.ClientBuilder.DiscoveryClientOrDie("resourcequota-controller")
	discoveryFunc := resourceQuotaControllerDiscoveryClient.ServerPreferredNamespacedResources
	listerFuncForResource := generic.ListerFuncForResourceFunc(controllerContext.InformerFactory.ForResource)
	quotaConfiguration := quotainstall.NewQuotaConfigurationForControllers(listerFuncForResource)

	resourceQuotaControllerOptions := &resourcequotacontroller.ControllerOptions{
		QuotaClient:               resourceQuotaControllerClient.CoreV1(),
		ResourceQuotaInformer:     controllerContext.InformerFactory.Core().V1().ResourceQuotas(),
		ResyncPeriod:              controller.StaticResyncPeriodFunc(controllerContext.ComponentConfig.ResourceQuotaController.ResourceQuotaSyncPeriod.Duration),
		InformerFactory:           controllerContext.ObjectOrMetadataInformerFactory,
		ReplenishmentResyncPeriod: controllerContext.ResyncPeriod,
		DiscoveryFunc:             discoveryFunc,
		IgnoredResourcesFunc:      quotaConfiguration.IgnoredResources,
		InformersStarted:          controllerContext.InformersStarted,
		Registry:                  generic.NewRegistry(quotaConfiguration.Evaluators()),
	}
	if resourceQuotaControllerClient.CoreV1().RESTClient().GetRateLimiter() != nil {
		if err := ratelimiter.RegisterMetricAndTrackRateLimiterUsage("resource_quota_controller", resourceQuotaControllerClient.CoreV1().RESTClient().GetRateLimiter()); err != nil {
			return nil, true, err
		}
	}

	resourceQuotaController, err := resourcequotacontroller.NewController(resourceQuotaControllerOptions)
	if err != nil {
		return nil, false, err
	}
	go resourceQuotaController.Run(ctx, int(controllerContext.ComponentConfig.ResourceQuotaController.ConcurrentResourceQuotaSyncs), controllerContext.Stop)

	// Periodically the quota controller to detect new resource types
	go resourceQuotaController.Sync(discoveryFunc, 30*time.Second, controllerContext.Stop)

	return nil, true, nil
}

func startNamespaceController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	// the namespace cleanup controller is very chatty.  It makes lots of discovery calls and then it makes lots of delete calls
	// the ratelimiter negatively affects its speed.  Deleting 100 total items in a namespace (that's only a few of each resource
	// including events), takes ~10 seconds by default.
	nsKubeconfig := controllerContext.ClientBuilder.ConfigOrDie("namespace-controller")
	nsKubeconfig.QPS *= 20
	nsKubeconfig.Burst *= 100
	namespaceKubeClient := clientset.NewForConfigOrDie(nsKubeconfig)
	return startModifiedNamespaceController(controllerContext, namespaceKubeClient, nsKubeconfig)
}

func startModifiedNamespaceController(ctx ControllerContext, namespaceKubeClient clientset.Interface, nsKubeconfig *restclient.Config) (http.Handler, bool, error) {

	metadataClient, err := metadata.NewForConfig(nsKubeconfig)
	if err != nil {
		return nil, true, err
	}

	discoverResourcesFn := namespaceKubeClient.Discovery().ServerPreferredNamespacedResources

	namespaceController := namespacecontroller.NewNamespaceController(
		namespaceKubeClient,
		metadataClient,
		discoverResourcesFn,
		ctx.InformerFactory.Core().V1().Namespaces(),
		ctx.ComponentConfig.NamespaceController.NamespaceSyncPeriod.Duration,
		v1.FinalizerKubernetes,
	)
	go namespaceController.Run(int(ctx.ComponentConfig.NamespaceController.ConcurrentNamespaceSyncs), ctx.Stop)

	return nil, true, nil
}

func startServiceAccountController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	sac, err := serviceaccountcontroller.NewServiceAccountsController(
		controllerContext.InformerFactory.Core().V1().ServiceAccounts(),
		controllerContext.InformerFactory.Core().V1().Namespaces(),
		controllerContext.ClientBuilder.ClientOrDie("service-account-controller"),
		serviceaccountcontroller.DefaultServiceAccountsControllerOptions(),
	)
	if err != nil {
		return nil, true, fmt.Errorf("error creating ServiceAccount controller: %v", err)
	}
	go sac.Run(ctx, 1, controllerContext.Stop)
	return nil, true, nil
}

func startTTLController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	go ttlcontroller.NewTTLController(
		controllerContext.InformerFactory.Core().V1().Nodes(),
		controllerContext.ClientBuilder.ClientOrDie("ttl-controller"),
	).Run(ctx, 5, controllerContext.Stop)
	return nil, true, nil
}

func startGarbageCollectorController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	if !controllerContext.ComponentConfig.GarbageCollectorController.EnableGarbageCollector {
		return nil, false, nil
	}

	gcClientset := controllerContext.ClientBuilder.ClientOrDie("generic-garbage-collector")
	discoveryClient := controllerContext.ClientBuilder.DiscoveryClientOrDie("generic-garbage-collector")

	config := controllerContext.ClientBuilder.ConfigOrDie("generic-garbage-collector")
	metadataClient, err := metadata.NewForConfig(config)
	if err != nil {
		return nil, true, err
	}

	ignoredResources := make(map[schema.GroupResource]struct{})
	for _, r := range controllerContext.ComponentConfig.GarbageCollectorController.GCIgnoredResources {
		ignoredResources[schema.GroupResource{Group: r.Group, Resource: r.Resource}] = struct{}{}
	}
	garbageCollector, err := garbagecollector.NewGarbageCollector(
		gcClientset,
		metadataClient,
		controllerContext.RESTMapper,
		ignoredResources,
		controllerContext.ObjectOrMetadataInformerFactory,
		controllerContext.InformersStarted,
	)
	if err != nil {
		return nil, true, fmt.Errorf("failed to start the generic garbage collector: %v", err)
	}

	// Start the garbage collector.
	workers := int(controllerContext.ComponentConfig.GarbageCollectorController.ConcurrentGCSyncs)
	go garbageCollector.Run(ctx, workers, controllerContext.Stop)

	// Periodically refresh the RESTMapper with new discovery information and sync
	// the garbage collector.
	go garbageCollector.Sync(discoveryClient, 30*time.Second, controllerContext.Stop)

	return garbagecollector.NewDebugHandler(garbageCollector), true, nil
}

func startPVCProtectionController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	pvcProtectionController, err := pvcprotection.NewPVCProtectionController(
		controllerContext.InformerFactory.Core().V1().PersistentVolumeClaims(),
		controllerContext.InformerFactory.Core().V1().Pods(),
		controllerContext.ClientBuilder.ClientOrDie("pvc-protection-controller"),
		utilfeature.DefaultFeatureGate.Enabled(features.StorageObjectInUseProtection),
		utilfeature.DefaultFeatureGate.Enabled(features.StorageObjectInUseProtection),
	)
	if err != nil {
		return nil, true, fmt.Errorf("failed to start the pvc protection controller: %v", err)
	}
	go pvcProtectionController.Run(ctx, 1, controllerContext.Stop)
	return nil, true, nil
}

func startPVProtectionController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	go pvprotection.NewPVProtectionController(
		controllerContext.InformerFactory.Core().V1().PersistentVolumes(),
		controllerContext.ClientBuilder.ClientOrDie("pv-protection-controller"),
		utilfeature.DefaultFeatureGate.Enabled(features.StorageObjectInUseProtection),
	).Run(ctx, 1, controllerContext.Stop)
	return nil, true, nil
}

func startTTLAfterFinishedController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	if !utilfeature.DefaultFeatureGate.Enabled(features.TTLAfterFinished) {
		return nil, false, nil
	}
	go ttlafterfinished.New(
		controllerContext.InformerFactory.Batch().V1().Jobs(),
		controllerContext.ClientBuilder.ClientOrDie("ttl-after-finished-controller"),
	).Run(ctx, int(controllerContext.ComponentConfig.TTLAfterFinishedController.ConcurrentTTLSyncs), controllerContext.Stop)
	return nil, true, nil
}

// processCIDRs is a helper function that works on a comma separated cidrs and returns
// a list of typed cidrs
// a flag if cidrs represents a dual stack
// error if failed to parse any of the cidrs
func processCIDRs(cidrsList string) ([]*net.IPNet, bool, error) {
	cidrsSplit := strings.Split(strings.TrimSpace(cidrsList), ",")

	cidrs, err := netutils.ParseCIDRs(cidrsSplit)
	if err != nil {
		return nil, false, err
	}

	// if cidrs has an error then the previous call will fail
	// safe to ignore error checking on next call
	dualstack, _ := netutils.IsDualStackCIDRs(cidrs)

	return cidrs, dualstack, nil
}

// setNodeCIDRMaskSizes returns the IPv4 and IPv6 node cidr mask sizes.
// If --node-cidr-mask-size not set, then it will return default IPv4 and IPv6 cidr mask sizes.
func setNodeCIDRMaskSizes(cfg nodeipamconfig.NodeIPAMControllerConfiguration) (int, int, error) {
	ipv4Mask, ipv6Mask := defaultNodeMaskCIDRIPv4, defaultNodeMaskCIDRIPv6
	// NodeCIDRMaskSizeIPv4 and NodeCIDRMaskSizeIPv6 can be used only for dual-stack clusters
	if cfg.NodeCIDRMaskSizeIPv4 != 0 || cfg.NodeCIDRMaskSizeIPv6 != 0 {
		return ipv4Mask, ipv6Mask, errors.New("usage of --node-cidr-mask-size-ipv4 and --node-cidr-mask-size-ipv6 are not allowed with non dual-stack clusters")
	}
	if cfg.NodeCIDRMaskSize != 0 {
		ipv4Mask = int(cfg.NodeCIDRMaskSize)
		ipv6Mask = int(cfg.NodeCIDRMaskSize)
	}
	return ipv4Mask, ipv6Mask, nil
}

// setNodeCIDRMaskSizesDualStack returns the IPv4 and IPv6 node cidr mask sizes to the value provided
// for --node-cidr-mask-size-ipv4 and --node-cidr-mask-size-ipv6 respectively. If value not provided,
// then it will return default IPv4 and IPv6 cidr mask sizes.
func setNodeCIDRMaskSizesDualStack(cfg nodeipamconfig.NodeIPAMControllerConfiguration) (int, int, error) {
	ipv4Mask, ipv6Mask := defaultNodeMaskCIDRIPv4, defaultNodeMaskCIDRIPv6
	// NodeCIDRMaskSize can be used only for single stack clusters
	if cfg.NodeCIDRMaskSize != 0 {
		return ipv4Mask, ipv6Mask, errors.New("usage of --node-cidr-mask-size is not allowed with dual-stack clusters")
	}
	if cfg.NodeCIDRMaskSizeIPv4 != 0 {
		ipv4Mask = int(cfg.NodeCIDRMaskSizeIPv4)
	}
	if cfg.NodeCIDRMaskSizeIPv6 != 0 {
		ipv6Mask = int(cfg.NodeCIDRMaskSizeIPv6)
	}
	return ipv4Mask, ipv6Mask, nil
}

// getNodeCIDRMaskSizes is a helper function that helps the generate the node cidr mask
// sizes slice based on the cluster cidr slice
func getNodeCIDRMaskSizes(clusterCIDRs []*net.IPNet, maskSizeIPv4, maskSizeIPv6 int) []int {
	nodeMaskCIDRs := make([]int, len(clusterCIDRs))

	for idx, clusterCIDR := range clusterCIDRs {
		if netutils.IsIPv6CIDR(clusterCIDR) {
			nodeMaskCIDRs[idx] = maskSizeIPv6
		} else {
			nodeMaskCIDRs[idx] = maskSizeIPv4
		}
	}
	return nodeMaskCIDRs
}

func startStorageVersionGCController(ctx context.Context, controllerContext ControllerContext) (http.Handler, bool, error) {
	go storageversiongc.NewStorageVersionGC(
		controllerContext.ClientBuilder.ClientOrDie("storage-version-garbage-collector"),
		controllerContext.InformerFactory.Coordination().V1().Leases(),
		controllerContext.InformerFactory.Internal().V1alpha1().StorageVersions(),
	).Run(ctx, controllerContext.Stop)
	return nil, true, nil
}
