/*
Copyright 2014 The Kubernetes Authors All rights reserved.

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
// components.  This includes cluster controller

package app

import (
	"net"
	"net/http"
	"net/http/pprof"
	"strconv"

	"k8s.io/kubernetes/federation/cmd/federated-controller-manager/app/options"
	"k8s.io/kubernetes/pkg/client/restclient"

	federationclientset "k8s.io/kubernetes/federation/client/clientset_generated/federation_release_1_3"
	clustercontroller "k8s.io/kubernetes/federation/pkg/federated-controller/cluster"
	"k8s.io/kubernetes/pkg/client/unversioned/clientcmd"
	"k8s.io/kubernetes/pkg/healthz"
	"k8s.io/kubernetes/pkg/util/configz"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// NewControllerManagerCommand creates a *cobra.Command object with default parameters
func NewControllerManagerCommand() *cobra.Command {
	s := options.NewCMServer()
	s.AddFlags(pflag.CommandLine)
	cmd := &cobra.Command{
		Use: "federated-controller-manager",
		Long: `The federated controller manager is a daemon that embeds
the core control loops shipped with ubernetes. In applications of robotics and
automation, a control loop is a non-terminating loop that regulates the state of
the system. In kubernetes federation, a controller is a control loop that watches
the shared state of the cluster replicaset through the apiserver and makes changes
attempting to move the current state towards the desired state.`,
		Run: func(cmd *cobra.Command, args []string) {
		},
	}

	return cmd
}

// Run runs the CMServer.  This should never exit.
func Run(s *options.CMServer) error {
	if c, err := configz.New("componentconfig"); err == nil {
		c.Set(s.ControllerManagerConfiguration)
	} else {
		glog.Errorf("unable to register configz: %s", err)
	}
	restClientCfg, err := clientcmd.BuildConfigFromFlags(s.Master, s.ApiServerconfig)
	if err != nil {
		return err
	}

	// Override restClientCfg qps/burst settings from flags
	restClientCfg.QPS = s.FederatedAPIQPS
	restClientCfg.Burst = s.FederatedAPIBurst

	go func() {
		mux := http.NewServeMux()
		healthz.InstallHandler(mux)
		if s.EnableProfiling {
			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		}
		mux.Handle("/metrics", prometheus.Handler())

		server := &http.Server{
			Addr:    net.JoinHostPort(s.Address, strconv.Itoa(s.Port)),
			Handler: mux,
		}
		glog.Fatal(server.ListenAndServe())
	}()

	run := func() {
		err := StartControllers(s, restClientCfg)
		glog.Fatalf("error running controllers: %v", err)
		panic("unreachable")
	}
	run()
	panic("unreachable")
}

func StartControllers(s *options.CMServer, restClientCfg *restclient.Config) error {
	federationClientSet := federationclientset.NewForConfigOrDie(restclient.AddUserAgent(restClientCfg, "cluster-controller"))
	go clustercontroller.NewclusterController(federationClientSet, s.ClusterMonitorPeriod.Duration).Run()
	select {}
}
