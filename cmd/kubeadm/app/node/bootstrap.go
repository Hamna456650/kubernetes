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

package node

import (
	"fmt"
	"os"
	"sync"
	"time"

	kubeadmapi "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm"
	kubeadmutil "k8s.io/kubernetes/cmd/kubeadm/app/util"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	certclient "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/certificates/unversioned"
	"k8s.io/kubernetes/pkg/client/unversioned/clientcmd"
	"k8s.io/kubernetes/pkg/types"
	"k8s.io/kubernetes/pkg/util/wait"
)

// ConnectionDetails represents a master API endpoint connection
type ConnectionDetails struct {
	CertClient *certclient.CertificatesClient
	Endpoint   string
	CACert     []byte
	NodeName   types.NodeName
}

// retryTimeout between the subsequent attempts to connect
// to an API endpoint
const retryTimeout = 5

// EstablishMasterConnection establishes a connection with exactly one of the provided API endpoints.
// The function builds a client for every endpoint and concurrently keeps trying to connect to any one
// of the provided endpoints. Blocks until at least one connection is established, then it stops the
// connection attempts for other endpoints.
func EstablishMasterConnection(s *kubeadmapi.NodeConfiguration, clusterInfo *kubeadmapi.ClusterInfo) (*ConnectionDetails, error) {
	hostName, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("<node/bootstrap> failed to get node hostname [%v]", err)
	}
	// TODO(phase1+) https://github.com/kubernetes/kubernetes/issues/33641
	nodeName := types.NodeName(hostName)

	endpoints := clusterInfo.Endpoints
	caCert := []byte(clusterInfo.CertificateAuthorities[0])

	stopChan := make(chan struct{})
	result := make(chan *ConnectionDetails)
	var wg sync.WaitGroup
	for _, endpoint := range endpoints {
		clientSet, err := createClients(caCert, endpoint, s.Secrets.BearerToken, nodeName)
		if err != nil {
			fmt.Printf("<node/bootstrap> warning: %s. Skipping endpoint %s\n", err, endpoint)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			wait.Until(func() {
				fmt.Printf("<node/bootstrap> trying to connect to endpoint %s\n", endpoint)
				if err := clientSet.CoreClient.Get().AbsPath("version").Do().Error(); err != nil {
					fmt.Printf("<node/bootstrap> failed to connect to %s: %v\n", endpoint, err)
					return
				}
				if err := checkCertsAPI(clientSet.DiscoveryClient); err != nil {
					fmt.Printf("<node/bootstrap> certificate API check failed %s: %v\n", endpoint, err)
					return
				}
				fmt.Printf("<node/bootstrap> successfully established connection with endpoint %s\n", endpoint)
				// connection established, stop all wait threads
				close(stopChan)
				result <- &ConnectionDetails{
					CertClient: clientSet.CertificatesClient,
					Endpoint:   endpoint,
					CACert:     caCert,
					NodeName:   nodeName,
				}
			}, retryTimeout*time.Second, stopChan)
		}()
	}

	go func() {
		wg.Wait()
		// all wait.Until() calls have finished now
		close(result)
	}()

	establishedConnection, ok := <-result
	if !ok {
		return nil, fmt.Errorf("<node/bootstrap> failed to create bootstrap clients " +
			"for any of the provided API endpoints")
	}
	return establishedConnection, nil
}

// Creates a set of clients for this endpoint
func createClients(caCert []byte, endpoint, token string, nodeName types.NodeName) (*clientset.Clientset, error) {
	bareClientConfig := kubeadmutil.CreateBasicClientConfig("kubernetes", endpoint, caCert)
	bootstrapClientConfig, err := clientcmd.NewDefaultClientConfig(
		*kubeadmutil.MakeClientConfigWithToken(
			bareClientConfig, "kubernetes", fmt.Sprintf("kubelet-%s", nodeName), token,
		),
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create API client configuration [%v]", err)
	}
	clientSet, err := clientset.NewForConfig(bootstrapClientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create clients for the API endpoint %s [%v]", endpoint, err)
	}
	return clientSet, nil
}
