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

package master

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"strconv"

	netutil "k8s.io/apimachinery/pkg/util/net"
	kubeadmapi "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm"
	kubeadmapiext "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm/v1alpha1"
	kubeadmutil "k8s.io/kubernetes/cmd/kubeadm/app/util"
	cmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"
	"k8s.io/kubernetes/pkg/util/uuid"
)

func PrepareTokenDiscovery(d *kubeadmapi.TokenDiscovery) error {
	if len(d.Addresses) == 0 {
		ip, err := netutil.ChooseHostInterface()
		if err != nil {
			return err
		}
		d.Addresses = []string{ip.String() + ":" + strconv.Itoa(kubeadmapiext.DefaultDiscoveryBindPort)}
	}
	if err := kubeadmutil.GenerateTokenIfNeeded(d); err != nil {
		return fmt.Errorf("failed to generate token(s) [%v]", err)
	}
	return nil
}

func CreateTokenAuthFile(bt string) error {
	tokenAuthFilePath := path.Join(kubeadmapi.GlobalEnvParams.HostPKIPath, "tokens.csv")
	if err := os.MkdirAll(kubeadmapi.GlobalEnvParams.HostPKIPath, 0700); err != nil {
		return fmt.Errorf("failed to create directory %q [%v]", kubeadmapi.GlobalEnvParams.HostPKIPath, err)
	}
	serialized := []byte(fmt.Sprintf("%s,kubeadm-node-csr,%s,system:kubelet-bootstrap\n", bt, uuid.NewUUID()))
	// DumpReaderToFile create a file with mode 0600
	if err := cmdutil.DumpReaderToFile(bytes.NewReader(serialized), tokenAuthFilePath); err != nil {
		return fmt.Errorf("failed to save token auth file (%q) [%v]", tokenAuthFilePath, err)
	}
	return nil
}
