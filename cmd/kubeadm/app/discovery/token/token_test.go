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

package token

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"k8s.io/api/core/v1"
	bootstrapapi "k8s.io/client-go/tools/bootstrap/token/api"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	kubeadmapi "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm"
	kubeconfigutil "k8s.io/kubernetes/cmd/kubeadm/app/util/kubeconfig"
	"k8s.io/kubernetes/cmd/kubeadm/app/util/pubkeypin"
)

// testCertPEM is a simple self-signed test certificate issued with the openssl CLI:
// openssl req -new -newkey rsa:2048 -days 36500 -nodes -x509 -keyout /dev/null -out test.crt
const testCertPEM = `
-----BEGIN CERTIFICATE-----
MIIDRDCCAiygAwIBAgIJAJgVaCXvC6HkMA0GCSqGSIb3DQEBBQUAMB8xHTAbBgNV
BAMTFGt1YmVhZG0ta2V5cGlucy10ZXN0MCAXDTE3MDcwNTE3NDMxMFoYDzIxMTcw
NjExMTc0MzEwWjAfMR0wGwYDVQQDExRrdWJlYWRtLWtleXBpbnMtdGVzdDCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK0ba8mHU9UtYlzM1Own2Fk/XGjR
J4uJQvSeGLtz1hID1IA0dLwruvgLCPadXEOw/f/IWIWcmT+ZmvIHZKa/woq2iHi5
+HLhXs7aG4tjKGLYhag1hLjBI7icqV7ovkjdGAt9pWkxEzhIYClFMXDjKpMSynu+
YX6nZ9tic1cOkHmx2yiZdMkuriRQnpTOa7bb03OC1VfGl7gHlOAIYaj4539WCOr8
+ACTUMJUFEHcRZ2o8a/v6F9GMK+7SC8SJUI+GuroXqlMAdhEv4lX5Co52enYaClN
+D9FJLRpBv2YfiCQdJRaiTvCBSxEFz6BN+PtP5l2Hs703ZWEkOqCByM6HV8CAwEA
AaOBgDB+MB0GA1UdDgQWBBRQgUX8MhK2rWBWQiPHWcKzoWDH5DBPBgNVHSMESDBG
gBRQgUX8MhK2rWBWQiPHWcKzoWDH5KEjpCEwHzEdMBsGA1UEAxMUa3ViZWFkbS1r
ZXlwaW5zLXRlc3SCCQCYFWgl7wuh5DAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEB
BQUAA4IBAQCaAUif7Pfx3X0F08cxhx8/Hdx4jcJw6MCq6iq6rsXM32ge43t8OHKC
pJW08dk58a3O1YQSMMvD6GJDAiAfXzfwcwY6j258b1ZlI9Ag0VokvhMl/XfdCsdh
AWImnL1t4hvU5jLaImUUMlYxMcSfHBGAm7WJIZ2LdEfg6YWfZh+WGbg1W7uxLxk6
y4h5rWdNnzBHWAGf7zJ0oEDV6W6RSwNXtC0JNnLaeIUm/6xdSddJlQPwUv8YH4jX
c1vuFqTnJBPcb7W//R/GI2Paicm1cmns9NLnPR35exHxFTy+D1yxmGokpoPMdife
aH+sfuxT8xeTPb3kjzF9eJTlnEquUDLM
-----END CERTIFICATE-----`

// testCertPEM is a simple self-signed test certificate issued with the openssl CLI:
// openssl req -new -newkey rsa:2048 -days 36500 -nodes -x509 -keyout /dev/null -out test.crt
const testCertPEM2 = `
-----BEGIN CERTIFICATE-----
MIIDRDCCAiygAwIBAgIJAJgVaCXvC6HkMA0GCSqGSIb3DQEBBQUAMB8xHTAbBgNV
BAMTFGt1YmVhZG0ta2V5cGlucy10ZXN0MCAXDTE3MDcwNTE3NDMxMFoYDzIxMTcw
NjExMTc0MzEwWjAfMR0wGwYDVQQDExRrdWJlYWRtLWtleXBpbnMtdGVzdDCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK0ba8mHU9UtYlzM1Own2Fk/XGjR
J4uJQvSeGLtz1hID1IA0dLwruvgLCPadXEOw/f/IWIWcmT+ZmvIHZKa/woq2iHi5
+HLhXs7aG4tjKGLYhag1hLjBI7icqV7ovkjdGAt9pWkxEzhIYClFMXDjKpMSynu+
YX6nZ9tic1cOkHmx2yiZdMkuriRQnpTOa7bb03OC1VfGl7gHlOAIYaj4539WCOr8
+ACTUMJUFEHcRZ2o8a/v6F9GMK+7SC8SJUI+GuroXqlMAdhEv4lX5Co52enYaClN
+D9FJLRpBv2YfiCQdJRaiTvCBSxEFz6BN+PtP5l2Hs703ZWEkOqCByM6HV8CAwEA
AaOBgDB+MB0GA1UdDgQWBBRQgUX8MhK2rWBWQiPHWcKzoWDH5DBPBgNVHSMESDBG
gBRQgUX8MhK2rWBWQiPHWcKzoWDH5KEjpCEwHzEdMBsGA1UEAxMUa3ViZWFkbS1r
ZXlwaW5zLXRlc3SCCQCYFWgl7wuh5DAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEB
BQUAA4IBAQCaAUif7Pfx3X0F08cxhx8/Hdx4jcJw6MCq6iq6rsXM32ge43t8OHKC
pJW08dk58a3O1YQSMMvD6GJDAiAfXzfwcwY6j258b1ZlI9Ag0VokvhMl/XfdCsdh
AWImnL1t4hvU5jLaImUUMlYxMcSfHBGAm7WJIZ2LdEfg6YWfZh+WGbg1W7uxLxk6
y4h5rWdNnzBHWAGf7zJ0oEDV6W6RSwNXtC0JNnLaeIUm/6xdSddJlQPwUv8YH4jX
c1vuFqTnJBPcb7W//R/GI2Paicm1cmns9NLnPR35exHxFTy+D1yxmGokpoPMdife
aH+sfuxT8xeTPb3kjzF9eJTlnEquUDLM
-----END CERTIFICATE-----`

// expectedHash can be verified using the openssl CLI:
// openssl x509 -pubkey -in test.crt openssl rsa -pubin -outform der 2>&/dev/null | openssl dgst -sha256 -hex
const expectedHash2 = `sha256:345959acb2c3b2feb87d281961c893f62a314207ef02599f1cc4a5fb255480b3`

const (
	userID      = "johndoe"
	userSecret  = "John's secret"
	validConfig = `
apiVersion: v1
kind: Config
current-context: example-context
clusters:
- cluster:
    api-version: v1
    server: https://example.com:8000
  name: example-cluster
contexts:
- context:
    cluster: example-cluster
    namespace: example-ns
    user: example-user
  name: example-context
preferences:
  colors: true
users:
- name: example-user
  user:
    token: example-user-token`
	validToken = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImpvaG5kb2UifQ..VoFkSb03kjPpER6qoyr4Gv3idDJE54xRvQUHjtwxt-c"
)

func TestFetchInsecureClusterInfo(t *testing.T) {
	const (
		endpoint = "E"
		cluster  = "C"
	)
	resultCluster, client, server, err := fetchInsecureClusterInfo(endpoint, cluster)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if resultCluster != cluster {
		t.Errorf("unexpected cluster name: %v", resultCluster)
	}
	if server != "https://"+endpoint {
		t.Errorf("unexpected server: %v", server)
	}
	if client == nil {
		t.Error("client should not be nil")
	}
}

func TestValidateAndLoadInsecureConfig(t *testing.T) {
	user := &kubeadmapi.BootstrapTokenString{
		ID:     "johndoe",
		Secret: "John's secret",
	}
	noSecretUser := &kubeadmapi.BootstrapTokenString{
		ID:     "johndoe",
		Secret: "",
	}
	emptyUser := &kubeadmapi.BootstrapTokenString{
		ID:     "",
		Secret: "",
	}
	tests := []struct {
		description string
		clusterInfo *v1.ConfigMap
		token       *kubeadmapi.BootstrapTokenString
		expectError bool
	}{
		{
			description: "Valid config is loaded",
			expectError: false,
			token:       user,
			clusterInfo: &v1.ConfigMap{
				Data: map[string]string{
					bootstrapapi.KubeConfigKey:                   validConfig,
					bootstrapapi.JWSSignatureKeyPrefix + user.ID: validToken,
				},
			},
		},
		{
			description: "Empty KubeConfig returns error",
			expectError: true,
			token:       emptyUser,
			clusterInfo: &v1.ConfigMap{
				Data: map[string]string{
					bootstrapapi.KubeConfigKey: "",
				},
			},
		},
		{
			description: "Missing KubeConfig returns error",
			expectError: true,
			token:       emptyUser,
			clusterInfo: &v1.ConfigMap{
				Data: map[string]string{},
			},
		},
		{
			description: "Missing JWSSignatureKeyPrefix returns error",
			expectError: true,
			token:       noSecretUser,
			clusterInfo: &v1.ConfigMap{
				Data: map[string]string{
					bootstrapapi.KubeConfigKey: "XYZ",
				},
			},
		},
		{
			description: "Empty JWSSignatureKeyPrefix returns error",
			expectError: true,
			token:       noSecretUser,
			clusterInfo: &v1.ConfigMap{
				Data: map[string]string{
					bootstrapapi.KubeConfigKey:                           "#$%",
					bootstrapapi.JWSSignatureKeyPrefix + noSecretUser.ID: "",
				},
			},
		},
		{
			description: "Mismatching signature returns error",
			expectError: true,
			token:       user,
			clusterInfo: &v1.ConfigMap{
				Data: map[string]string{
					bootstrapapi.KubeConfigKey:                   "#$%",
					bootstrapapi.JWSSignatureKeyPrefix + user.ID: "#$%",
				},
			},
		},
		{
			description: "Invalid but signed KubeConfig returns error",
			expectError: true,
			token:       user,
			clusterInfo: &v1.ConfigMap{
				Data: map[string]string{
					bootstrapapi.KubeConfigKey:                   "%$^*",
					bootstrapapi.JWSSignatureKeyPrefix + user.ID: "eyJhbGciOiJIUzI1NiIsImtpZCI6ImpvaG5kb2UifQ..zGIAkO6lW_-9a2FVLjYwfAS52VcJrK-8F52PoPPHy_M",
				},
			},
		},
	}

	for _, test := range tests {
		config, err := validateAndLoadInsecureConfig(test.clusterInfo, test.token)
		if err == nil && test.expectError {
			t.Errorf("%s: unexpected success", test.description)
		} else if err != nil && test.expectError == false {
			t.Errorf("%s: unexpected error on case: %v", test.description, err)
		} else if err == nil && test.expectError == false && config == nil {
			t.Errorf("%s: no error and no config", test.description)
		}
	}
}

func prepareTestConfig(clusters int) *clientcmdapi.Config {
	config := clientcmdapi.NewConfig()
	for i := 0; i < clusters; i++ {
		name := fmt.Sprintf("C%d", i+1)
		config.Clusters[name] = clientcmdapi.NewCluster()
		config.Clusters[name].CertificateAuthorityData = []byte(testCertPEM2)
	}
	return config
}

func TestFetchSecureClient(t *testing.T) {
	const (
		endpoint = "E"
		cluster  = "C"
	)

	pubkeyset := pubkeypin.NewSet()
	emptyConfig := prepareTestConfig(0)
	oneClusterConfig := prepareTestConfig(1)
	twoClusterConfig := prepareTestConfig(2)

	_, err := fetchSecureClient(endpoint, emptyConfig, cluster, pubkeyset)
	if err == nil {
		t.Error("unexpected success")
	}

	_, err = fetchSecureClient(endpoint, oneClusterConfig, cluster, pubkeyset)
	if err == nil {
		t.Error("unexpected success")
	}

	_, err = fetchSecureClient(endpoint, twoClusterConfig, cluster, pubkeyset)
	if err == nil {
		t.Error("unexpected success")
	}

	err = pubkeyset.Allow(expectedHash2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = fetchSecureClient(endpoint, emptyConfig, cluster, pubkeyset)
	if err == nil {
		t.Error("unexpected success")
	}

	_, err = fetchSecureClient(endpoint, twoClusterConfig, cluster, pubkeyset)
	if err == nil {
		t.Error("unexpected success")
	}

	client, err := fetchSecureClient(endpoint, oneClusterConfig, cluster, pubkeyset)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("fetchSecureClient returned success, but no client")
	}
}

func TestLoadSecureConfig(t *testing.T) {
	tests := []struct {
		description         string
		expectError         bool
		secureClusterInfo   *v1.ConfigMap
		insecureClusterInfo *v1.ConfigMap
	}{
		{
			description: "Mismatching configs return error",
			expectError: true,
			secureClusterInfo: &v1.ConfigMap{
				Data: map[string]string{
					bootstrapapi.KubeConfigKey: "ABC",
				},
			},
			insecureClusterInfo: &v1.ConfigMap{
				Data: map[string]string{
					bootstrapapi.KubeConfigKey: "XYZ",
				},
			},
		},
		{
			description: "Matching invalid configs result in error",
			expectError: true,
			secureClusterInfo: &v1.ConfigMap{
				Data: map[string]string{
					bootstrapapi.KubeConfigKey: "%$^*",
				},
			},
			insecureClusterInfo: &v1.ConfigMap{
				Data: map[string]string{
					bootstrapapi.KubeConfigKey: "%$^*",
				},
			},
		},
		{
			description: "Matching valid configs gets loaded",
			expectError: false,
			secureClusterInfo: &v1.ConfigMap{
				Data: map[string]string{
					bootstrapapi.KubeConfigKey:                  validConfig,
					bootstrapapi.JWSSignatureKeyPrefix + userID: validToken,
				},
			},
			insecureClusterInfo: &v1.ConfigMap{
				Data: map[string]string{
					bootstrapapi.KubeConfigKey: validConfig,
				},
			},
		},
	}

	for _, test := range tests {
		config, err := loadSecureConfig(test.secureClusterInfo, test.insecureClusterInfo)
		if err != nil && !test.expectError {
			t.Errorf("%s: unexpected error: %v", test.description, err)
		} else if err == nil && test.expectError {
			t.Errorf("%s: unexpected success", test.description)
		} else if err == nil && config == nil && !test.expectError {
			t.Errorf("%s: returned success, but no config", test.description)
		}
	}
}

func TestRunForEndpointsAndReturnFirst(t *testing.T) {
	tests := []struct {
		endpoints        []string
		expectedEndpoint string
	}{
		{
			endpoints:        []string{"1", "2", "3"},
			expectedEndpoint: "1",
		},
		{
			endpoints:        []string{"6", "5"},
			expectedEndpoint: "5",
		},
		{
			endpoints:        []string{"10", "4"},
			expectedEndpoint: "4",
		},
	}
	for _, rt := range tests {
		returnKubeConfig, err := runForEndpointsAndReturnFirst(rt.endpoints, 5*time.Minute, func(endpoint string) (*clientcmdapi.Config, error) {
			timeout, _ := strconv.Atoi(endpoint)
			time.Sleep(time.Second * time.Duration(timeout))
			return kubeconfigutil.CreateBasic(endpoint, "foo", "foo", []byte{}), nil
		})
		if err != nil {
			t.Errorf("unexpected error: %v for endpoint %s", err, rt.expectedEndpoint)
		}
		endpoint := returnKubeConfig.Clusters[returnKubeConfig.Contexts[returnKubeConfig.CurrentContext].Cluster].Server
		if endpoint != rt.expectedEndpoint {
			t.Errorf(
				"failed TestRunForEndpointsAndReturnFirst:\n\texpected: %s\n\t  actual: %s",
				endpoint,
				rt.expectedEndpoint,
			)
		}
	}
}

func TestParsePEMCert(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		input       []byte
		expectValid bool
	}{
		{"invalid certificate data", []byte{0}, false},
		{"certificate with junk appended", []byte(testCertPEM + "\nABC"), false},
		{"multiple certificates", []byte(testCertPEM + "\n" + testCertPEM), false},
		{"valid", []byte(testCertPEM), true},
	} {
		cert, err := parsePEMCert(testCase.input)
		if testCase.expectValid {
			if err != nil {
				t.Errorf("failed TestParsePEMCert(%s): unexpected error %v", testCase.name, err)
			}
			if cert == nil {
				t.Errorf("failed TestParsePEMCert(%s): returned nil", testCase.name)
			}
		} else {
			if err == nil {
				t.Errorf("failed TestParsePEMCert(%s): expected an error", testCase.name)
			}
			if cert != nil {
				t.Errorf("failed TestParsePEMCert(%s): expected not to get a certificate back, but got one", testCase.name)
			}
		}
	}
}
