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

package certificate

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"sort"

	"github.com/prometheus/client_golang/prometheus"

	certificates "k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	clientset "k8s.io/client-go/kubernetes"
	certificatesclient "k8s.io/client-go/kubernetes/typed/certificates/v1beta1"
	"k8s.io/client-go/util/certificate"
	kubeletconfig "k8s.io/kubernetes/pkg/kubelet/apis/config"
	"k8s.io/kubernetes/pkg/kubelet/metrics"
)

// NewKubeletServerCertificateManager creates a certificate manager for the kubelet when retrieving a server certificate
// or returns an error.
func NewKubeletServerCertificateManager(kubeClient clientset.Interface, kubeCfg *kubeletconfig.KubeletConfiguration, nodeName types.NodeName, getAddresses func() []v1.NodeAddress, certDirectory string) (certificate.Manager, error) {
	var certSigningRequestClient certificatesclient.CertificateSigningRequestInterface
	if kubeClient != nil && kubeClient.CertificatesV1beta1() != nil {
		certSigningRequestClient = kubeClient.CertificatesV1beta1().CertificateSigningRequests()
	}
	certificateStore, err := certificate.NewFileStore(
		"kubelet-server",
		certDirectory,
		certDirectory,
		kubeCfg.TLSCertFile,
		kubeCfg.TLSPrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize server certificate store: %v", err)
	}
	var certificateExpiration = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metrics.KubeletSubsystem,
			Subsystem: "certificate_manager",
			Name:      "server_expiration_seconds",
			Help:      "Gauge of the lifetime of a certificate. The value is the date the certificate will expire in seconds since January 1, 1970 UTC.",
		},
	)
	prometheus.MustRegister(certificateExpiration)

	getTemplate := func() *x509.CertificateRequest {
		hostnames, ips := addressesToHostnamesAndIPs(getAddresses())
		// don't return a template if we have no addresses to request for
		if len(hostnames) == 0 && len(ips) == 0 {
			return nil
		}
		return &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   fmt.Sprintf("system:node:%s", nodeName),
				Organization: []string{"system:nodes"},
			},
			DNSNames:    hostnames,
			IPAddresses: ips,
		}
	}

	m, err := certificate.NewManager(&certificate.Config{
		ClientFn: func(current *tls.Certificate) (certificatesclient.CertificateSigningRequestInterface, error) {
			return certSigningRequestClient, nil
		},
		GetTemplate: getTemplate,
		Usages: []certificates.KeyUsage{
			// https://tools.ietf.org/html/rfc5280#section-4.2.1.3
			//
			// Digital signature allows the certificate to be used to verify
			// digital signatures used during TLS negotiation.
			certificates.UsageDigitalSignature,
			// KeyEncipherment allows the cert/key pair to be used to encrypt
			// keys, including the symmetric keys negotiated during TLS setup
			// and used for data transfer.
			certificates.UsageKeyEncipherment,
			// ServerAuth allows the cert to be used by a TLS server to
			// authenticate itself to a TLS client.
			certificates.UsageServerAuth,
		},
		CertificateStore:      certificateStore,
		CertificateExpiration: certificateExpiration,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize server certificate manager: %v", err)
	}
	return m, nil
}

func addressesToHostnamesAndIPs(addresses []v1.NodeAddress) (dnsNames []string, ips []net.IP) {
	seenDNSNames := map[string]bool{}
	seenIPs := map[string]bool{}
	for _, address := range addresses {
		if len(address.Address) == 0 {
			continue
		}

		switch address.Type {
		case v1.NodeHostName:
			if ip := net.ParseIP(address.Address); ip != nil {
				seenIPs[address.Address] = true
			} else {
				seenDNSNames[address.Address] = true
			}
		case v1.NodeExternalIP, v1.NodeInternalIP:
			if ip := net.ParseIP(address.Address); ip != nil {
				seenIPs[address.Address] = true
			}
		case v1.NodeExternalDNS, v1.NodeInternalDNS:
			seenDNSNames[address.Address] = true
		}
	}

	for dnsName := range seenDNSNames {
		dnsNames = append(dnsNames, dnsName)
	}
	for ip := range seenIPs {
		ips = append(ips, net.ParseIP(ip))
	}

	// return in stable order
	sort.Strings(dnsNames)
	sort.Slice(ips, func(i, j int) bool { return ips[i].String() < ips[j].String() })

	return dnsNames, ips
}

// NewKubeletClientCertificateManager sets up a certificate manager without a
// client that can be used to sign new certificates (or rotate). If a CSR
// client is set later, it may begin rotating/renewing the client cert.
func NewKubeletClientCertificateManager(
	certDirectory string,
	nodeName types.NodeName,
	bootstrapCertData []byte,
	bootstrapKeyData []byte,
	certFile string,
	keyFile string,
	clientFn certificate.CSRClientFunc,
) (certificate.Manager, error) {

	certificateStore, err := certificate.NewFileStore(
		"kubelet-client",
		certDirectory,
		certDirectory,
		certFile,
		keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize client certificate store: %v", err)
	}
	var certificateExpiration = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metrics.KubeletSubsystem,
			Subsystem: "certificate_manager",
			Name:      "client_expiration_seconds",
			Help:      "Gauge of the lifetime of a certificate. The value is the date the certificate will expire in seconds since January 1, 1970 UTC.",
		},
	)
	prometheus.Register(certificateExpiration)

	m, err := certificate.NewManager(&certificate.Config{
		ClientFn: clientFn,
		Template: &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   fmt.Sprintf("system:node:%s", nodeName),
				Organization: []string{"system:nodes"},
			},
		},
		Usages: []certificates.KeyUsage{
			// https://tools.ietf.org/html/rfc5280#section-4.2.1.3
			//
			// DigitalSignature allows the certificate to be used to verify
			// digital signatures including signatures used during TLS
			// negotiation.
			certificates.UsageDigitalSignature,
			// KeyEncipherment allows the cert/key pair to be used to encrypt
			// keys, including the symmetric keys negotiated during TLS setup
			// and used for data transfer..
			certificates.UsageKeyEncipherment,
			// ClientAuth allows the cert to be used by a TLS client to
			// authenticate itself to the TLS server.
			certificates.UsageClientAuth,
		},

		// For backwards compatibility, the kubelet supports the ability to
		// provide a higher privileged certificate as initial data that will
		// then be rotated immediately. This code path is used by kubeadm on
		// the masters.
		BootstrapCertificatePEM: bootstrapCertData,
		BootstrapKeyPEM:         bootstrapKeyData,

		CertificateStore:      certificateStore,
		CertificateExpiration: certificateExpiration,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize client certificate manager: %v", err)
	}
	return m, nil
}
