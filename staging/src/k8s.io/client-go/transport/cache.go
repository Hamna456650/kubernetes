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

package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apimachinery/pkg/util/wait"
)

// TlsTransportCache caches TLS http.RoundTrippers different configurations. The
// same RoundTripper will be returned for configs with identical TLS options If
// the config has no custom TLS options, http.DefaultTransport is returned.
type tlsTransportCache struct {
	mu         sync.Mutex
	transports map[tlsCacheKey]http.RoundTripper
}

// DialerStopCh is stop channel that is passed down to dynamic cert dialer.
// It's exposed as variable for testing purposes to avoid testing for goroutine
// leakages.
var DialerStopCh = wait.NeverStop

const idleConnsPerHost = 25

var tlsCache = &tlsTransportCache{transports: make(map[tlsCacheKey]http.RoundTripper)}

type tlsCacheKey struct {
	insecure           bool
	caData             string
	certData           string
	keyData            string `datapolicy:"security-key"`
	certFile           string
	keyFile            string
	serverName         string
	nextProtos         string
	disableCompression bool
	// these functions are wrapped to allow them to be used as map keys
	getCert *GetCertHolder
	dial    *DialHolder
}

func (t tlsCacheKey) String() string {
	keyText := "<none>"
	if len(t.keyData) > 0 {
		keyText = "<redacted>"
	}
	return fmt.Sprintf("insecure:%v, caData:%#v, certData:%#v, keyData:%s, serverName:%s, disableCompression:%t, getCert:%p, dial:%p",
		t.insecure, t.caData, t.certData, keyText, t.serverName, t.disableCompression, t.getCert, t.dial)
}

func (c *tlsTransportCache) get(config *Config) (http.RoundTripper, error) {
	key, canCache, err := tlsConfigKey(config)
	if err != nil {
		return nil, err
	}

	if canCache {
		// Ensure we only create a single transport for the given TLS options
		c.mu.Lock()
		defer c.mu.Unlock()

		// See if we already have a custom transport for this config
		if t, ok := c.transports[key]; ok {
			return t, nil
		}
	}

	// Get the TLS options for this client config
	tlsConfig, err := TLSConfigFor(config)
	if err != nil {
		return nil, err
	}
	// The options didn't require a custom TLS config
	if tlsConfig == nil && config.DialHolder == nil && config.Proxy == nil {
		return http.DefaultTransport, nil
	}

	var dial func(ctx context.Context, network, address string) (net.Conn, error)
	if config.DialHolder != nil {
		dial = config.DialHolder.Dial
	} else {
		dial = (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext
	}

	// If we use are reloading files, we need to handle certificate rotation properly
	// TODO(jackkleeman): We can also add rotation here when config.HasCertCallback() is true
	if config.TLS.ReloadTLSFiles {
		dynamicCertDialer := certRotatingDialer(tlsConfig.GetClientCertificate, dial)
		tlsConfig.GetClientCertificate = dynamicCertDialer.GetClientCertificate
		dial = dynamicCertDialer.connDialer.DialContext
		go dynamicCertDialer.Run(DialerStopCh)
	}

	proxy := http.ProxyFromEnvironment
	if config.Proxy != nil {
		proxy = config.Proxy
	}

	h1tr := &http.Transport{
		Proxy:               proxy,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,
		MaxIdleConnsPerHost: idleConnsPerHost,
		DialContext:         dial,
		DisableCompression:  config.DisableCompression,
	}
	h2tr := h1tr.Clone()

	utilnet.SetOldTransportDefaults(h1tr)
	utilnet.SetTransportDefaults(h2tr)

	transport := &upgradeAwareTransport{
		h1: h1tr,
		h2: h2tr,
	}

	if canCache {
		// Cache a single transport for these options
		c.transports[key] = transport
	}

	return transport, nil
}

type upgradeAwareTransport struct {
	h1, h2 http.RoundTripper
}

func (tr *upgradeAwareTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if v := req.Header.Get("Upgrade"); v != "" {
		return tr.h1.RoundTrip(req)
	}
	return tr.h2.RoundTrip(req)
}

func (tr *upgradeAwareTransport) WrappedRoundTripper() http.RoundTripper {
	return tr.h2
}

// tlsConfigKey returns a unique key for tls.Config objects returned from TLSConfigFor
func tlsConfigKey(c *Config) (tlsCacheKey, bool, error) {
	// Make sure ca/key/cert content is loaded
	if err := loadTLSFiles(c); err != nil {
		return tlsCacheKey{}, false, err
	}

	if c.Proxy != nil {
		// cannot determine equality for functions
		return tlsCacheKey{}, false, nil
	}

	k := tlsCacheKey{
		insecure:           c.TLS.Insecure,
		caData:             string(c.TLS.CAData),
		serverName:         c.TLS.ServerName,
		nextProtos:         strings.Join(c.TLS.NextProtos, ","),
		disableCompression: c.DisableCompression,
		getCert:            c.TLS.GetCertHolder,
		dial:               c.DialHolder,
	}

	if c.TLS.ReloadTLSFiles {
		k.certFile = c.TLS.CertFile
		k.keyFile = c.TLS.KeyFile
	} else {
		k.certData = string(c.TLS.CertData)
		k.keyData = string(c.TLS.KeyData)
	}

	return k, true, nil
}
