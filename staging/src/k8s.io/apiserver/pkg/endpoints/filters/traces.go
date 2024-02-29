/*
Copyright 2021 The Kubernetes Authors.

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

package filters

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"

	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	tracing "k8s.io/component-base/tracing"
)

// WithTracing adds tracing to requests if the incoming request is sampled
func WithTracing(handler http.Handler, tp trace.TracerProvider) http.Handler {
	opts := []otelhttp.Option{
		otelhttp.WithPropagators(tracing.Propagators()),
		otelhttp.WithPublicEndpointFn(reqHasAnonymousUser),
		otelhttp.WithTracerProvider(tp),
	}
	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add the http.target attribute to the otelhttp span
		// Workaround for https://github.com/open-telemetry/opentelemetry-go-contrib/issues/3743
		if r.URL != nil {
			trace.SpanFromContext(r.Context()).SetAttributes(semconv.HTTPTarget(r.URL.RequestURI()))
		}
		handler.ServeHTTP(w, r)
	})
	// With Noop TracerProvider, the otelhttp still handles context propagation.
	// See https://github.com/open-telemetry/opentelemetry-go/tree/main/example/passthrough
	return otelhttp.NewHandler(wrappedHandler, "KubernetesAPI", opts...)
}

func reqHasAnonymousUser(req *http.Request) bool {
	user, ok := genericapirequest.UserFrom(req.Context())
	if !ok {
		return true
	}
	return isAnonymousUser(user)
}
