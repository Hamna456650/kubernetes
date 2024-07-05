/*
Copyright 2023 The Kubernetes Authors.

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

package api

import (
	"reflect"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/fuzzer"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/install"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/apitesting/roundtrip"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	_ "k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/sets"
)

var groups = []runtime.SchemeBuilder{
	apiextensionsv1.SchemeBuilder,
	apiextensionsv1beta1.SchemeBuilder,
}

func TestCompatibility(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, builder := range groups {
		require.NoError(t, builder.AddToScheme(scheme))
	}

	opts := roundtrip.NewCompatibilityTestOptions(scheme)

	// Fill unstructured JSON field types
	opts.FillFuncs = map[reflect.Type]roundtrip.FillFunc{
		reflect.TypeOf(&apiextensionsv1.JSON{}): func(s string, i int, obj interface{}) {
			obj.(*apiextensionsv1.JSON).Raw = []byte(strconv.Quote(s + "Value"))
		},
		reflect.TypeOf(&apiextensionsv1beta1.JSON{}): func(s string, i int, obj interface{}) {
			obj.(*apiextensionsv1beta1.JSON).Raw = []byte(strconv.Quote(s + "Value"))
		},
	}

	opts.Complete(t)

	// limit to types in apiextensions.k8s.io
	filteredKinds := []schema.GroupVersionKind{}
	for _, gvk := range opts.Kinds {
		if gvk.Group == apiextensionsv1.SchemeGroupVersion.Group {
			filteredKinds = append(filteredKinds, gvk)
		}
	}
	opts.Kinds = filteredKinds

	opts.Run(t)
}

func TestRoundtripToUnstructured(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	roundtrip.RoundtripToUnstructured(t, scheme, fuzzer.Funcs,
		sets.New(
			apiextensionsv1.SchemeGroupVersion.WithKind("CreateOptions"),
			apiextensionsv1.SchemeGroupVersion.WithKind("PatchOptions"),
			apiextensionsv1.SchemeGroupVersion.WithKind("UpdateOptions"),
			apiextensionsv1beta1.SchemeGroupVersion.WithKind("CreateOptions"),
			apiextensionsv1beta1.SchemeGroupVersion.WithKind("PatchOptions"),
			apiextensionsv1beta1.SchemeGroupVersion.WithKind("UpdateOptions"),
		),
		sets.New(
			apiextensionsv1.SchemeGroupVersion.WithKind("ConversionReview"),
			apiextensionsv1beta1.SchemeGroupVersion.WithKind("ConversionReview"),
		),
	)
}
