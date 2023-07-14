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

package setdefault

import (
	"context"
	"testing"
	"time"

	"k8s.io/klog/v2"

	storagev1alpha1 "k8s.io/api/storage/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/admission"
	admissiontesting "k8s.io/apiserver/pkg/admission/testing"
	"k8s.io/client-go/informers"
	api "k8s.io/kubernetes/pkg/apis/core"
	storageutil "k8s.io/kubernetes/pkg/apis/storage/util"
	"k8s.io/kubernetes/pkg/controller"
)

func TestAdmission(t *testing.T) {
	empty := ""
	foo := "foo"

	defaultClass1 := &storagev1alpha1.VolumeAttributesClass{
		TypeMeta: metav1.TypeMeta{
			Kind: "VolumeAttributesClass",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "default1",
			Annotations: map[string]string{
				storageutil.AlphaIsDefaultVolumeAttributesClassAnnotation: "true",
			},
		},
	}
	defaultClass2 := &storagev1alpha1.VolumeAttributesClass{
		TypeMeta: metav1.TypeMeta{
			Kind: "VolumeAttributesClass",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "default2",
			Annotations: map[string]string{
				storageutil.AlphaIsDefaultVolumeAttributesClassAnnotation: "true",
			},
		},
	}
	// Class that has explicit default = false
	classWithFalseDefault := &storagev1alpha1.VolumeAttributesClass{
		TypeMeta: metav1.TypeMeta{
			Kind: "VolumeAttributesClass",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "nondefault1",
			Annotations: map[string]string{
				storageutil.AlphaIsDefaultVolumeAttributesClassAnnotation: "false",
			},
		},
	}
	// Class with missing default annotation (=non-default)
	classWithNoDefault := &storagev1alpha1.VolumeAttributesClass{
		TypeMeta: metav1.TypeMeta{
			Kind: "VolumeAttributesClass",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "nondefault2",
		},
	}
	// Class with empty default annotation (=non-default)
	classWithEmptyDefault := &storagev1alpha1.VolumeAttributesClass{
		TypeMeta: metav1.TypeMeta{
			Kind: "VolumeAttributesClass",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "nondefault2",
			Annotations: map[string]string{
				storageutil.AlphaIsDefaultVolumeAttributesClassAnnotation: "",
			},
		},
	}
	classWithCreateTime1 := &storagev1alpha1.VolumeAttributesClass{
		TypeMeta: metav1.TypeMeta{
			Kind: "VolumeAttributesClass",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "default1",
			CreationTimestamp: metav1.NewTime(time.Date(2022, time.Month(1), 1, 0, 0, 0, 1, time.UTC)),
			Annotations: map[string]string{
				storageutil.AlphaIsDefaultVolumeAttributesClassAnnotation: "true",
			},
		},
	}
	classWithCreateTime2 := &storagev1alpha1.VolumeAttributesClass{
		TypeMeta: metav1.TypeMeta{
			Kind: "VolumeAttributesClass",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "default2",
			CreationTimestamp: metav1.NewTime(time.Date(2022, time.Month(1), 1, 0, 0, 0, 0, time.UTC)),
			Annotations: map[string]string{
				storageutil.AlphaIsDefaultVolumeAttributesClassAnnotation: "true",
			},
		},
	}

	claimWithClass := &api.PersistentVolumeClaim{
		TypeMeta: metav1.TypeMeta{
			Kind: "PersistentVolumeClaim",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "claimWithClass",
			Namespace: "ns",
		},
		Spec: api.PersistentVolumeClaimSpec{
			VolumeAttributesClassName: &foo,
		},
	}
	claimWithEmptyClass := &api.PersistentVolumeClaim{
		TypeMeta: metav1.TypeMeta{
			Kind: "PersistentVolumeClaim",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "claimWithEmptyClass",
			Namespace: "ns",
		},
		Spec: api.PersistentVolumeClaimSpec{
			VolumeAttributesClassName: &empty,
		},
	}
	claimWithNoClass := &api.PersistentVolumeClaim{
		TypeMeta: metav1.TypeMeta{
			Kind: "PersistentVolumeClaim",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "claimWithNoClass",
			Namespace: "ns",
		},
	}

	tests := []struct {
		name              string
		classes           []*storagev1alpha1.VolumeAttributesClass
		claim             *api.PersistentVolumeClaim
		expectError       bool
		expectedClassName string
	}{
		{
			"no default, no modification of PVCs",
			[]*storagev1alpha1.VolumeAttributesClass{classWithFalseDefault, classWithNoDefault, classWithEmptyDefault},
			claimWithNoClass,
			false,
			"",
		},
		{
			"one default, modify PVC with class=nil",
			[]*storagev1alpha1.VolumeAttributesClass{defaultClass1, classWithFalseDefault, classWithNoDefault, classWithEmptyDefault},
			claimWithNoClass,
			false,
			"default1",
		},
		{
			"one default, no modification of PVC with class=''",
			[]*storagev1alpha1.VolumeAttributesClass{defaultClass1, classWithFalseDefault, classWithNoDefault, classWithEmptyDefault},
			claimWithEmptyClass,
			false,
			"",
		},
		{
			"one default, no modification of PVC with class='foo'",
			[]*storagev1alpha1.VolumeAttributesClass{defaultClass1, classWithFalseDefault, classWithNoDefault, classWithEmptyDefault},
			claimWithClass,
			false,
			"foo",
		},
		{
			"two defaults, no modification of PVC with class=''",
			[]*storagev1alpha1.VolumeAttributesClass{defaultClass1, defaultClass2, classWithFalseDefault, classWithNoDefault, classWithEmptyDefault},
			claimWithEmptyClass,
			false,
			"",
		},
		{
			"two defaults, no modification of PVC with class='foo'",
			[]*storagev1alpha1.VolumeAttributesClass{defaultClass1, defaultClass2, classWithFalseDefault, classWithNoDefault, classWithEmptyDefault},
			claimWithClass,
			false,
			"foo",
		},
		{
			"two defaults with same creation time, choose the one with smaller name",
			[]*storagev1alpha1.VolumeAttributesClass{defaultClass1, defaultClass2, classWithFalseDefault, classWithNoDefault, classWithEmptyDefault},
			claimWithNoClass,
			false,
			defaultClass1.Name,
		},
		{
			"two defaults, choose the one with newer creation time",
			[]*storagev1alpha1.VolumeAttributesClass{classWithCreateTime1, classWithCreateTime2, classWithFalseDefault, classWithNoDefault, classWithEmptyDefault},
			claimWithNoClass,
			false,
			classWithCreateTime1.Name,
		},
	}

	for _, test := range tests {
		klog.V(4).Infof("starting test %q", test.name)

		// clone the claim, it's going to be modified
		claim := test.claim.DeepCopy()

		ctrl := newPlugin()
		informerFactory := informers.NewSharedInformerFactory(nil, controller.NoResyncPeriodFunc())
		ctrl.SetExternalKubeInformerFactory(informerFactory)
		for _, c := range test.classes {
			informerFactory.Storage().V1alpha1().VolumeAttributesClasses().Informer().GetStore().Add(c)
		}
		attrs := admission.NewAttributesRecord(
			claim, // new object
			nil,   // old object
			api.Kind("PersistentVolumeClaim").WithVersion("version"),
			claim.Namespace,
			claim.Name,
			api.Resource("persistentvolumeclaims").WithVersion("version"),
			"", // subresource
			admission.Create,
			&metav1.CreateOptions{},
			false, // dryRun
			nil,   // userInfo
		)
		err := admissiontesting.WithReinvocationTesting(t, ctrl).Admit(context.TODO(), attrs, nil)
		klog.Infof("Got %v", err)
		if err != nil && !test.expectError {
			t.Errorf("Test %q: unexpected error received: %v", test.name, err)
		}
		if err == nil && test.expectError {
			t.Errorf("Test %q: expected error and no error recevied", test.name)
		}

		class := ""
		if claim.Spec.VolumeAttributesClassName != nil {
			class = *claim.Spec.VolumeAttributesClassName
		}
		if test.expectedClassName != "" && test.expectedClassName != class {
			t.Errorf("Test %q: expected class name %q, got %q", test.name, test.expectedClassName, class)
		}
		if test.expectedClassName == "" && class != "" {
			t.Errorf("Test %q: expected class name %q, got %q", test.name, test.expectedClassName, class)
		}
	}
}
