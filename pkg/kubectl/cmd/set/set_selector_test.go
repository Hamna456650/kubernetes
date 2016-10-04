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

package set

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/apis/batch"
	"k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/runtime"
)

func TestUpdateSelectorForObjectTypes(t *testing.T) {
	before := unversioned.LabelSelector{MatchLabels: map[string]string{"fee": "true"},
		MatchExpressions: []unversioned.LabelSelectorRequirement{
			{
				Key:      "foo",
				Operator: unversioned.LabelSelectorOpIn,
				Values:   []string{"on", "yes"},
			},
		}}

	rc := api.ReplicationController{}
	ser := api.Service{}
	dep := extensions.Deployment{Spec: extensions.DeploymentSpec{Selector: &before}}
	ds := extensions.DaemonSet{Spec: extensions.DaemonSetSpec{Selector: &before}}
	rs := extensions.ReplicaSet{Spec: extensions.ReplicaSetSpec{Selector: &before}}
	job := batch.Job{Spec: batch.JobSpec{Selector: &before}}
	pvc := api.PersistentVolumeClaim{Spec: api.PersistentVolumeClaimSpec{Selector: &before}}
	sa := api.ServiceAccount{}
	type args struct {
		obj      runtime.Object
		selector unversioned.LabelSelector
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "rc",
			args: args{
				obj:      &rc,
				selector: unversioned.LabelSelector{},
			},
			wantErr: false,
		},
		{name: "ser",
			args: args{
				obj:      &ser,
				selector: unversioned.LabelSelector{},
			},
			wantErr: false,
		},
		{name: "dep",
			args: args{
				obj:      &dep,
				selector: unversioned.LabelSelector{},
			},
			wantErr: false,
		},
		{name: "ds",
			args: args{
				obj:      &ds,
				selector: unversioned.LabelSelector{},
			},
			wantErr: false,
		},
		{name: "rs",
			args: args{
				obj:      &rs,
				selector: unversioned.LabelSelector{},
			},
			wantErr: false,
		},
		{name: "job",
			args: args{
				obj:      &job,
				selector: unversioned.LabelSelector{},
			},
			wantErr: false,
		},
		{name: "pvc - no updates",
			args: args{
				obj:      &pvc,
				selector: unversioned.LabelSelector{},
			},
			wantErr: true,
		},
		{name: "sa - no selector",
			args: args{
				obj:      &sa,
				selector: unversioned.LabelSelector{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		if err := updateSelectorForObject(tt.args.obj, tt.args.selector); (err != nil) != tt.wantErr {
			t.Errorf("%q. updateSelectorForObject() error = %v, wantErr %v", tt.name, err, tt.wantErr)
		}
	}
}

func TestUpdateNewSelectorValuesForObject(t *testing.T) {
	before := unversioned.LabelSelector{MatchLabels: map[string]string{"fee": "true"},
		MatchExpressions: []unversioned.LabelSelectorRequirement{
			{
				Key:      "foo",
				Operator: unversioned.LabelSelectorOpIn,
				Values:   []string{"on", "yes"},
			},
		}}

	dep := extensions.Deployment{Spec: extensions.DeploymentSpec{Selector: &before}}
	type args struct {
		obj      runtime.Object
		selector unversioned.LabelSelector
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "empty",
			args: args{
				obj: &dep,
				selector: unversioned.LabelSelector{
					MatchLabels:      map[string]string{},
					MatchExpressions: []unversioned.LabelSelectorRequirement{},
				},
			},
			wantErr: false,
		},
		{name: "label-only",
			args: args{
				obj: &dep,
				selector: unversioned.LabelSelector{
					MatchLabels:      map[string]string{"b": "u"},
					MatchExpressions: []unversioned.LabelSelectorRequirement{},
				},
			},
			wantErr: false,
		},
		{name: "expr-only",
			args: args{
				obj: &dep,
				selector: unversioned.LabelSelector{
					MatchLabels: map[string]string{},
					MatchExpressions: []unversioned.LabelSelectorRequirement{
						{
							Key:      "a",
							Operator: "In",
							Values:   []string{"x", "y"},
						},
					},
				},
			},
			wantErr: false,
		},
		{name: "both",
			args: args{
				obj: &dep,
				selector: unversioned.LabelSelector{
					MatchLabels: map[string]string{"b": "u"},
					MatchExpressions: []unversioned.LabelSelectorRequirement{
						{
							Key:      "a",
							Operator: "In",
							Values:   []string{"x", "y"},
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		if err := updateSelectorForObject(tt.args.obj, tt.args.selector); (err != nil) != tt.wantErr {
			t.Errorf("%q. updateSelectorForObject() error = %v, wantErr %v", tt.name, err, tt.wantErr)
		}

		assert.EqualValues(t, &tt.args.selector, dep.Spec.Selector, tt.name)

	}
}

func TestUpdateOldSelectorValuesForObject(t *testing.T) {
	ser := api.Service{Spec: api.ServiceSpec{Selector: map[string]string{"fee": "true"}}}
	type args struct {
		obj      runtime.Object
		selector unversioned.LabelSelector
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "empty",
			args: args{
				obj: &ser,
				selector: unversioned.LabelSelector{
					MatchLabels:      map[string]string{},
					MatchExpressions: []unversioned.LabelSelectorRequirement{},
				},
			},
			wantErr: false,
		},
		{name: "label-only",
			args: args{
				obj: &ser,
				selector: unversioned.LabelSelector{
					MatchLabels:      map[string]string{"fee": "false", "x": "y"},
					MatchExpressions: []unversioned.LabelSelectorRequirement{},
				},
			},
			wantErr: false,
		},
		{name: "expr-only - err",
			args: args{
				obj: &ser,
				selector: unversioned.LabelSelector{
					MatchLabels: map[string]string{},
					MatchExpressions: []unversioned.LabelSelectorRequirement{
						{
							Key:      "a",
							Operator: "In",
							Values:   []string{"x", "y"},
						},
					},
				},
			},
			wantErr: true,
		},
		{name: "both - err",
			args: args{
				obj: &ser,
				selector: unversioned.LabelSelector{
					MatchLabels: map[string]string{"b": "u"},
					MatchExpressions: []unversioned.LabelSelectorRequirement{
						{
							Key:      "a",
							Operator: "In",
							Values:   []string{"x", "y"},
						},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		err := updateSelectorForObject(tt.args.obj, tt.args.selector)
		if (err != nil) != tt.wantErr {
			t.Errorf("%q. updateSelectorForObject() error = %v, wantErr %v", tt.name, err, tt.wantErr)
		} else if !tt.wantErr {
			assert.EqualValues(t, tt.args.selector.MatchLabels, ser.Spec.Selector, tt.name)
		}
	}
}

func TestGetResourcesAndSelector(t *testing.T) {
	type args struct {
		args []string
	}
	tests := []struct {
		name          string
		args          args
		wantResources []string
		wantSelector  *unversioned.LabelSelector
		wantErr       bool
	}{
		{
			name:          "basic match",
			args:          args{args: []string{"rc/foo", "healthy=true"}},
			wantResources: []string{"rc/foo"},
			wantErr:       false,
			wantSelector: &unversioned.LabelSelector{
				MatchLabels:      map[string]string{"healthy": "true"},
				MatchExpressions: []unversioned.LabelSelectorRequirement{},
			},
		},
		{
			name:          "basic expression",
			args:          args{args: []string{"rc/foo", "buildType notin (debug, test)"}},
			wantResources: []string{"rc/foo"},
			wantErr:       false,
			wantSelector: &unversioned.LabelSelector{
				MatchLabels: map[string]string{},
				MatchExpressions: []unversioned.LabelSelectorRequirement{
					{
						Key:      "buildType",
						Operator: "NotIn",
						Values:   []string{"debug", "test"},
					},
				},
			},
		},
		{
			name:          "selector error",
			args:          args{args: []string{"rc/foo", "buildType notthis (debug, test)"}},
			wantResources: []string{"rc/foo"},
			wantErr:       true,
			wantSelector: &unversioned.LabelSelector{
				MatchLabels:      map[string]string{},
				MatchExpressions: []unversioned.LabelSelectorRequirement{},
			},
		},
	}
	for _, tt := range tests {
		gotResources, gotSelector, err := getResourcesAndSelector(tt.args.args)
		if err != nil {
			if !tt.wantErr {
				t.Errorf("%q. getResourcesAndSelector() error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			continue
		}
		if !reflect.DeepEqual(gotResources, tt.wantResources) {
			t.Errorf("%q. getResourcesAndSelector() gotResources = %v, want %v", tt.name, gotResources, tt.wantResources)
		}
		if !reflect.DeepEqual(gotSelector, tt.wantSelector) {
			t.Errorf("%q. getResourcesAndSelector() gotSelector = %v, want %v", tt.name, gotSelector, tt.wantSelector)
		}
	}
}
