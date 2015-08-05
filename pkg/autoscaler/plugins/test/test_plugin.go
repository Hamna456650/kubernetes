/*
Copyright 2015 The Kubernetes Authors All rights reserved.

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

package test

import (
	"fmt"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/autoscaler"
)

type TestAutoScalerPlugin struct {
	Tag     string
	Actions []autoscaler.ScalingAction
	Error   string
}

// Name returns the name of this test auto scaler plugin.
func (p *TestAutoScalerPlugin) Name() string {
	return p.Tag
}

// Assesses a policy with the advisors and returns the desired scaling actions.
func (p *TestAutoScalerPlugin) Assess(spec api.AutoScalerSpec, advisors []autoscaler.Advisor) ([]autoscaler.ScalingAction, error) {
	if len(p.Error) > 0 {
		return p.Actions, fmt.Errorf(p.Error)
	}

	return p.Actions, nil
}
