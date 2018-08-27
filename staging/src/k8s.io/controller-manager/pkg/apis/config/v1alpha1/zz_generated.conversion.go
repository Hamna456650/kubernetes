// +build !ignore_autogenerated

/*
Copyright The Kubernetes Authors.

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

// Code generated by conversion-gen. DO NOT EDIT.

package v1alpha1

import (
	unsafe "unsafe"

	configv1alpha1 "k8s.io/apimachinery/pkg/apis/config/v1alpha1"
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"
	apisconfigv1alpha1 "k8s.io/apiserver/pkg/apis/config/v1alpha1"
	config "k8s.io/controller-manager/pkg/apis/config"
)

func init() {
	localSchemeBuilder.Register(RegisterConversions)
}

// RegisterConversions adds conversion functions to the given scheme.
// Public to allow building arbitrary schemes.
func RegisterConversions(s *runtime.Scheme) error {
	if err := s.AddGeneratedConversionFunc((*GenericControllerManagerConfiguration)(nil), (*config.GenericControllerManagerConfiguration)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_GenericControllerManagerConfiguration_To_config_GenericControllerManagerConfiguration(a.(*GenericControllerManagerConfiguration), b.(*config.GenericControllerManagerConfiguration), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*config.GenericControllerManagerConfiguration)(nil), (*GenericControllerManagerConfiguration)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_config_GenericControllerManagerConfiguration_To_v1alpha1_GenericControllerManagerConfiguration(a.(*config.GenericControllerManagerConfiguration), b.(*GenericControllerManagerConfiguration), scope)
	}); err != nil {
		return err
	}
	if err := s.AddConversionFunc((*config.GenericControllerManagerConfiguration)(nil), (*GenericControllerManagerConfiguration)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_config_GenericControllerManagerConfiguration_To_v1alpha1_GenericControllerManagerConfiguration(a.(*config.GenericControllerManagerConfiguration), b.(*GenericControllerManagerConfiguration), scope)
	}); err != nil {
		return err
	}
	if err := s.AddConversionFunc((*GenericControllerManagerConfiguration)(nil), (*config.GenericControllerManagerConfiguration)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_GenericControllerManagerConfiguration_To_config_GenericControllerManagerConfiguration(a.(*GenericControllerManagerConfiguration), b.(*config.GenericControllerManagerConfiguration), scope)
	}); err != nil {
		return err
	}
	return nil
}

func autoConvert_v1alpha1_GenericControllerManagerConfiguration_To_config_GenericControllerManagerConfiguration(in *GenericControllerManagerConfiguration, out *config.GenericControllerManagerConfiguration, s conversion.Scope) error {
	out.Port = in.Port
	out.Address = in.Address
	out.MinResyncPeriod = in.MinResyncPeriod
	if err := configv1alpha1.Convert_v1alpha1_ClientConnectionConfiguration_To_config_ClientConnectionConfiguration(&in.ClientConnection, &out.ClientConnection, s); err != nil {
		return err
	}
	out.ControllerStartInterval = in.ControllerStartInterval
	if err := apisconfigv1alpha1.Convert_v1alpha1_LeaderElectionConfiguration_To_config_LeaderElectionConfiguration(&in.LeaderElection, &out.LeaderElection, s); err != nil {
		return err
	}
	out.Controllers = *(*[]string)(unsafe.Pointer(&in.Controllers))
	if err := apisconfigv1alpha1.Convert_v1alpha1_DebuggingConfiguration_To_config_DebuggingConfiguration(&in.Debugging, &out.Debugging, s); err != nil {
		return err
	}
	return nil
}

func autoConvert_config_GenericControllerManagerConfiguration_To_v1alpha1_GenericControllerManagerConfiguration(in *config.GenericControllerManagerConfiguration, out *GenericControllerManagerConfiguration, s conversion.Scope) error {
	out.Port = in.Port
	out.Address = in.Address
	out.MinResyncPeriod = in.MinResyncPeriod
	if err := configv1alpha1.Convert_config_ClientConnectionConfiguration_To_v1alpha1_ClientConnectionConfiguration(&in.ClientConnection, &out.ClientConnection, s); err != nil {
		return err
	}
	out.ControllerStartInterval = in.ControllerStartInterval
	if err := apisconfigv1alpha1.Convert_config_LeaderElectionConfiguration_To_v1alpha1_LeaderElectionConfiguration(&in.LeaderElection, &out.LeaderElection, s); err != nil {
		return err
	}
	out.Controllers = *(*[]string)(unsafe.Pointer(&in.Controllers))
	if err := apisconfigv1alpha1.Convert_config_DebuggingConfiguration_To_v1alpha1_DebuggingConfiguration(&in.Debugging, &out.Debugging, s); err != nil {
		return err
	}
	return nil
}
