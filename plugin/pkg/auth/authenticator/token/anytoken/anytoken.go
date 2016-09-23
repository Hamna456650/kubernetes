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

package anytoken

import (
	"strings"

	"k8s.io/kubernetes/pkg/auth/user"
)

type AnyTokenAuthenticator struct{}

func (AnyTokenAuthenticator) AuthenticateToken(value string) (user.Info, bool, error) {
	userTokens := strings.SplitN(value, "/", 2)
	ret := &user.DefaultInfo{Name: userTokens[0]}
	if len(userTokens) == 1 {
		return ret, true, nil
	}

	groupString := userTokens[1]
	if len(groupString) == 0 {
		return ret, true, nil
	}

	ret.Groups = strings.Split(groupString, ",")
	return ret, true, nil
}
