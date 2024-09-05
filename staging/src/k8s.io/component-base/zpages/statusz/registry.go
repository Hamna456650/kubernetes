/*
Copyright 2024 The Kubernetes Authors.

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

package statusz

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type Options struct {
	StartTime            time.Time
	GoVersion            string
	BinaryVersion        string
	CompatibilityVersion string
}

type statuszRegistry struct {
	lock    sync.Mutex
	options Options
}

func (reg *statuszRegistry) handleStatusz() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		statuszData := reg.populateStatuszData()
		jsonData, err := json.MarshalIndent(statuszData, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, string(jsonData))
	}
}

func (reg *statuszRegistry) populateStatuszData() StatuszResponse {
	uptime := int(time.Since(reg.options.StartTime).Seconds())

	return StatuszResponse{
		StartTime: reg.options.StartTime.String(),
		Uptime: fmt.Sprintf("%d hr %02d min %02d sec",
			uptime/3600, (uptime/60)%60, uptime%60),
		GoVersion:            reg.options.GoVersion,
		BinaryVersion:        reg.options.BinaryVersion,
		CompatibilityVersion: reg.options.CompatibilityVersion,
		UsefulLinks: map[string]string{
			"healthz": "/healthz",
			"livez":   "/livez",
			"readyz":  "/readyz",
			"metrics": "/metrics",
		},
	}
}
