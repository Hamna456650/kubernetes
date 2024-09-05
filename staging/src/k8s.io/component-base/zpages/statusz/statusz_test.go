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
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestStatusz(t *testing.T) {
	timeNow := time.Now()
	uptime := time.Since(timeNow)
	binaryVersion := "1.32"
	tests := []struct {
		name       string
		opts       Options
		wantResp   *StatuszResponse
		wantStatus int
	}{
		{
			name: "default",
			opts: Options{
				StartTime:     timeNow,
				BinaryVersion: binaryVersion,
			},
			wantResp: &StatuszResponse{
				StartTime: timeNow.String(),
				Uptime: fmt.Sprintf("%d hr %02d min %02d sec",
					uptime/3600, (uptime/60)%60, uptime%60),
				BinaryVersion: binaryVersion,
				UsefulLinks: map[string]string{
					"healthz": "/healthz",
					"livez":   "/livez",
					"readyz":  "/readyz",
					"metrics": "/metrics",
				},
			},
			wantStatus: http.StatusOK,
		},
	}

	for i, test := range tests {
		mux := http.NewServeMux()
		Statusz{}.Install(mux, test.opts)

		path := "/statusz"
		req, err := http.NewRequest("GET", fmt.Sprintf("http://example.com%s", path), nil)
		if err != nil {
			t.Fatalf("case[%d] Unexpected error while creating request: %v", i, err)
		}

		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != test.wantStatus {
			t.Fatalf("case[%d] want status code: %v, got: %v", i, test.wantStatus, w.Code)
		}

		c := w.Header().Get("Content-Type")
		if c != "text/plain; charset=utf-8" {
			t.Fatalf("case[%d] want header: %v, got: %v", i, "text/plain", c)
		}

		gotResp := &StatuszResponse{}
		if err = json.Unmarshal(w.Body.Bytes(), gotResp); err != nil {
			t.Fatalf("case[%d] Unexpected error while unmarshaling wantResponse: %v", i, err)
		}

		if diff := cmp.Diff(test.wantResp, gotResp, cmpopts.IgnoreFields(StatuszResponse{}, "Uptime")); diff != "" {
			t.Fatalf("Unexpected diff on response (-want,+got):\n%s", diff)
		}
	}

}
